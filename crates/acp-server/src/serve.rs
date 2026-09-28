//! Serving the control-plane axum app: plain HTTP with graceful drain, or mutual TLS between
//! components (require a client cert signed by the ACP CA).
use axum::Router;

/// Serve `app` on `addr`. With TLS material present, require a client certificate signed by the ACP
/// CA (mTLS); otherwise serve plain HTTP and drain in-flight requests on shutdown.
pub(crate) async fn run(app: Router, addr: &str, tls: Option<(String, String, String)>) {
    if let Some((ca, cert, key)) = tls {
        tracing::error!("listening on https://{addr} (mTLS, client cert required)");
        serve_mtls(addr, app, &ca, &cert, &key).await;
        return;
    }
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    tracing::info!("listening on http://{addr}");
    // X.7: drain in-flight requests on SIGTERM/Ctrl-C instead of dropping them. The evidence
    // ledger is durable per-append, so a clean drain loses no decision and double-executes none.
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("serve");
}

/// Serve the axum app over mutual TLS: present the server cert and REQUIRE a client cert signed by
/// the ACP CA, so only enrolled components can reach the control API.
pub(crate) async fn serve_mtls(addr: &str, app: Router, ca: &str, cert: &str, key: &str) {
    crate::mtls::ensure_provider();
    let ca = std::fs::read(ca).expect("read tls-ca");
    let cert = std::fs::read(cert).expect("read tls-cert");
    let key = std::fs::read(key).expect("read tls-key");
    let cfg = crate::mtls::server_config(&ca, &cert, &key).expect("mtls server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(t) => t, // handshake fails here for a client with no/bad cert (mutual auth)
                Err(_) => return,
            };
            let io = hyper_util::rt::TokioIo::new(tls);
            let svc = hyper_util::service::TowerToHyperService::new(app);
            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}

/// Resolve when the process is asked to stop, so the server can drain rather than drop.
pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining in-flight requests");
}
