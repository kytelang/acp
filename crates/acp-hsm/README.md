# acp-hsm

PKCS#11 HSM signing backend (H0.3 hardening). Fills the `acp_core::sign::Signer` seam with an
HSM-held Ed25519 key (YubiHSM / Thales / SoftHSM / any PKCS#11 module), so the evidence signing key
never sits in a file. HSM signatures verify with the same `verify_ed25519` path as the file signer,
so an HSM-signed tree head is interchangeable with a file-signed one. No cloud: the module is a
local shared library.

## Verified against SoftHSM

```sh
brew install softhsm            # or your distro package
export SOFTHSM2_CONF=/path/to/softhsm2.conf   # tokendir = ...
softhsm2-util --init-token --slot 0 --label acp --so-pin 1234 --pin 5678
# note the reassigned slot id from --show-slots, then:
ACP_PKCS11_MODULE=$(find /opt/homebrew /usr -name libsofthsm2.so 2>/dev/null | head -1) \
ACP_PKCS11_SLOT=<reassigned-slot-id> ACP_PKCS11_PIN=5678 ACP_PKCS11_LABEL=acp \
  cargo test -p acp-hsm
```

Run HSM tests single-threaded (PKCS#11 `C_Initialize` is once-per-process): `cargo test -p acp-hsm
-- --test-threads=1`. Gated on `ACP_PKCS11_MODULE`, so CI without a module skips cleanly.

## Ledger integration

`ThreadedPkcs11Signer` is the `Send` handle the ledger takes: it owns a dedicated thread holding the
(thread-bound) PKCS#11 session and services sign requests over a channel, so it satisfies
`Box<dyn Signer + Send>` and the ledger signs every tree head directly on the HSM. Verified against
SoftHSM (moved across a thread boundary and signs). Production points `ACP_PKCS11_MODULE` at the real
HSM's module; no cloud.
