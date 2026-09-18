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

The test signs a message with the HSM key and asserts it verifies with `acp_core::sign::verify_ed25519`
(the ledger's path). Gated on `ACP_PKCS11_MODULE`, so CI without a module skips cleanly.

## Ledger integration (remaining deploy wiring)

A `cryptoki` Session is thread-bound, so plugging `Pkcs11Signer` directly into the ledger's
`Box<dyn Signer + Send>` needs a small dedicated-signing-thread + channel wrapper (open the session on
that thread, send it sign requests). The signer itself is complete and verified; that wrapper is the
one deploy-time piece. Production points `ACP_PKCS11_MODULE` at the real HSM's module.
