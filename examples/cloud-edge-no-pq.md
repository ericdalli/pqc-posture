```
pqc-posture [TEST URL]:443 -v
[TEST URL]:443: D (45/100)
pqc-posture 0.1.0
client: OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)  (/usr/bin/openssl)
hybrid groups offerable by this client: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024

[TEST URL]:443  [D] 45/100
-------------------------------------------------
  measured against : [TEST IP]
  negotiated group : prime256v1  (classical)
  TLS versions     : 1.3, 1.2
  groups accepted  : classical_ec: secp256r1, secp384r1, secp521r1
  cert key         : RSA 2048-bit, [NUMBER OF]d left
  cert signed with : sha256WithRSAEncryption (by the issuer)
  findings:
   !! [NO_PQ_KEX] TLS 1.3 is available but no post-quantum group is. Every session here is recordable today and decryptable later.
      [TLS12_ENABLED] TLS 1.2 is still accepted. It cannot carry a hybrid group, so any client that falls back to it is unprotected regardless of the TLS 1.3 configuration.
      [CERT_SIG_CLASSICAL] Certificate signature is sha256WithRSAEncryption. Classical signatures are expected in 2026 and are not retroactively exploitable; do not treat this as urgent alongside the key exchange findings.
  probes:
      __default__              supported -> prime256v1
      __realistic__            supported -> prime256v1
      X25519MLKEM768           rejected. peer sent TLS alert: handshake_failure
      SecP256r1MLKEM768        rejected. peer sent TLS alert: handshake_failure
      SecP384r1MLKEM1024       rejected. peer sent TLS alert: handshake_failure
      MLKEM512                 rejected. peer sent TLS alert: handshake_failure
      MLKEM768                 rejected. peer sent TLS alert: handshake_failure
      MLKEM1024                rejected. peer sent TLS alert: handshake_failure
      X25519                   rejected. peer sent TLS alert: handshake_failure
      secp256r1                supported -> prime256v1
      secp384r1                supported -> secp384r1
      secp521r1                supported -> secp521r1
      X448                     rejected. peer sent TLS alert: handshake_failure
      ffdhe2048                rejected. peer sent TLS alert: handshake_failure
      ffdhe3072                rejected. peer sent TLS alert: handshake_failure

summary: 0/1 negotiate hybrid KEX by default; 0/1 support it at all
```
