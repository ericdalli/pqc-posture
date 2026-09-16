# Scope and authorised use

`pqc-posture` opens TLS connections to hosts you name and records how they
respond. That is active interaction with a remote service, not passive
observation.

- Run it only against endpoints you own or are explicitly authorised to test.
- A full sweep is one handshake per group per pass. At 13 groups and 10 passes
  that is 130 connections to a single address. Against a VIP with connection
  limits or a WAF, that is enough to register as anomalous. Size `repeat`
  deliberately.
- Probes within one address run serially by design. Do not parallelise them to
  "speed things up" against production.
- This repository contains no real inventory data. `inventory.example.json`
  uses RFC 5737 / RFC 3849 documentation addresses and example.com-style
  hostnames throughout.

Nothing in this tool attempts to exploit, downgrade, or bypass anything. It
offers a group, records the answer, and disconnects.
