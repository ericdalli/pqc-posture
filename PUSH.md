# Getting this into github.com/ericdalli/pqc-posture

Run these on the machine you downloaded the archive to. Nothing needs to be
copied to or from any other machine.

## 1. Create the repo on GitHub

github.com → New repository → name `pqc-posture` → **Public** →
do **not** add a README, .gitignore or licence (this archive has them).

## 2. Push

```bash
unzip pqc-posture.zip && cd pqc-posture

git init -b main
git add .
git commit -m "Phase 1: observation-layer TLS/PQC posture scanner

Evidence model records one immutable record per handshake; topology
inference is a separate pure function over that evidence. Three-state
support matrix keeps 'not observed' distinct from 'not supported'.
Stdlib only; OpenSSL 3.5 subprocess for hybrid KEM groups."

git remote add origin git@github.com:ericdalli/pqc-posture.git
git push -u origin main
```

HTTPS instead of SSH: `https://github.com/ericdalli/pqc-posture.git`, and use a
personal access token as the password (Settings → Developer settings → Personal
access tokens → Fine-grained, `Contents: read/write` on this repo only).

## 3. Confirm

- Actions tab → CI run goes green (79 tests)
- `git check-ignore -v inventory.json` → confirms real inventories are excluded

## 4. Then

```bash
# Codespaces: Code -> Codespaces -> Create codespace
# or locally:
code .        # "Reopen in Container"
```

## Before your first real scan

```bash
bash scripts/check-openssl.sh
```

## Never commit

`inventory.json`, `evidence.json`, anything with real VIPs or backend IPs.
`.gitignore` covers the obvious names, but it cannot catch a file you name
something else. Check `git status` before every commit.
