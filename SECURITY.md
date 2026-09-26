# Security Policy

## Scope

RIAK v0.1, v0.2, and v0.3 are experimental research code. v0.1 has a known
linear break and v0.2/v0.3 have not completed independent cryptanalysis,
side-channel review, or formal AEAD review. Do not use any RIAK format to
protect real or sensitive data.

## Key handling

- No real key may be committed to this repository, examples, fixtures, issues,
  logs, or pull requests.
- Keys in test-vector files are public, non-secret KAT fixtures. They are not
  credentials and must never be reused for real data.
- Generate a key locally and protect the file:
  ```text
  ./target/release/riak keygen > key.hex
  chmod 600 key.hex
  ```
- Prefer `--key-file`; raw `--key` command-line arguments are rejected.
- If a key has ever protected real data, assume it is compromised. Rotate it
  and re-encrypt the data; removing it from the current tree or repository
  history does not make it secret again.

## Reporting a vulnerability

Do not open a public issue for a vulnerability or a working exploit. Use the
repository's private GitHub security advisory channel and include a minimal
reproducer, affected version, and impact assessment.

Cryptographic design comments and reproducible public analysis are welcome
after a fix or mitigation is available, but do not publish a live exploit
against users' data.
