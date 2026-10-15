# Security

## Wallet keys and signatures

The checker reads wallet private keys from the local `-keys` file and uses them in
memory to sign OpenSea Sign-In with Ethereum (SIWE) messages. It sends the SIWE message
and signature to OpenSea to create a session for each wallet. **The private keys
themselves are not sent to OpenSea and are not written to a report.**

This is not a hardware-wallet flow: keys are plaintext on disk and accessible to the
running process. Use wallets appropriate for this risk, protect the keys file with
operating-system permissions, and remove the file when you no longer need it. Never
commit private keys, API keys, session cookies, or reports containing wallet addresses.

The checker keeps OpenSea session cookies in memory for the process lifetime. It does not
save those cookies to disk.

## Network requests

The checker connects to OpenSea for SIWE authentication and eligibility queries. If an
OpenSea API key is provided, it is sent to OpenSea's REST API for contract lookup and
phase-name lookup. Do not use an API key you are not authorized to use.

## Reporting a vulnerability

Do not report security vulnerabilities in a public issue. Contact the repository
maintainer privately with a concise description, impact, and reproduction steps. Do not
include live private keys, API keys, signatures, or session cookies in a report.
