# OpenSea Wallet Allowlist Checker

A standalone command-line tool that checks whether EVM wallets are eligible for the
allowlist phases of an OpenSea drop. It signs in to OpenSea separately for each wallet,
reads the drop's eligibility phases, and prints a per-wallet report.

The checker is read-only with respect to the blockchain: it does not build, sign, or send
mint transactions. It does sign an OpenSea Sign-In with Ethereum (SIWE) message locally
using each wallet's private key. See [Security](#security) before using real wallets.

## Features

- Check a collection by its OpenSea URL or collection slug.
- Optionally resolve a contract address to a collection using an OpenSea API key.
- Check multiple wallets from one local private-key file.
- Report eligibility phase by phase, with an explicit `Error` result when eligibility
  cannot be determined.
- Optionally save the full report as JSON.
- Pace and retry sign-in requests to reduce OpenSea rate-limit failures.
- Stop a long run with Ctrl+C and retain results already checked.

## Requirements

- Go **1.26 or newer** to build from source (the version declared in `go.mod`).
- Internet access to OpenSea's website, GraphQL endpoint, and—when used—the OpenSea REST
  API.
- Private keys for the wallets you want to check.

## Build

This repository contains source files only; executables are not distributed. Build it
yourself from the `walletchecker` directory with Go installed:

```sh
go build -o wlchecker .
```

The command builds for the platform you're currently using. To cross-compile, set Go's
`GOOS` and `GOARCH` environment variables. For example, from macOS or Linux, build common
64-bit targets:

```sh
GOOS=windows GOARCH=amd64 go build -o wlchecker.exe .
GOOS=linux GOARCH=amd64 go build -o wlchecker .
GOOS=darwin GOARCH=arm64 go build -o wlchecker .
```

On PowerShell, environment variables are set differently:

```powershell
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o wlchecker.exe .
$env:GOOS = "linux"
go build -o wlchecker .
$env:GOOS = "darwin"
$env:GOARCH = "arm64"
go build -o wlchecker .
$env:GOOS = ""
$env:GOARCH = ""
```

Use the appropriate filename suffix for each target (`.exe` for Windows). `GOARCH` must
match the target architecture; other combinations supported by Go are also available.
Go downloads the module dependencies listed in `go.mod` the first time it builds.

## Prepare wallet keys

Create a local text file with **one private key per line**. The default filename is
`keys.txt` in the current working directory:

```text
# Comments and blank lines are ignored
0x0123...your-private-key...
abcdef...another-private-key...
```

The optional `0x` prefix is accepted. Duplicate wallet addresses are checked only once.
An invalid non-comment line stops the run and identifies the file and line number without
printing the key.

The keys file is plaintext and grants full control of the wallets. Do not commit it, send
it to anyone, or store valuable funds in wallets whose keys are used with this tool.
The repository `.gitignore` excludes `keys.txt` and locally built executables, but you
should still verify what you stage before pushing.

## Usage

```text
wlchecker <OpenSea URL | collection slug | contract address> [flags]
```

Examples:

```sh
# Check every wallet in keys.txt against a collection
./wlchecker cool-collection

# An OpenSea collection URL works too
./wlchecker https://opensea.io/collection/cool-collection

# Specify the chain used for OpenSea sign-in
./wlchecker cool-collection -chain base

# Resolve a contract address (requires an OpenSea API key)
./wlchecker 0x0000000000000000000000000000000000000000 -chain base -apikey YOUR_KEY

# Save a machine-readable report
./wlchecker cool-collection -json report.json

# Use a different wallet-key file
./wlchecker cool-collection -keys wallets/mint-wallets.txt
```

On Windows, run `.\wlchecker.exe` in PowerShell or `wlchecker.exe` in Command Prompt.
Flags may appear before or after the collection argument.

### Flags

| Flag | Default | Description |
|---|---|---|
| `-keys` | `keys.txt` | File containing one private key per line |
| `-chain` | `ethereum` | Chain name used for SIWE and contract lookup |
| `-apikey` | `OPENSEA_API_KEY` environment variable, if set | OpenSea API key; required for contract-address lookup and used for drop phase names |
| `-json` | *(disabled)* | Write the complete report to the specified JSON file |

Supported chain names: `ethereum`, `base`, `arbitrum`, `optimism`, `polygon`, `apechain`,
`abstract`, `robinhood`, `ink`, `hyperevm`, `arc`, and `sepolia`.

Set the API key through an environment variable to avoid putting it directly in shell
history:

```powershell
$env:OPENSEA_API_KEY = "your-key"
.\wlchecker.exe cool-collection
```

```sh
export OPENSEA_API_KEY="your-key"
./wlchecker cool-collection
```

## Reading the results

The report first lists the drop's phases, then gives each wallet one of these statuses:

- **Eligible** — OpenSea says the wallet can mint in at least one phase. The phase column
  names the best available phase, preferring allowlist phases over public phases. The JSON
  report includes all eligible phase keys, including public phases.
- **Not eligible** — OpenSea returned a definitive result and the wallet is not eligible
  for any available phase.
- **Error** — the checker could not confirm eligibility, for example because sign-in,
  OpenSea, or a network request failed. An error is not treated as “not eligible.”
- **Stopped** — the check had not completed when you stopped the run.

If `-apikey` is available, the checker may display the drop's configured phase names.
Without it, allowlist phases use generated names such as `Allowlist 1`.

Example JSON shape:

```json
{
  "slug": "cool-collection",
  "phases": [
    {
      "key": "s0",
      "name": "Early Access",
      "type": "allowlist",
      "cap": 2,
      "index": 0
    }
  ],
  "results": [
    {
      "address": "0x...",
      "status": "Eligible",
      "phase": "Early Access · max 2",
      "eligible": ["s0"]
    }
  ]
}
```

Treat report files as private: they contain wallet addresses and eligibility details.
They do not contain the private keys.

## Stopping a run

Press Ctrl+C once to stop starting new checks and print the completed results. A second
Ctrl+C exits immediately. OpenSea may rate-limit sign-ins; the checker spaces requests and
retries errors, so checking many wallets can take several minutes.

## Troubleshooting

| Message / symptom | What to check |
|---|---|
| `can't open keys file` | Run from the directory containing `keys.txt`, or pass the correct path with `-keys`. |
| `not a valid private key` | Check the indicated line in the keys file; remove labels or other text. |
| `unknown chain` | Use one of the supported chain names listed above. |
| Contract lookup needs an API key | Set `OPENSEA_API_KEY` or pass `-apikey`, or use the OpenSea collection URL/slug instead. |
| `isn't an OpenSea collection link, slug or contract address` | Use a collection URL, a slug containing only letters, numbers, `_` or `-`, or an EVM contract address. |
| `not an OpenSea drop (no mint stages)` | Verify that the collection exists and has OpenSea drop mint phases. |
| A wallet reports `Error` | Retry later, check connectivity, and consider OpenSea rate limits. `Error` does not mean the wallet failed the allowlist. |

## Security

Read [SECURITY.md](SECURITY.md) for details on key handling, signed messages, session
cookies, and how to report security issues.
