<div align="center">

# leakguard

**Blazing-fast, zero-dependency C++17 secret scanner to catch leaked API keys, tokens, and credentials before you push.**

[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat-square&logo=cplusplus&logoColor=white)](https://isocpp.org/)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-16a34a?style=flat-square)](https://github.com/HikariDevv/leakguard)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

Scans repositories in milliseconds using high-signal regex rules and **Shannon entropy analysis**.<br/>
Single native binary. CI/CD ready (`--json` + exit code `1`).

</div>

---

## Preview

```text
$ leakguard ./my-project

  [HIGH]  src/config.js:12
          GitHub Personal Access Token  -> ghp_************cyB (entropy 5.02)

  [HIGH]  .env.backup:4
          AWS Access Key ID  -> AKIA************7Q2A (entropy 3.75)

  [MED ]  src/auth.java:47
          High-Entropy Secret String  -> 9f8a************e12b (entropy 4.84)

  Scanned 342 files (28410 lines) in 14.3 ms — 3 potential leak(s) found.
```

---

## What It Detects

| Category | Rule / Heuristic | Severity |
| :--- | :--- | :---: |
| **GitHub** | Personal Access Tokens (`ghp_...`) & Fine-Grained Tokens (`github_pat_...`) | `HIGH` |
| **Cloud** | AWS Access Key IDs (`AKIA...`) & Google API Keys (`AIza...`) | `HIGH` |
| **Payments & AI** | Stripe Secret Keys (`sk_live_...`, `sk_test_...`) & OpenAI API Keys (`sk-...`) | `HIGH` |
| **Messaging** | Slack Bot / User Tokens (`xox...`) | `HIGH` |
| **Cryptography** | Private Key PEM Headers (`RSA`, `EC`, `DSA`, `OPENSSH`) | `HIGH` |
| **Credentials** | Hardcoded `api_key`, `secret`, `token`, `password` assignments | `MED` |
| **Unknown Secrets** | **Shannon Entropy** detection on suspicious high-entropy string literals | `MED` |

---

## Quick Start

### Build with `g++` or `clang++`
```bash
make
```
Or directly:
```bash
g++ -std=c++17 -O2 -Wall -Wextra src/*.cpp -o leakguard
```

### Build with CMake (Windows / macOS / Linux)
```bash
cmake -B build
cmake --build build --config Release
```

---

## Usage

### Scan the current directory
```bash
./leakguard .
```

### Scan a specific folder or file
```bash
./leakguard ./src
./leakguard .env
```

### JSON output for CI / GitHub Actions
```bash
./leakguard . --json
```

### Custom entropy threshold
```bash
./leakguard . --threshold 4.8
```

### Exit Codes
| Code | Meaning |
| :---: | :--- |
| `0` | Clean — no potential secrets detected |
| `1` | One or more potential secrets found |
| `2` | Invalid CLI arguments or missing path |

---

## Git Pre-Commit Hook

Block accidental commits containing secrets automatically by adding this to `.git/hooks/pre-commit`:

```bash
#!/usr/bin/env bash
leakguard . || {
  echo "Commit blocked: remove detected secrets before committing."
  exit 1
}
```

---

## Project Structure

```text
leakguard/
├── CMakeLists.txt
├── Makefile
├── LICENSE
├── README.md
└── src/
    ├── main.cpp       # CLI argument parser & exit codes
    ├── scanner.hpp    # Recursive filesystem walker & binary filtering
    ├── scanner.cpp
    ├── rules.hpp      # Built-in regex detection rules & keyword matcher
    ├── rules.cpp
    ├── entropy.hpp    # Shannon entropy calculation & secret masking
    ├── entropy.cpp
    ├── reporter.hpp   # Colored terminal & JSON report formatters
    ├── reporter.cpp
    └── finding.hpp    # Core domain models (Finding, Severity, ScanStats)
```

---

## License

Released under the [MIT License](LICENSE). Built by **Dips** ([HikariDevv](https://github.com/HikariDevv)).
