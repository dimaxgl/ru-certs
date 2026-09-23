# Technical Architecture: ru-certs CLI Utility (Go Single Binary)

## 1. Architecture Overview & Principles
The `ru-certs` CLI utility is engineered in **Go (Golang 1.22+)** as a high-performance, statically-linked, single binary with zero external runtime dependencies on Linux, macOS, and Windows. 

Go is the premier choice for infrastructure tools (like `caddy`, `lego`, `traefik`, `cosign`, `step-ca`) because it delivers:
- **Instant startup time & single binary distribution** (easy `curl` or package installation on servers without Python runtime or virtualenvs).
- **Native robust ACME RFC 8555 engine** with standard library HTTP/TLS primitives.
- **Strict ASN.1 encoding primitives** via `encoding/asn1` and `crypto/x509` with full control over numeric string tags, custom OIDs, and SAN extensions.
- **Embedded Root CAs & Cross-Platform Trust Stores** via `crypto/x509` and OS-specific trust store APIs.

### Architectural Invariants
1. **Single Portable Binary:** No external Python/interpreter dependencies. Standalone binary runs on any Linux distribution (glibc or musl/Alpine), macOS, and Windows.
2. **Modular Go Package Design:** Clear domain packages (`cmd`, `pkg/acme`, `pkg/csr`, `pkg/ca`, `pkg/storage`, `pkg/dns`).
3. **Deterministic Cryptographic & ASN.1 Serialization:** Strict OID schemas, UTF-8 strings, and `NUMERICSTRING` formatting for Russian regulatory fields (INN, OGRN, SNILS).
4. **Safe Filesystem & Storage Defaults:** Atomic certificate writes with POSIX `0600` permissions on private keys.
5. **Robust ACME Protocol Engine:** Nonce management, automatic retry with `Retry-After` backoff, HTTP-01 webroot/standalone handlers, and DNS-01 provider hooks.

---

## 2. Component Package Structure

```
ru-certs/
├── cmd/
│   └── ru-certs/
│       └── main.go                 # Cobra CLI root & entry point
├── internal/
│   ├── cli/
│   │   ├── cert.go                 # 'cert issue', 'renew' commands
│   │   ├── csr.go                  # 'csr generate', 'csr verify' commands
│   │   ├── ca.go                   # 'ca install', 'ca check' commands
│   │   └── account.go              # 'account register' command
│   └── config/
│       └── config.go               # Configuration, CLI flags, ENV bindings (Viper)
├── pkg/
│   ├── acme/
│   │   ├── client.go               # RFC 8555 ACME client core
│   │   ├── directory.go            # Directory discovery & endpoint caching
│   │   ├── account.go              # Account key creation & JWS signing
│   │   ├── order.go                # Order lifecycle, authorization polling, finalization
│   │   └── challenge/
│   │       ├── http01.go           # Webroot file writer & Standalone HTTP server
│   │       ├── dns01.go            # DNS-01 challenge orchestration & record digest
│   │       └── providers/
│   │           ├── regru.go        # Native Reg.ru API client
│   │           └── hook.go         # Generic script / command execution hook
│   ├── csr/
│   │   ├── builder.go              # CSR builder & pipeline
│   │   ├── rsa.go                  # RSA 2048/4096 & ECDSA key generation
│   │   ├── gost.go                 # GOST 34.10-2012 key & CSR generation (Cgo/CLI fallback)
│   │   ├── oids.go                 # Russian regulatory OID definitions & constants
│   │   ├── asn1.go                 # Custom ASN.1 sequence & NUMERICSTRING encoder
│   │   └── linter.go               # CSR compliance & structure validator
│   ├── ca/
│   │   ├── truststore.go           # OS-specific trust store integration (Linux, macOS)
│   │   ├── roots.go                # Embedded/remote Минцифры root & issuing CA certs
│   │   └── verifier.go             # TLS handshake & certificate chain verification
│   └── storage/
│       ├── manager.go              # Storage directory structure & atomic file persistence
│       └── renewal.go              # Renewal profile state tracking & renewal evaluation
├── go.mod
└── go.sum
```

---

## 3. Data Flow & Subsystem Interactions

```
                +----------------------------+
                |     Cobra CLI Commands     |
                |  (issue, csr, ca, renew)   |
                +-------------+--------------+
                              |
       +----------------------+----------------------+
       |                      |                      |
+------v-----+         +------v-----+         +------v-----+
|   pkg/csr  |         |  pkg/acme  |         |   pkg/ca   |
| Cryptography|        |  Protocol  |         | TrustStore |
+------+-----+         +------+-----+         +------+-----+
       |                      |                      |
       | ASN.1 & OIDs         | Challenges & Orders  | Минцифры CAs
       v                      v                      v
+------------+         +------------+         +------------+
| Key & CSR  | ------> | Finalize   | ------> | pkg/storage|
| Generator  |         | Order      |         | Store Certs|
+------------+         +------------+         +------------+
```

---

## 4. Cryptographic & Regulatory Details in Go

### 4.1 ASN.1 Subject & OID Encoding
Go's `encoding/asn1` package allows exact control of ASN.1 tag types:
- **`asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagNumericString, Bytes: []byte(inn)}`** for INN (`1.2.643.3.131.1.1`), INNLE (`1.2.643.100.4`), OGRN (`1.2.643.100.1`), OGRNIP (`1.2.643.100.5`), SNILS (`1.2.643.100.3`).
- **`asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(val)}`** for `subjectSignTool` (`1.2.643.100.111`), `SN`, `GN`, `O`, `ST`, `L`, `streetAddress`.
- **Certificate Policies:** Sequence of PolicyInformation objects for `1.2.643.2.25.1.14.1` (DV), `1.2.643.2.25.1.14.2` (OV), and `1.2.643.100.113.1`..`5` (KC1–KB2).

### 4.2 ACME JWS & Nonce Protocol
- Supports JWS `RS256` / `ES256` signatures with full RFC 8555 nonce handling.
- Standalone HTTP server uses Go's built-in `net/http` with graceful timeout and shutdown.

### 4.3 OS Trust Store Management
- **Debian / Ubuntu:** Writes to `/usr/local/share/ca-certificates/ru-certs-ca.crt` and executes `update-ca-certificates`.
- **RHEL / CentOS / Alma / Rocky:** Writes to `/etc/pki/ca-trust/source/anchors/` and executes `update-ca-trust extract`.
- **macOS:** Calls `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain`.
- **Go TLS Client Pool:** Injects Минцифры root bundle into `tls.Config.RootCAs` so the binary connects securely to NUC endpoints even before system-wide root installation.

---

## 5. Build & Distribution
- **Tooling:** Standard Go toolchain (`go build`).
- **Cross-Compilation:** `GOOS=linux GOARCH=amd64 go build`, `GOOS=linux GOARCH=arm64 go build`, `GOOS=darwin GOARCH=arm64 go build`.
- **Binary Size & Stripping:** `go build -ldflags="-s -w" -o ru-certs ./cmd/ru-certs`.
