# Use Cases: ru-certs CLI Utility

## Overview
This document specifies the end-to-end use case scenarios for the `ru-certs` CLI utility. It maps user goals across individuals (Физические лица), individual entrepreneurs (ИП), legal entities (ЮЛ), and system administrators to exact functional flows, preconditions, trigger inputs, step-by-step executions, and postconditions.

---

### UC-1: Issue RSA DV Certificate via ACME (HTTP-01 Webroot)
- **Primary Actor:** DevOps / System Administrator
- **Stakeholder Goal:** Automate issuance of a standard RSA 2048/4096-bit Domain Validation certificate for an active web server.
- **Preconditions:**
  - Domain points to the target server's public IP.
  - Web server (Nginx/Apache) serves static files from `--webroot` path.
  - Минцифры root CA certificate bundle is accessible.
- **Trigger:**
  ```bash
  ru-certs cert issue -d example.ru -d www.example.ru --webroot /var/www/html --email admin@example.ru
  ```
- **Main Success Scenario:**
  1. CLI loads or initializes local ACME account keypair (`account.key`).
  2. CLI queries NUC Voskhod directory (`https://nuc-acme.voskhod.ru/acme/api/v1/directory`).
  3. CLI submits new order for `example.ru` and `www.example.ru`.
  4. ACME server returns HTTP-01 challenge authorizations.
  5. CLI generates key authorization tokens and writes files to `/var/www/html/.well-known/acme-challenge/<token>`.
  6. CLI notifies ACME server that challenges are ready.
  7. ACME server validates challenge endpoints over HTTP port 80.
  8. CLI polls order status until `status: ready`.
  9. CLI generates RSA 2048 private key and CSR with Subject `CN=example.ru, C=RU` and SAN `example.ru, www.example.ru`.
  10. CLI submits CSR to finalize endpoint.
  11. CLI downloads certificate chain, saves `cert.pem`, `chain.pem`, `fullchain.pem`, and `privkey.pem` to `/etc/ru-certs/live/example.ru/`.
  12. CLI cleans up temporary `.well-known/acme-challenge/` files.
- **Postconditions:** Valid certificate and key are installed in target path; permissions on `privkey.pem` are `0600`.
- **Extensions / Error Flows:**
  - *4a. Challenge validation failure (404/connection refused):* CLI cleans up challenge tokens, displays HTTP response received from CA, and exits with code 1.
  - *9a. Rate limiting (429 Too Many Requests):* CLI inspects `Retry-After` header and outputs human-readable wait duration.

---

### UC-2: Issue DV Certificate via ACME (Standalone Mode)
- **Primary Actor:** System Administrator
- **Stakeholder Goal:** Issue or renew certificate on a host where port 80 is free (or web server stopped temporarily).
- **Preconditions:**
  - Port 80 is not bound by another service.
  - Domain resolves to this host.
- **Trigger:**
  ```bash
  ru-certs cert issue -d mail.company.ru --standalone --email noc@company.ru --post-hook "systemctl restart postfix"
  ```
- **Main Success Scenario:**
  1. CLI initializes built-in ephemeral HTTP server on `0.0.0.0:80`.
  2. CLI places ACME order and responds to HTTP-01 challenge requests directly via internal server.
  3. Upon challenge validation success, internal HTTP server shuts down.
  4. CLI submits CSR, downloads certificate, and saves bundle.
  5. CLI executes `--post-hook` command.
- **Postconditions:** Ephemeral HTTP server is closed; certificate bundle is written; postfix service reloaded.

---

### UC-3: Issue DV Certificate via ACME (DNS-01 with Reg.ru)
- **Primary Actor:** Administrator managing wildcard or internal servers.
- **Stakeholder Goal:** Issue wildcard (`*.example.ru`) or non-public domain certificate using DNS challenge.
- **Preconditions:**
  - Domain DNS hosted on Reg.ru.
  - Environment variables `REGRU_USERNAME` and `REGRU_PASSWORD` configured.
- **Trigger:**
  ```bash
  ru-certs cert issue -d "*.example.ru" -d example.ru --dns regru --email admin@example.ru
  ```
- **Main Success Scenario:**
  1. CLI submits ACME order for `*.example.ru` and `example.ru`.
  2. ACME server issues DNS-01 challenge tokens.
  3. CLI calculates TXT record values (`base64url(sha256(keyAuthorization))`).
  4. CLI calls Reg.ru API (`/zone/add_txt_record`) to create `_acme-challenge.example.ru` TXT record.
  5. CLI polls authoritative DNS nameservers until TXT record propagates (configurable timeout, default 60s).
  6. CLI notifies ACME server; CA verifies DNS record.
  7. CLI finalizes order, downloads full certificate chain.
  8. CLI calls Reg.ru API (`/zone/clear_txt_record`) to remove challenge record.
- **Postconditions:** Wildcard certificate issued; DNS records cleaned up.

---

### UC-4: Generate GOST 2012 CSR for Legal Entity (ЮЛ)
- **Primary Actor:** Corporate Security Officer / Legal Entity IT Lead
- **Stakeholder Goal:** Generate compliant GOST 34.10-2012 PKCS#10 request (`.p10` file) for Gosuslugi portal submission.
- **Preconditions:**
  - Organization registration metadata (INN 10 digits, OGRN 13 digits) available.
  - OpenSSL with GOST engine installed.
- **Trigger:**
  ```bash
  ru-certs csr generate \
    --type ov-yl \
    --crypto gost512 \
    --paramset A \
    --cn "portal.company.ru" \
    --o "ООО Компания" \
    --innle "7701234567" \
    --ogrn "1027700123456" \
    --st "77 г. Москва" \
    --l "г. Москва" \
    --street "ул. Новая, д. 10" \
    --email "sec@company.ru" \
    --kc-class KC1 \
    --out-p10 ./portal_company.p10 \
    --out-key ./portal_company.key
  ```
- **Main Success Scenario:**
  1. CLI validates 10-digit INNLE, 13-digit OGRN, ST formatting, and UTF-8 encoding.
  2. CLI constructs ASN.1 subject sequence with explicit OIDs:
     - `1.2.643.100.4` (INNLE as NUMERICSTRING)
     - `1.2.643.100.1` (OGRN as NUMERICSTRING)
     - `1.2.643.100.111` (subjectSignTool = "HSM")
  3. CLI adds certificate policies: `1.2.643.2.25.1.14.2` and `1.2.643.100.113.1` (KC1).
  4. CLI generates 512-bit GOST private key using paramset A.
  5. CLI produces DER-encoded `.p10` and PEM `.key` file.
  6. CLI runs internal ASN.1 linting and reports full metadata summary.
- **Postconditions:** `.p10` file passes NUC portal upload validation; private key secured at `0600`.

---

### UC-5: Generate RSA/GOST CSR for Individual Entrepreneur (ИП) & Citizen (ФЛ)
- **Primary Actor:** Individual Entrepreneur (ИП) or Private Citizen (ФЛ)
- **Stakeholder Goal:** Generate compliant CSR containing personal Russian identifiers (SNILS, 12-digit INN, OGRNIP for ИП).
- **Preconditions:** Valid 12-digit INN, 11-digit SNILS, and (for ИП) 15-digit OGRNIP.
- **Trigger (ИП):**
  ```bash
  ru-certs csr generate \
    --type ov-ip \
    --crypto rsa2048 \
    --cn "shop.ru" \
    --sn "Иванов" \
    --gn "Иван Иванович" \
    --inn "770123456789" \
    --ogrnip "304770000123456" \
    --snils "12345678901" \
    --out-csr ./shop.csr
  ```
- **Main Success Scenario:**
  1. CLI performs checksum validation on INN, SNILS, and OGRNIP lengths and string masks.
  2. CLI encodes `SN` and `GN` in UTF-8, and formats numeric identifiers with proper ASN.1 tags.
  3. CLI signs CSR with generated private key and verifies signature integrity.
- **Postconditions:** Verified CSR and key written to specified output directory.

---

### UC-6: Lint and Verify Existing CSR (.csr / .p10)
- **Primary Actor:** Security Auditor / DevOps Engineer
- **Stakeholder Goal:** Check third-party or existing CSR for Russian regulatory compliance before portal submission.
- **Trigger:**
  ```bash
  ru-certs csr verify ./request.p10
  ```
- **Main Success Scenario:**
  1. CLI decodes ASN.1 structure (supporting PEM and DER).
  2. CLI verifies signature validity and public key algorithm.
  3. CLI checks presence of required extensions (`keyUsage`, `extendedKeyUsage`, `SAN`, `certificatePolicies`).
  4. CLI prints tabular report with validation verdict (`PASSED` / `FAILED`) and details of any non-compliant OIDs.
- **Postconditions:** Exit code 0 if valid; non-zero if validation fails.

---

### UC-7: Provision CA Root & Intermediate Trust Bundle
- **Primary Actor:** System Administrator
- **Stakeholder Goal:** Download and install Russian National Certification Authority (Минцифры) root and issuing certificates.
- **Trigger:**
  ```bash
  ru-certs ca install --system
  ```
- **Main Success Scenario:**
  1. CLI retrieves verified Минцифры root CA and sub-CA intermediate certificates from authoritative endpoints.
  2. CLI validates certificate signatures against embedded root fingerprints.
  3. If `--system` specified, CLI runs OS-specific trust store integration (`update-ca-certificates` on Debian/Ubuntu, `trust anchor` on RHEL/CentOS, or `security add-trusted-cert` on macOS).
  4. CLI performs test TLS connection to `https://nuc-acme.voskhod.ru/acme/api/v1/directory` and verifies chain trust.
- **Postconditions:** System and application TLS handshakes with NUC endpoints succeed without TLS certificate errors.

---

### UC-8: Automated Batch Certificate Renewal
- **Primary Actor:** Cron daemon / Systemd Timer
- **Stakeholder Goal:** Check all active certificates on host and renew only those expiring within 30 days.
- **Trigger:**
  ```bash
  ru-certs renew --quiet
  ```
- **Main Success Scenario:**
  1. CLI scans `/etc/ru-certs/renewal/` directory for managed domain configuration profiles.
  2. CLI inspects `notAfter` timestamp of each certificate.
  3. For certificates with >30 days remaining, CLI skips renewal and logs status.
  4. For certificates with <=30 days remaining, CLI automatically triggers renewal using saved challenge settings (e.g. webroot or DNS).
  5. If renewed, CLI updates `live/` symlinks and invokes saved `--post-hook` script.
- **Postconditions:** Expiring certificates renewed; services reloaded; audit log updated.
