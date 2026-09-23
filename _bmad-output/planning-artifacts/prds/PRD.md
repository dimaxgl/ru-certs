---
title: ru-certs CLI Utility PRD
created: 2026-09-22
updated: 2026-09-23
status: draft
---

# PRD: ru-certs CLI Utility

## 0. Document Purpose
This document specifies functional, structural, and regulatory requirements for the `ru-certs` command-line utility. It serves Product Managers, Architects, Developers, and QA engineers designing, implementing, and verifying the CLI. The utility automates certificate lifecycle operations:
1. Multi-certificate bundle issuance (Triple Certificate Strategy: MinTsifry RSA + MinTsifry/CryptoPro GOST + Let's Encrypt / Public ACME).
2. Web server and reverse proxy / load balancer configuration generation (Nginx multi-cert dual/triple-bind, Traefik TLS stores, HAProxy).
3. ACME protocol interactions with the Russian National Certification Authority (NUC Voskhod / Минцифры) and Public CAs (Let's Encrypt).
4. Regulatory CSR generation with Russian ASN.1 OIDs (INN, OGRN, SNILS, SKZI KC1–KB2 policies) for Physical Persons (ФЛ), Individual Entrepreneurs (ИП), and Legal Entities (ЮЛ).
5. CA trust store management and automated batch renewal pipelines.

## 1. Vision
Russian organizations and internet services face a critical dual-connectivity challenge:
- Users within Russia utilizing Russian browsers (Yandex Browser, Atom) or systems with installed Минцифры root certificates require **Минцифры TLS certificates (RSA or GOST)**.
- Public sector and state-regulated information systems require **GOST R 34.10-2012** cryptographic compliance.
- Foreign users, global API clients, and standard devices without Russian root certificates fail with SSL errors unless presented with a globally trusted **Let's Encrypt / Public CA certificate**.

Deploying and maintaining this multi-certificate setup manually on web servers (Nginx, Traefik, HAProxy, Envoy) is complex and prone to renewal failures, cipher mismatch, and invalid OID formatting.

`ru-certs` solves this by introducing an automated **Triple Certificate Engine** and **Config Synthesis Subsystem**:
- With a single command, `ru-certs` issues all three certificates (MinTsifry RSA via NUC ACME, Let's Encrypt via Public ACME, and generates/manages GOST DV/OV certificates).
- It structures the output files into predictable directory layouts (`/etc/ru-certs/live/<domain>/{mintsifry-rsa,mintsifry-gost,letsencrypt}/`).
- It generates production-ready, drop-in configuration snippets and reverse proxy configs for **Nginx** (supporting multi-certificate dual-handshake and OpenSSL GOST engine) and **Traefik** (dynamic TLS configuration with fallback stores).

---

## 2. Target User & Journeys

### 2.1 Jobs To Be Done
- **Multi-Cert Provisioning:** Issue a complete 3-cert bundle (MinTsifry RSA + GOST + Let's Encrypt) with one automated command.
- **Server Configuration Synthesis:** Generate verified Nginx and Traefik configuration snippets that negotiate the right certificate per client cipher support.
- **Regulatory CSR Synthesis:** Generate standard-compliant PKCS#10 requests with Russian OIDs (INN, OGRN, SNILS, KC1–KB2 policies) for Gosuslugi portal submission or ACME issuance.
- **Automated Lifecycle & Renewal:** Atomically renew all managed certificates across all CAs without downtime or file corruption.

### 2.2 Key User Journeys

- **UJ-1. Triple Certificate Issuance & Nginx Multi-Cert Deployment**
  - **Persona:** DevOps engineer hosting a high-traffic Russian e-commerce platform (`shop.ru`).
  - **Path:** Runs `ru-certs cert obtain -d shop.ru -d www.shop.ru --email admin@shop.ru --multi-cert --webroot /var/www/html --generate-config nginx`.
  - **Outcome:** `ru-certs` requests MinTsifry RSA from NUC ACME, requests Let's Encrypt certificate from Let's Encrypt ACME, prepares GOST certificate structure, places all certificates in structured subdirectories, and writes an optimized `/etc/ru-certs/configs/shop.ru.nginx.conf` snippet.
  - **Result:** Nginx serves Let's Encrypt to foreign clients, MinTsifry RSA to Russian clients, and GOST to Russian cryptographic clients seamlessly.

- **UJ-2. Cloud-Native Deployment with Traefik Reverse Proxy**
  - **Persona:** Cloud architect running containerized microservices behind Traefik.
  - **Path:** Runs `ru-certs cert obtain -d api.company.ru --multi-cert --dns cloudflare --generate-config traefik`.
  - **Outcome:** Generates Traefik dynamic YAML configuration (`/etc/ru-certs/configs/api.company.ru.traefik.yaml`) defining `tls.certificates` stores for default and custom fallback stores.

- **UJ-3. GOST OV CSR Preparation for Legal Entity (ЮЛ)**
  - **Persona:** Security officer at Russian enterprise preparing GOST 2012 (512-bit) certificate for state portal.
  - **Path:** Runs `ru-certs csr --profile ov-yl --crypto gost512 --paramset A --org "ООО ПРЕДПРИЯТИЕ" --inn-le "7701234560" --ogrn "1237700123451" --skzi-class KC1 --output /etc/ru-certs/gost/company.csr`.
  - **Outcome:** Generates valid `.p10` DER and `.key` matching Gosuslugi regulatory specifications.

- **UJ-4. Trust Store Provisioning and Automated Renewals**
  - **Persona:** Sysadmin running daily cron job.
  - **Path:** `ru-certs renew` checks all active certificate profiles across all CAs and renews those within 30 days of expiration, executing deploy hooks (`--deploy-hook "systemctl reload nginx"`).

---

## 3. Features & Functional Requirements

### 3.1 Multi-Certificate Engine (Triple Certificate Strategy)

#### FR-1: Triple Certificate Orchestration
Actor can request multi-certificate issuance (`--multi-cert` / `--bundle triple`) for a domain set.
- **Consequences (testable):**
  - `ru-certs cert obtain -d <domain> --multi-cert` triggers:
    1. **MinTsifry RSA:** ACME order against `https://nuc-acme.voskhod.ru/acme/api/v1/directory`.
    2. **Let's Encrypt RSA/ECDSA:** ACME order against `https://acme-v02.api.letsencrypt.org/directory` (or staging).
    3. **GOST Certificate:** Generates GOST 2012 keypair/CSR or completes GOST ACME order if supported.
  - Output directories are strictly segregated:
    - `/etc/ru-certs/live/<domain>/mintsifry-rsa/{fullchain.pem,privkey.pem,cert.pem}`
    - `/etc/ru-certs/live/<domain>/letsencrypt/{fullchain.pem,privkey.pem,cert.pem}`
    - `/etc/ru-certs/live/<domain>/gost/{csr.p10,privkey.pem,cert.pem}`

#### FR-2: Unified Challenge Solving Across CAs
Actor can use a single challenge configuration (HTTP-01 webroot/standalone or DNS-01 Cloudflare/Reg.ru) to validate domain control across multiple CAs sequentially or in parallel.
- **Consequences (testable):**
  - Tokens for NUC Voskhod and Let's Encrypt are presented and validated without clobbering each other.

---

### 3.2 Web Server & Load Balancer Configuration Generator

#### FR-3: Nginx Multi-Certificate Configuration Synthesis
Actor can generate ready-to-use Nginx SSL configuration snippets (`--generate-config nginx` or `ru-certs config nginx -d <domain>`).
- **Consequences (testable):**
  - Produces standard Nginx multi-cert configuration block:
    ```nginx
    # MinTsifry RSA
    ssl_certificate     /etc/ru-certs/live/example.ru/mintsifry-rsa/fullchain.pem;
    ssl_certificate_key /etc/ru-certs/live/example.ru/mintsifry-rsa/privkey.pem;

    # Let's Encrypt (ECDSA / RSA)
    ssl_certificate     /etc/ru-certs/live/example.ru/letsencrypt/fullchain.pem;
    ssl_certificate_key /etc/ru-certs/live/example.ru/letsencrypt/privkey.pem;

    # OpenSSL GOST Engine (if GOST cert present)
    # ssl_certificate     /etc/ru-certs/live/example.ru/gost/fullchain.pem;
    # ssl_certificate_key /etc/ru-certs/live/example.ru/gost/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ```
  - Includes options for dual-port split, SNI fallback, and cipher suite presets for Russian & International traffic.

#### FR-4: Traefik Dynamic Configuration Synthesis
Actor can generate Traefik dynamic file provider configuration (`--generate-config traefik` or `ru-certs config traefik -d <domain>`).
- **Consequences (testable):**
  - Generates valid Traefik YAML/TOML configuration mapping multiple certificate stores:
    ```yaml
    tls:
      certificates:
        - certFile: /etc/ru-certs/live/example.ru/letsencrypt/fullchain.pem
          keyFile: /etc/ru-certs/live/example.ru/letsencrypt/privkey.pem
          stores:
            - default
        - certFile: /etc/ru-certs/live/example.ru/mintsifry-rsa/fullchain.pem
          keyFile: /etc/ru-certs/live/example.ru/mintsifry-rsa/privkey.pem
      stores:
        default:
          defaultCertificate:
            certFile: /etc/ru-certs/live/example.ru/letsencrypt/fullchain.pem
            keyFile: /etc/ru-certs/live/example.ru/letsencrypt/privkey.pem
    ```

---

### 3.3 CSR & Regulatory ASN.1 Engine

#### FR-5: Regulatory OID Formatting and Validation
Generates strictly compliant PKCS#10 requests with Russian OIDs for `dv`, `ov-fl`, `ov-ip`, and `ov-yl` profiles.
- Validates INN (10/12 digits), OGRN (13 digits), OGRNIP (15 digits), SNILS (11 digits) checksums.
- Injects SKZI certificate policies (`1.2.643.100.113.1` .. `5`).
- Converts Cyrillic domains to IDNA 2008 Punycode.

---

### 3.4 ACME Client Core & CA Trust Management

#### FR-6: ACME Directory & JWS Engine
- RFC 8555 compliant JWS message signing (RS256/ES256) with automatic `badNonce` retry.
- Direct integration with NUC Voskhod directory and Let's Encrypt directory.
- Embedded Минцифры root and intermediate certificates with system store installer (`ru-certs ca install`).

#### FR-7: Storage and Renewal Engine
- Atomic file writes via temporary files and `os.Rename`.
- Private key permissions locked to `0600`.
- Automated batch renewal check (`ru-certs renew`) with deploy hooks.

---

## 4. Web Server Architecture Guide (How Multi-Certs Work)

### 4.1 How Nginx Handles Multi-Certificates
1. **Modern OpenSSL (1.0.2+) / Nginx (1.11.0+) Multi-Certificate Support:**
   Nginx allows specifying multiple `ssl_certificate` and `ssl_certificate_key` directives in the same `server` block as long as each certificate uses a different key algorithm (e.g. RSA + ECDSA + GOST).
2. **TLS Handshake Negotiation:**
   - When a client connects (ClientHello), it sends supported Cipher Suites and Signature Algorithms.
   - If the client supports ECDSA, Nginx serves the Let's Encrypt ECDSA certificate.
   - If the client requests RSA or Russian ciphers, Nginx serves the MinTsifry RSA / GOST certificate.
3. **OpenSSL GOST Engine Integration:**
   For GOST TLS, Nginx is compiled with OpenSSL configured with `engine_section = gost_section`.

### 4.2 How Traefik Handles Multi-Certificates
1. Traefik automatically inspects the Subject and SANs of all certificates loaded in the dynamic configuration.
2. When a TLS connection arrives, Traefik performs SNI matching and matches the client's supported cipher algorithm with the best candidate certificate in its store.

---

## 5. Success Metrics
- **SM-1:** 100% automated issuance of the 3-cert bundle in under 60 seconds with a single command.
- **SM-2:** 0 SSL handshake errors when clients connect with Russian or International browser profiles against generated Nginx/Traefik configs.
- **SM-3:** 0 certificate corruption incidents during automated renewal.
