# QA Test Plan & Cases: ru-certs CLI Utility

## Overview
This document specifies test scenarios and verification cases for the `ru-certs` CLI utility derived directly from PRD requirements and use cases.

---

### Test Suite 1: CSR Generation & Regulatory Linting (TC-CSR)

#### TC-CSR-01: DV RSA CSR Generation & Extensions
- **Objective:** Verify standard DV CSR contains CN, RU country, KeyUsage, ExtendedKeyUsage, and SAN.
- **Input:** `ru-certs csr generate --type dv --crypto rsa2048 --cn domain.ru --san www.domain.ru`
- **Expected:**
  - Valid PKCS#10 PEM format.
  - SAN includes `domain.ru` and `www.domain.ru`.
  - KeyUsage has `digitalSignature`, `keyEncipherment`.
  - ExtendedKeyUsage has `serverAuth`, `clientAuth`.

#### TC-CSR-02: OV-YL GOST 512 CSR Generation (Legal Entity)
- **Objective:** Verify GOST 2012 512-bit CSR generation with 10-digit INNLE, 13-digit OGRN, subjectSignTool, and KC1 policy.
- **Input:** `ru-certs csr generate --type ov-yl --crypto gost512 --cn portal.ru --o "ООО Тест" --innle 7701234567 --ogrn 1027700123456 --st "77 г. Москва" --kc-class KC1`
- **Expected:**
  - Derives `.p10` DER format.
  - OID `1.2.643.100.4` contains `NUMERICSTRING` of length 10.
  - OID `1.2.643.100.1` contains `NUMERICSTRING` of length 13.
  - Certificate policy includes `1.2.643.2.25.1.14.2` and `1.2.643.100.113.1`.

#### TC-CSR-03: OV-IP & OV-FL Field Validation
- **Objective:** Verify strict validation of INN (12 digits), SNILS (11 digits), and OGRNIP (15 digits).
- **Input:** Invalid INN (e.g. 10 digits for IP)
- **Expected:** Command fails with informative validation error message and exit code 1.

---

### Test Suite 2: ACME Protocol Client & Challenges (TC-ACME)

#### TC-ACME-01: Account Registration & Directory Discovery
- **Objective:** Discover endpoints from `https://nuc-acme.voskhod.ru/acme/api/v1/directory` and register new account key.
- **Expected:** Nonce fetched, account created, status 200/201 returned with Account URL.

#### TC-ACME-02: HTTP-01 Webroot Challenge
- **Objective:** Verify creation and cleanup of `/.well-known/acme-challenge/<token>` file.
- **Expected:** Key authorization correctly computed; file permissions readable by web server; file deleted after order completion.

#### TC-ACME-03: DNS-01 Reg.ru Challenge
- **Objective:** Verify TXT record addition and deletion via Reg.ru API.
- **Expected:** `_acme-challenge.<domain>` TXT record created with correct base64url SHA-256 digest; record deleted upon finalization.

---

### Test Suite 3: CA Trust Store Installation (TC-CA)

#### TC-CA-01: CA Root Installation & TLS Verification
- **Objective:** Download Минцифры root & issuing certificates and test TLS handshake.
- **Input:** `ru-certs ca install --local ./ca-bundle.crt`
- **Expected:** Certificate bundle created; TLS connection to NUC endpoints succeeds without `CERTIFICATE_VERIFY_FAILED`.

---

### Test Suite 4: Lifecycle & Automated Renewal (TC-RENEW)

#### TC-RENEW-01: Expiration-based Renewal Trigger
- **Objective:** Skip certificates >30 days from expiry; renew certificates <=30 days.
- **Expected:** Accurate detection of `notAfter` dates; only expiring certificates trigger ACME re-issuance.
