# ru-certs

[![CI](https://github.com/dimaxgl/ru-certs/actions/workflows/ci.yml/badge.svg)](https://github.com/dimaxgl/ru-certs/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/dimaxgl/ru-certs)](https://goreportcard.com/report/github.com/dimaxgl/ru-certs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**ru-certs** — легковесная CLI-утилита на Go (единый бинарный файл без внешних зависимостей) для автоматизации выпуска, продления и управления SSL/TLS-сертификатами Национального удостоверяющего центра (**Минцифры России / НУЦ Восход**), **Let's Encrypt** и генерации регламентных **ГОСТ Р 34.10-2012** запросов.

---

## ⚡ Особенности и возможности

- **Единый статический бинарник**: Zero-dependency Go CLI. Кросс-компиляция для Linux (`amd64`, `arm64`), macOS (`Apple Silicon`, `Intel`) и Windows.
- **ACME Client (RFC 8555)**:
  - Прямая работа с каталогом НУЦ Восход (`https://nuc-acme.voskhod.ru/acme/api/v1/directory`).
  - Встроенный боевой бандл доверенных корневых и подчиненных сертификатов Минцифры.
  - Автоматический Retry при `badNonce` и поддержка асинхронной финализации заказов.
- **Способы подтверждения владения доменом**:
  - **HTTP-01**: локальная веб-директория (`--webroot`) или встроенный веб-сервер (`--standalone`).
  - **DNS-01**: Cloudflare API v4 (`--dns cloudflare`) и Reg.ru API (`--dns regru`) с поддержкой **Wildcard** (`*.example.ru`).
- **Мульти-сертификатная связка (Triple Certificate Bundle)**:
  - Одновременный выпуск связки `--multi-cert`: **Let's Encrypt + Минцифры RSA + Минцифры ГОСТ**.
- **Генератор конфигураций для веб-серверов (`ru-certs config`)**:
  - Готовые конфигурации для **Nginx** и **Traefik** с автоматической отдачей нужного сертификата клиенту по TLS CipherSuites на этапе ClientHello.
- **Регламентный CSR генератор (ГОСТ 2012 и RSA)**:
  - Поддержка профилей: `dv`, `ov-fl` (физлица), `ov-ip` (ИП), `ov-yl` (юрлица).
  - Вшитые ASN.1 OID РФ: ИНН ЮЛ (`1.2.643.100.4`), ОГРН (`1.2.643.100.1`), ОГРНИП (`1.2.643.100.5`), СНИЛС (`1.2.643.100.3`).
  - Политики применения СКЗИ классов **КС1, КС2, КС3, КБ1, КБ2**.
  - Нативная pure-Go реализация **ГОСТ Р 34.10-2012 (256/512 бит) / 34.11-2012 (Стрибог)**.
  - Автоматическая конвертация кириллицы в Punycode (`домен.рф` → `xn--...`).
- **Безопасное хранилище и автообновление**:
  - Certbot-совместимая структура каталогов (`/etc/ru-certs/live/<domain>/...`).
  - Атомарная запись ключей и сертификатов через временные файлы с фиксацией прав `0600`.
  - Автоматический перевыпуск истекающих сертификатов (`ru-certs renew`).

---

## 📦 Установка

### Готовые бинарные файлы
Скачайте актуальный релиз со страницы [GitHub Releases](https://github.com/dimaxgl/ru-certs/releases):

```bash
# Пример для Linux x86_64
curl -sL https://github.com/dimaxgl/ru-certs/releases/latest/download/ru-certs-linux-amd64.tar.gz | tar xz
sudo mv ru-certs /usr/local/bin/ru-certs
sudo chmod +x /usr/local/bin/ru-certs
```

### Сборка из исходников (Go 1.22+)
```bash
git clone https://github.com/dimaxgl/ru-certs.git
cd ru-certs
go build -o bin/ru-certs ./cmd/ru-certs
sudo mv bin/ru-certs /usr/local/bin/
```

---

## 🚀 Быстрый старт

### 1. Получение сертификата Минцифры через ACME

#### Вариант A: Через Nginx / Apache (HTTP-01 Webroot)
```bash
ru-certs cert obtain \
  -d example.ru -d www.example.ru \
  --email admin@example.ru \
  --webroot /var/www/html
```

#### Вариант B: Через автономный сервер (HTTP-01 Standalone)
```bash
ru-certs cert obtain \
  -d example.ru \
  --email admin@example.ru \
  --standalone
```

#### Вариант C: Через DNS (DNS-01 с Wildcard)

- **Cloudflare**:
  ```bash
  ru-certs cert obtain \
    -d example.ru -d "*.example.ru" \
    --email admin@example.ru \
    --dns cloudflare \
    --cf-token "your_cloudflare_api_token"
  ```
- **Reg.ru**:
  ```bash
  ru-certs cert obtain \
    -d example.ru -d "*.example.ru" \
    --email admin@example.ru \
    --dns regru \
    --regru-user "username" \
    --regru-pass "password_or_api_key"
  ```

---

### 2. Одновременный выпуск 3-х сертификатов (Multi-Cert)

Для максимальной совместимости (международные клиенты + пользователи РФ + ГОСТ-системы):

```bash
ru-certs cert obtain \
  -d mycompany.ru -d "*.mycompany.ru" \
  --email admin@mycompany.ru \
  --dns cloudflare \
  --cf-token "$CLOUDFLARE_API_TOKEN" \
  --multi-cert
```

Сертификаты будут сохранены в:
- `/etc/ru-certs/live/mycompany.ru/letsencrypt/{fullchain.pem, privkey.pem}`
- `/etc/ru-certs/live/mycompany.ru/mintsifry-rsa/{fullchain.pem, privkey.pem}`
- `/etc/ru-certs/live/mycompany.ru/gost/{fullchain.pem, privkey.pem}`

---

### 3. Генерация конфигурации для веб-сервера

Сгенерируйте готовый конфиг, где веб-сервер сам выбирает нужный сертификат под каждого клиента:

- **Nginx**:
  ```bash
  ru-certs config nginx -d "mycompany.ru" -o /etc/nginx/conf.d/mycompany.conf
  sudo nginx -t && sudo systemctl reload nginx
  ```
- **Traefik**:
  ```bash
  ru-certs config traefik -d "mycompany.ru" -o /etc/traefik/dynamic/tls.yml
  ```

---

### 4. Генерация регламентных CSR с реквизитами РФ

#### Для Юридического Лица (ЮЛ) — ГОСТ Р 34.10-2012 (256 бит):
```bash
ru-certs csr \
  --profile ov-yl \
  --key-type gost256 \
  --cn "портал-компании.рф" \
  --org "ООО МОЯ КОМПАНИЯ" \
  --inn-le "7701234560" \
  --ogrn "1237700123451" \
  --state "77 г. Москва" \
  --loc "г. Москва" \
  --street "ул. Тверская, д. 1" \
  --skzi-class KC2 \
  --output ./company_gost.csr
```

#### Для Индивидуального Предпринимателя (ИП):
```bash
ru-certs csr \
  --profile ov-ip \
  --cn "shop.ru" \
  --ogrnip "321774600123456" \
  --inn "770123456789" \
  --snils "12345678901" \
  --output ./ip.csr
```

---

### 5. Доверенные корневые сертификаты Минцифры

- **Экспорт единого бандла PEM**:
  ```bash
  ru-certs ca export /etc/ssl/certs/russian_trusted_ca.pem
  ```
- **Установка в системное хранилище ОС** (Linux / macOS / Windows):
  ```bash
  sudo ru-certs ca install
  ```

---

### 6. Автоматическое продление (Cron / Systemd)

Команда `renew` проверяет сертификаты и перевыпускает те, до окончания срока которых осталось менее 30 дней:

```bash
ru-certs renew
```

#### Настройка Cron:
```bash
# /etc/cron.d/ru-certs-renew
0 3 * * * root /usr/local/bin/ru-certs renew && systemctl reload nginx
```

#### Настройка Systemd Timer:
```ini
# /etc/systemd/system/ru-certs-renew.service
[Unit]
Description=Renew Russian and ACME Certificates
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ru-certs renew
ExecStartPost=/bin/systemctl reload nginx

# /etc/systemd/system/ru-certs-renew.timer
[Unit]
Description=Daily renewal timer for ru-certs

[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
```
Активация:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ru-certs-renew.timer
```

---

## 🛠️ Справка по командам CLI

```
ru-certs [command]

Available Commands:
  ca          Управление корневыми бандлами Минцифры России (export / install)
  cert        Выпуск и управление SSL/TLS-сертификатами (obtain / revoke)
  config      Генерация конфигураций для веб-серверов (nginx / traefik)
  csr         Генерация регламентных PKCS#10 запросов (RSA / ГОСТ 2012)
  renew       Автоматическое продление активных сертификатов

Flags:
      --config-dir string   Путь к каталогу конфигураций (default "/etc/ru-certs")
      --server string       URL каталога ACME (default "https://nuc-acme.voskhod.ru/acme/api/v1/directory")
  -h, --help                Справка
```

---

## 🧪 Тестирование

Запуск полного набора unit-, mock- и интеграционных тестов:

```bash
go test -v -race ./...
```

Проверка покрытия кода:
```bash
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

---

## 📄 Лицензия

Распространяется под лицензией [MIT](LICENSE).
