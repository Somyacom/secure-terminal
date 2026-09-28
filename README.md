# SECURE-TERMINAL - защищённый обмен терминал - сервер

Прототип защищённого обмена данными между терминалом и сервером. Что он обеспечивает:
- подлинность источника и неотказуемость (подписи хранятся в журнале и проверяются задним числом);
- целостность;
- конфиденциальность тела поверх TLS 1.3;
- защиту от повторной отправки, в том числе между процессами и после перезапуска;
- устойчивость к перегрузке: лимиты по IP и по терминалу, квоты, проверка подписи вне event loop;
- строгую обработку входных данных.

Криптография **гибридная постквантовая**: каждая операция одновременно опирается на классический алгоритм и на постквантовый стандарт NIST 2024 года. Собственных примитивов нет.

## Файлы

`crypto.py`  вся криптография: гибридная подпись, HPKE, форматы ключей, подписываемые строки 
`server.py`  сервер: конвейер проверок, лимиты, команды `serve` и `verify-journal` 
`store.py`  SQLite: nonce (общие для всех воркеров) и журнал событий с доказательствами 
`keystore.py`  файлы ключей: атомарная запись 0600, проверка прав, шифрование паролем, реестр 
`keytool.py`  управление ключами: `server-init`, `terminal-init`, `register`, `revoke`, `restore`, `list`, `demo`
`client.py`  клиент терминала: `send`, `get`, `explain` 
`test_all.py`  100 автотестов 
`deploy/`  `secure-terminal.service` (systemd), `nginx.conf` 
`requirements.txt` / `requirements.lock`  диапазоны версий / точные версии с SHA-256 

## Быстрый старт на одной машине
Нужен Python 3.10+.
```bash
python3 -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements.lock
python -m pytest -q                                       # 100 passed

python keytool.py demo term-001 term-002                  # keys/: server.json, terminals.json, term-*.json
python server.py serve                                    # http://127.0.0.1:8000, база data/journal.db
```

Во втором окне:

```bash
source .venv/bin/activate
python client.py send --keys keys/term-001.json operation --payload amount=150 currency=RUB
# {"event_id": "62a730e3bb29437593088d1e3c01db76"}
python client.py get  --keys keys/term-001.json 62a730e3bb29437593088d1e3c01db76
python client.py get  --keys keys/term-002.json 62a730e3bb29437593088d1e3c01db76   # чужое - 404
python server.py verify-journal --keys keys/server.json                              # записей: 1, ошибок: 0
```

Без TLS сервер слушает только `127.0.0.1`, а клиент ходит по `http://` только на localhost. Это режим отладки.

## Эксплуатация: сервер и терминалы на разных машинах

### 1. Сервер: ключи

```bash
python keytool.py server-init --encrypt           # спросит пароль (≥12 символов) дважды
# keys/server.json       секреты сервера, зашифрованы паролем, 0600
# keys/server.pub.json   раздать на терминалы
# keys/terminals.json    реестр терминалов
# отпечаток сервера: eccd:ea30:a6ba:4ba4:0ba6:14b4:f790:0c58
```

### 2. Терминал: свои ключи на самом устройстве

Скопируйте на терминал `server.pub.json` (он не секретный) и выполните:

```bash
python keytool.py terminal-init term-001 --server-pub server.pub.json
# keys/term-001.json       секреты терминала, 0600 (никуда не копируются)
# keys/term-001.pub.json   отправить на сервер
# закреплён сервер:    eccd:ea30:…   ← сверьте с отпечатком из шага 1
# отпечаток терминала: 968d:1800:e721:1b56:fcd2:8a5f:de1b:0671
```

### 3. Сервер: регистрация терминала

```bash
python keytool.py register term-001.pub.json
# терминал term-001, отпечаток 968d:1800:e721:1b56:fcd2:8a5f:de1b:0671
# Отпечаток совпадает с показанным на терминале? [y/N]
```

Отпечаток сверяется по независимому каналу (телефон, акт установки). Так подменённый по дороге ключ не будет зарегистрирован. Работающий сервер подхватывает изменения реестра в течение секунды.

### 4. TLS

Вариант А, TLS в самом сервере (TLS 1.3, ниже не принимается):

```bash
python server.py serve --host 0.0.0.0 --port 8443 --workers 2 \
    --tls-cert /etc/secure-terminal/tls.crt --tls-key /etc/secure-terminal/tls.key \
    --passphrase-file /etc/secure-terminal/passphrase
```

Вариант Б, за nginx (`deploy/nginx.conf`): сервер слушает `127.0.0.1:8000` с `--behind-proxy`, nginx держит TLS и первый рубеж лимитов.

Свой CA для закрытой сети терминалов (сертификат сервера должен содержать его имя или IP в subjectAltName):

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -keyout ca.key -out ca.crt -subj "/CN=ST Terminal CA"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout tls.key -out tls.csr -subj "/CN=st.example.local"
printf "subjectAltName=DNS:st.example.local,IP:10.0.0.5\n" > san.ext
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out tls.crt -extfile san.ext
chmod 600 tls.key ca.key        # ca.key храните вне сервера
```

### 5. Терминал: работа

```bash
export ST_URL=https://st.example.local:8443 ST_CA_FILE=/opt/secure-terminal/ca.crt
python client.py send --keys keys/term-001.json login --payload user=alice
```

С `--ca` / `ST_CA_FILE` клиент доверяет **только** этому CA (закрепление), системное хранилище не используется. Без него сертификат проверяется по системному хранилищу. Проверку отключить нельзя.

### 6. Отзыв и восстановление

```bash
python keytool.py revoke term-002      # действует через ≤1 с, перезапуск не нужен
python keytool.py restore term-002
python keytool.py list
```

### 7. Проверка журнала

```bash
python server.py verify-journal --db data/journal.db --registry keys/terminals.json \
    --keys keys/server.json --passphrase-file /etc/secure-terminal/passphrase
# записей: 2, ошибок: 0, головной хеш: 00e5129b…
```

Для каждой записи проверяется цепочка хешей, подпись терминала и совпадение полей с подписанным шифртекстом. Без `--keys` проверяются только цепочка и подписи: для этого достаточно публичного реестра. Головной хеш стоит периодически фиксировать во внешней системе. Тогда удаление хвоста журнала тоже будет заметно.

### 8. Постоянная работа (systemd + nginx)

```bash
sudo useradd -r -s /usr/sbin/nologin st
sudo mkdir -p /opt/secure-terminal /var/lib/secure-terminal /etc/secure-terminal
sudo cp *.py requirements.lock /opt/secure-terminal/
sudo python3 -m venv /opt/secure-terminal/.venv
sudo /opt/secure-terminal/.venv/bin/pip install --require-hashes -r /opt/secure-terminal/requirements.lock
sudo install -m 600 /dev/stdin /etc/secure-terminal/passphrase <<< 'ваш-длинный-пароль'   # читает только root/systemd
cd /var/lib/secure-terminal && sudo /opt/secure-terminal/.venv/bin/python /opt/secure-terminal/keytool.py \
    server-init --encrypt --passphrase-file /etc/secure-terminal/passphrase
sudo chown -R st:st /var/lib/secure-terminal && sudo chmod 700 /var/lib/secure-terminal
sudo cp deploy/secure-terminal.service /etc/systemd/system/
sudo cp deploy/nginx.conf /etc/nginx/conf.d/secure-terminal.conf && sudo nginx -t && sudo systemctl reload nginx
sudo systemctl daemon-reload && sudo systemctl enable --now secure-terminal
journalctl -u secure-terminal -f
```

Время на всех машинах синхронизируйте через NTP (`chrony`): допуск ±30 с.

## Лимиты по умолчанию

`ip_rate` / `ip_burst`  20 запросов/с с IP, всплеск 40 (до любой работы) 
`key_rate` / `key_burst`  10 запросов/с на терминал, всплеск 20 
`max_nonces_per_key`  2 000 живых nonce на терминал 
`max_events_per_key`  1 000 000 событий на терминал 
`event_retention_days`  0 — хранить вечно 
`verify_concurrency` / `max_verify_queue`  число ядер / 64 ожидающих, дальше 503 
`--limit-concurrency`  256 соединений на воркер 

Лимиты частоты считаются в каждом воркере отдельно (при `--workers 2` фактический предел по IP вдвое выше). Квоты nonce и событий общие, они хранятся в базе.

### Алгоритмы

| Задача | Алгоритм | Стандарт | Почему он |
|---|---|---|---|
| Подпись (классическая половина) | Ed25519 | RFC 8032 | быстрый, детерминированный, проверен годами |
| Подпись (постквантовая половина) | ML-DSA-65 | NIST FIPS 204 (2024) | устойчив к квантовому компьютеру; уровень 3 (≈ AES-192) |
| Обмен ключами | ML-KEM-768 + X25519 (гибрид) | FIPS 203 + RFC 7748 | секрет безопасен, пока стоек *хотя бы один* из двух |
| Шифрование тела | HPKE | RFC 9180 | стандартная схема «зашифровать на публичный ключ» |
| Выработка ключа | HKDF-SHA256 | RFC 5869 | стандарт HPKE |
| Шифр + аутентификация | ChaCha20-Poly1305 | RFC 8439 | постоянное время без аппаратного AES (важно для терминалов) |
| Защита от повтора | метка времени ±30 с + nonce 128 бит | — | nonce из системного CSPRNG |

Секретный ключ терминала никогда не покидает терминал. Поэтому **даже полностью скомпрометированный сервер не может подделать запрос терминала**. В первой версии с HMAC это было не так. Кроме того, подпись даёт неотказуемость.
### Гибридная подпись

```
                        ┌──────────────► Ed25519.sign(sk_ed, m) ─────────────► 64 Б  ─┐
   m (подписываемая ────┤                                                             ├─► X-Signature
     строка)            └──────────────► ML-DSA-65.sign(sk_ml, m, ctx) ──────► 3309 Б ─┘   3373 Б → base64url 4498 симв.

   Проверка: длина == 3373  И  Ed25519 верна  И  ML-DSA-65 верна   (обе проверяются всегда)
```

- Чтобы подделать подпись, нужно взломать **оба** алгоритма. Квантовый компьютер ломает Ed25519, но не ML-DSA. Если в новом ML-DSA найдут слабость, остаётся Ed25519.
- Длина подписи фиксирована, поэтому одну половину нельзя отрезать и выдать остаток за подпись.
- `ctx = "SECURE-TERMINAL/v2"`: FIPS 204 позволяет пришить контекст к подписи ML-DSA. Подпись из другого протокола здесь не пройдёт.

### Шифрование тела (HPKE)

```
  ОТПРАВИТЕЛЬ                                                 ПОЛУЧАТЕЛЬ
  ───────────                                                 ──────────
  ML-KEM-768.Encap(pk) ─┐                                   ┌─ ML-KEM-768.Decap(sk, enc₁)
  X25519(eph, pk)      ─┴─► общий секрет ─► HKDF(·, info) ─►  │  X25519(sk, enc₂)
                                  │                           └─► тот же секрет ─► HKDF(·, info)
                                  ▼                                                     ▼
                     ChaCha20-Poly1305.seal(JSON)                     ChaCha20-Poly1305.open(...)

  На проводе:
  ┌──────────────────────────────────┬──────────────────┬───────────────┐
  │ капсула enc  1120 Б              │ шифртекст  N Б   │ тег  16 Б     │
  │ (ML-KEM 1088 Б + X25519 32 Б)    │ (= длине JSON)   │ (Poly1305)    │
  └──────────────────────────────────┴──────────────────┴───────────────┘
```

`info` — контекст, который входит в выработку ключа: метод, путь, `key_id`, время, nonce. Если подменить что-то одно, получится другой ключ, и расшифровка упадёт.

### Почему сначала шифрование, потом подпись

1. **Подделки отсекаются дёшево.** Сервер проверяет подпись (≈0,35 мс) до расшифровки и не тратит ресурсы на мусор.
2. **Подпись покрывает каждый байт шифртекста**, потому что в подписываемой строке есть его SHA-256.
3. **Классическая атака на такую схему закрыта.** Терминал B перехватывает шифртекст терминала A и отправляет его от своего имени со своей верной подписью. Подпись пройдёт, но `key_id = B` попадёт в `info`, ключ получится другим, и расшифровка упадёт. Сервер ответит `400 undecryptable`. Это проверяет тест `test_ciphertext_resigned_by_other_terminal_not_decryptable`.

### Что именно подписывается

```
запрос                                     ответ
──────                                     ─────
SECURE-TERMINAL/v2 REQUEST                 SECURE-TERMINAL/v2 RESPONSE
POST                                       201
/v1/events            ← с query, как есть  term-001
term-001                                   f142…928b   ← nonce ЗАПРОСА: ответ привязан
1790354099                                 1790354100
f142683d6aa20767bebb6111d809928b           <SHA-256 зашифрованного тела ответа>
8fadfdff…b55b3c5d3    ← SHA-256 шифртекста
```

Поля разделены `\n`. Все поля проверяются через `re.fullmatch`, так что `\n` внутри поля невозможен.
### Цена
Замер в среде разработки, Python 3.11, `cryptography` 50:
| Операция | Время |
|---|---|
| терминал: зашифровать и подписать запрос | ≈ 1,3 мс |
| сервер: проверить гибридную подпись | ≈ 0,35 мс |
| сервер: расшифровать HPKE | ≈ 0,15 мс |

По размеру: к телу добавляется 1136 Б (капсула и тег), к заголовкам ≈ 4,5 КБ подписи. Это нужно учесть в лимитах прокси: например, `large_client_header_buffers` в nginx должен быть не меньше 8 КБ.

### Тест-векторы

Ed25519 детерминирован, поэтому его половину подписи можно зафиксировать. Вектор закреплён в `test_ed25519_part_is_deterministic_vector` и сверен через `openssl pkeyutl -sign -rawin`. Подписи ML-DSA и шифрование HPKE намеренно рандомизированы, поэтому для них проверяются свойства: круговой прогон, привязка к контексту, отказ при изменении.

## Остаточные риски (кодом не закрываются)
- **Черновые стандарты.** HPKE с ML-KEM-768+X25519 сделан по черновику IETF, гибридная подпись - конкатенация, а не draft composite-sigs. Это решение библиотеки и индустрии; смена набора алгоритмов сосредоточена в `crypto.py`, версия протокола входит во все подписи.
- **Несколько хостов.** SQLite общий для воркеров одного хоста. Для нескольких серверов за балансировщиком нужно общее хранилище (PostgreSQL/Redis) с теми же операциями `claim_nonce` и `add_event`.
- **Скомпрометированный сервер** читает все тела и может подделать ответы, но не может подделать запрос терминала: его подпись в журнале остаётся доказательством.
- **Кража ключа с терминала.** Шифрование файла паролем и права 0600 защищают от копирования, но не от вредоносного кода на самом терминале. В эксплуатации ключ стоит держать в TPM/secure element.
- **Объёмный DDoS** выше уровня приложения закрывается на уровне сети (провайдер, allowlist адресов терминалов в nginx).

## Допущения

- Нужна `cryptography` 50.x (проверено на 50.0.1).
- Заголовки (метод, путь, `key_id`) не шифруются: они нужны для маршрутизации; от сети их скрывает TLS.
- Часы синхронизированы с точностью ±30 с.
- Прокси перед сервером не должен менять путь и query: они подписаны.
UPD, важный: setup.sh создаёт ключи через keytool.py demo в открытом виде. На рабочем сервере нужен server-init --encrypt
