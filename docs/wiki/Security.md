# Безопасность TrustChain

> Краткий, честный и заранее подготовленный ответ для security review, due diligence и вопросов про SOC 2.

## Что такое TrustChain с точки зрения безопасности

TrustChain не является "волшебной системой доверия". Это криптографический слой поверх AI-инструментов и агентных вызовов.

Он решает четыре конкретные задачи:

1. Подтверждает, **кто именно подписал ответ**.
2. Позволяет обнаружить **подмену или изменение payload после подписи**.
3. Добавляет **freshness / replay semantics** через `nonce` и `timestamp`.
4. Дает **проверяемый audit trail** через цепочку подписей и verifiable log.

TrustChain не доказывает, что результат "истинен", "безопасен" или "не содержит вредоносной бизнес-логики". Он доказывает происхождение, целостность и проверяемость.

## Из чего состоит модель доверия

### `trust_chain`

Базовое OSS-ядро.

Отвечает за:

- Ed25519-подписи ответов и tool outputs.
- Подписываемый canonical payload, в который входят `tool_id`, `data`, `timestamp`, `nonce`, `parent_signature`, а также доверительные метаданные.
- Проверку свежести и защиту от replay.
- Chain-of-Trust между последовательными действиями.
- X.509 PKI primitives, CRL и проверку цепочки сертификатов.
- Verifiable append-only log / Merkle proofs.
- Явный adapter API для внешних nonce backends через `TrustChainConfig(nonce_storage=...)`.

### `TrustChain_Platform`

Платформенный trust distribution layer.

Отвечает за:

- выпуск и публикацию сертификатов;
- CRL / revocation;
- публичный registry;
- lifecycle агентов;
- marketplace / сертификацию tools;
- платформенный verifiable log.

Важно: внешний клиент **не должен верить API платформы на слово**. Он должен:

1. получить `agent cert`;
2. получить `Platform CA`;
3. получить `Root CA`;
4. проверить цепочку локально;
5. проверить CRL локально;
6. только потом использовать public key из сертификата.

### `trust_chain_pro`

Enterprise-слой поверх ядра.

Отвечает за:

- HA nonce storage;
- KMS / HSM / encrypted local key storage;
- TSA / time anchoring;
- compliance / forensic / export tooling;
- аналитический и операционный слой.

Pro не должен подменять собой криптографическое ядро. Если что-то критично для trust semantics, это должно быть либо в `trust_chain`, либо строго опираться на него.

## Что гарантируется криптографически

При корректной интеграции TrustChain гарантирует:

- изменение подписанного payload будет обнаружено;
- доверительные метаданные не могут быть тихо подменены без инвалидирования подписи;
- повторно использованный `nonce` будет считаться replay;
- устаревшие ответы могут быть отклонены по freshness policy;
- revoked certificate не должен считаться валидным;
- sub-agent certificate становится недоверенным при отзыве родителя;
- verifiable log позволяет проверить целостность истории.

## Что НЕ гарантируется

TrustChain не решает следующие проблемы сам по себе:

- скомпрометированный runtime, который честно подписывает вредоносный ответ;
- утечка private key на стороне оператора;
- prompt injection, data poisoning и supply-chain риски без дополнительных controls;
- RBAC, IAM, change management и incident response как организационные процессы;
- соответствие SOC 2 "по факту наличия библиотеки".

## Ответы на типовые вопросы безопасника

### Нужно ли отправлять payload на внешний сервер для проверки?

Нет. Нормальная модель проверки офлайн-локальная.

### Нужен ли SaaS, чтобы использовать TrustChain?

Нет. Базовые подписи и проверка работают локально. Platform нужен там, где есть межорганизационное доверие, публичный registry или централизованная revocation/distribution модель.

### Уходят ли private keys из контура?

Не должны. Private key должен оставаться у оператора или в KMS/HSM. Если deployment строится так, что сервер генерирует leaf private key "за агента", это transitional design и плохой security posture.

### Можно ли использовать собственный nonce backend?

Да. Ядро поддерживает adapter-compatible backend через:

```python
from trustchain import TrustChain, TrustChainConfig

tc = TrustChain(TrustChainConfig(
    nonce_storage=my_storage,
    nonce_ttl=300,
))
```

Backend должен поддерживать либо `check_and_add(nonce, ttl=...)`, либо `add(nonce)` + `contains(nonce)`.

### Что такое public registry?

Это не "сервер, который говорит кому верить". Это точка распространения сертификатов и CRL. Доверие строится на pinned Root CA и локальной верификации цепочки.

## SOC 2: что уже близко к требованиям

Следующие свойства хорошо ложатся на SOC 2 narrative:

- cryptographic integrity и tamper evidence;
- replay protection;
- revocation model;
- append-only / verifiable audit trail;
- separation between public verification data и private signing material;
- explicit certificate chain / trust anchor model;
- возможность локальной верификации без передачи клиентских данных наружу.

## SOC 2: что еще нельзя честно считать завершенным

Ниже перечислены реальные gaps, которые нельзя маскировать маркетингом.

### 1. `TrustChain_Platform` еще не является полной SOC 2-ready control plane

Проблемные зоны:

- platform code historically был собран условно и не везде жил на той же trust model, что и ядро;
- не все API изначально использовали полноценный signed envelope;
- часть operational controls зависит от конкретного deployment, а не от продукта по умолчанию.

### 2. Выдача agent identity должна опираться на владение ключом агентом

Целевое состояние для серьезных окружений:

- CSR-based enrollment, либо
- issuance against externally supplied public key, либо
- KMS/HSM-backed enrollment flow.

Если private key leaf-сертификата генерируется и удерживается сервером "за агента", это неудобно для zero-trust и плохо для аудита владения ключом.

### 3. KMS / HSM не должны быть "опцией только в презентации"

Для high-assurance deployment нужны:

- documented key management policy;
- key rotation procedure;
- secret storage discipline;
- production path через KMS/HSM или хотя бы encrypted local key provider.

### 4. Нужны зрелые operational controls вокруг Platform

Вне криптографии остаются обязательные практики:

- RBAC и least privilege;
- audit of admin actions;
- backup / restore / DR;
- secure SDLC и change approval;
- centralized monitoring / alerting;
- incident response procedure;
- access review и secret rotation evidence.

## Практическая позиция проекта

Честная позиция должна звучать так:

- `trust_chain` уже дает сильное криптографическое ядро и локальную проверяемость;
- `TrustChain_Platform` движется к правильной модели доверия, но требует дальнейшего hardening;
- `trust_chain_pro` добавляет enterprise controls, но не должен обещать больше, чем реально поддерживает ядро и runtime integration.

## Рекомендуемый deployment для серьезных сред

Минимально разумный профиль:

1. Pinned Root CA.
2. Локальная верификация цепочки и CRL.
3. Replay protection через shared nonce backend.
4. KMS/HSM или encrypted key storage.
5. Verifiable log с регулярной проверкой целостности.
6. Separate admin access path для Platform.
7. Документированные процедуры revoke / rotate / incident review.

## Что говорить прямо, если спрашивают "готово ли это к SOC 2?"

Правильный ответ:

`trust_chain` дает сильную криптографическую основу для SOC 2-aligned architecture, но само соответствие SOC 2 зависит не только от библиотеки, а от того, как развернуты Platform, key management, access controls, logging, backups, change management и incident response.`

Именно такой ответ лучше любого "да, конечно, enterprise-ready" без доказательств.
