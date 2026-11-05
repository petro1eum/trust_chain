# Действующие контракты подписей и canonicalization

F09 из `TrustChain_Agent/docs/TRUSTCHAIN-TECHNOLOGY-AS-IS-TO-BE-2026-10-19.md`.
Каталог фиксирует действующие границы для рефакторинга. Он не вводит новый
формат документа, версию подписи или общий сериализатор для всех компонентов.

## SDK SignedResponse и tcreceipt

Владелец: `trust_chain`. Реализация: [signer.py](../trustchain/v2/signer.py),
[receipt.py](../trustchain/receipt.py).

| Профиль | Выбор | Подписываемые байты |
| --- | --- | --- |
| Legacy SignedResponse | `canon` отсутствует или `null` | `_canonical_bytes(data, None)`: Python `json.dumps(sort_keys=True, separators=(",", ":"))`, затем UTF-8. Настройки `ensure_ascii` и чисел сохраняются как в этой функции. |
| Явный legacy | `canon="json-sort-keys-minified"` | Тот же способ сериализации, но поле `canon` включено в подписываемый объект. Добавление этого поля к старому документу меняет подпись. |
| JCS | `canon="jcs"` | `_canonical_bytes(data, "jcs")` вызывает `rfc8785.dumps`. Это opt-in; профиль по умолчанию не меняется. |

Обязательный подписываемый набор строит `_build_canonical_data`:
`tool_id`, `data`, `timestamp`, `nonce`, `parent_signature`.
Современный вариант также покрывает `signature_id`; verifier сохраняет
совместимость с историческим вариантом без него.

При наличии включаются `parent_signatures`, `metadata`, `certificate`,
`tsa_proof`, `signer_role`, `custody`, `input_hash`, `alg`, `canon`.
Поле `signature` не входит в подписываемые байты. Отдельного префикса нет.
Для проверки следует вызывать `Signer.verify`, `verify_with_public_key`
или `Receipt.verify`, которые используют этот же построитель.

`tcreceipt` версии 1 переносит SignedResponse в `envelope`. Обёртка
`format/version/issued_at/key/summary/identity/witnesses` не превращается
целиком в подписываемый payload. Публичный ключ проверяется и, при необходимости,
закрепляется отдельно; наличие красивого summary не доказывает подпись.

Неизвестный `canon` не разрешает запасной способ сериализации.
Удаление или изменение существующего `canon` также должно отвергаться.

### Граница JavaScript

`trustchain/js_sdk/receipt.mjs`, `TrustChainVerifier` в `trustchain.js` и
`examples/verify.html` сохраняют свой существующий немаркированный legacy-путь.
Эта запись не объявляет их универсальными реализациями Python JSON или JCS.

Явный ненулевой `canon` в этих JS-проверяющих не поддерживается: результат
отклоняется, а сериализатор квитанции сообщает об unsupported profile.
Даже известный Python-профиль нельзя молча проверять как другой формат.
`SignedResponse` в JS сохраняет поле при decode/encode, чтобы промежуточная
модель не удаляла ограничение перед проверкой. `undefined` и `null` сохраняют
существующее legacy-поведение. Проверка помеченных документов доступна в Python.

## Platform workload broker

Владелец: `TrustChain_Platform`,
`backend/app/services/trustchain_secrets_broker_client.py` и
`services/trustchain_secrets_workload_broker/app.py`.

Транспорт: `trustchain.secrets.workload-signing.v1`.
Квитанция: `trustchain.secrets.workload-signing.receipt.v1`.

Подпись workload покрывает **точные входные bytes payload**, а не его повторную
сериализацию. Квитанция подписывается отдельным receipt key над:

```text
b"TrustChain-Secrets-Receipt\x00v1\x00" + canonical_json(claims)
```

`canonical_json` — sorted/minified Python JSON, `ensure_ascii=False`,
`allow_nan=False`, UTF-8. Все поля `claims` входят в подпись. Consumer дополнительно
проверяет схему, request, binding, payload/result hashes и закреплённые ключи.
Это не SignedResponse и не JCS-профиль SDK.

## APatch governed-work documents

Владелец: APatch, `apatch/governed_work.py`.
Схемы: `apatch.change.v1`, `apatch.timesheet-draft.v1`,
`apatch.work-evidence-bundle.v1`, `trustchain.project-source-binding.v1`.

`sign_document` покрывает весь документ **без** поля `signature`, используя
`canonical_bytes`: `_normalise`, sorted/minified JSON,
`ensure_ascii=False`, `allow_nan=False`, UTF-8. Проверять нужно тем же владельцем
формата, сохраняя ограничения `_normalise`.

Platform-вариант governed-work имеет отдельную domain separation:

```text
b"TrustChain-Governed-Work\x00v1\x00" + purpose.encode("ascii")
    + b"\x00" + canonical_bytes(document_without_signature)
```

Одинаковый документ с другим purpose или без префикса не является той же подписью.
Нельзя подменить этот путь вызовом SignedResponse.sign.

## Native Secrets broker

Владелец: Secrets, `local/secrets-console/macos/BrokerReceiptSigner.swift`,
`NativeAdminController.swift`; consumer — APatch `trust_identity.py`.

Подпись основной операции покрывает точные bytes запроса. Native receipt имеет
свой envelope версии 1: связывает request, binding, secret/version, tool,
payload/result hashes, policy, caller и сроки. Все переданные поля envelope
подписываются отдельным attestation key через Foundation
`JSONSerialization` с `.sortedKeys` и `.withoutEscapingSlashes`.

Публичный результат передаёт `receipt_envelope_json` и подпись этого JSON.
Consumer проверяет подпись переданных bytes и соответствие полей исходному
запросу. Нельзя заменить эти bytes «эквивалентным» JSON другого профиля.

Привязка attestation key отдельно подписывается workload key. Её поля:
`attestation_public_key_b64`, `binding_id`,
`domain="trustchain-secrets/broker-attestation-key/v1"`.
Здесь domain — подписываемое JSON-поле, а не префикс Platform receipt.

## Форматы ошибок

| Граница | Сохраняемый контракт |
| --- | --- |
| APatch MCP/runtime | Существующие `ok`, `error_type`, `recommended_action`, `cause`, signing request/result и checkpoint. Диагностика не разрешает повтор эффекта. |
| Native signer / stdio | Legacy signature output либо согласованный `signing-result-v1`; ошибка `SECRETS_SIGNING_ERROR` в stderr с request/code. Не превращать stderr в HTTP-документ. |
| Platform workload broker | HTTP status и ограниченная wire-schema `error_code`, при наличии — проверенный request id. Ошибка не заменяет проверку подписанной квитанции. |

Общие функции извлекаются только после подтверждения одинаковых bytes,
полей, domain и правил приёма. Изменение HTTP-представления ошибки не меняет
MCP/stdio или подписываемые документы.

## Проверки совместимости

- `tests/test_jcs_canonicalization.py`: прежние legacy bytes, opt-in JCS,
  неизвестный профиль, подмена данных и удаление `canon`.
- `tests/test_signature_id_canonical.py`, `tests/test_receipt.py`,
  `tests/test_hard_kms_signer.py`: существующие подписи и проверки SDK.
- `trustchain/js_sdk/test/canonicalization-profiles.test.mjs`: прежний legacy
  продолжает проходить; добавление профиля отвергается в SDK и в функциях,
  извлечённых из поставляемого HTML; decode/encode не теряет `canon`.

Эти автоматические проверки не являются проверкой установленного приложения,
Touch ID или опубликованной версии.
