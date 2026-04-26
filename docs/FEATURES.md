# TrustChain Features / Возможности TrustChain

## 🇺🇸 English

### What is TrustChain?

TrustChain is like a **digital notary for AI**. When an AI assistant uses tools (searches the web, queries a database, calls an API), TrustChain creates a tamper-proof receipt. If anyone tries to change the data later — you'll know immediately.

---

### Open Source (Free Forever)

| Feature | What it does |
|---------|--------------|
| **Ed25519 cryptographic signing** | Every AI response gets a unique "digital seal" that proves it wasn't altered. Like a wax seal on royal letters, but unbreakable. |
| **Chain of Trust** | Links multiple operations together. If step 2 depends on step 1, they're cryptographically connected. Change one — the whole chain breaks. |
| **Nonce replay protection** | Prevents "replay attacks" — someone can't take an old valid response and pretend it's new. Each response is single-use. |
| **AsyncTrustChain** | For modern fast web apps (FastAPI, async Python). Signs responses without slowing down your app. |
| **Pydantic v2 integration** | Your Python data models get automatic signatures. Define a class — it's signed automatically. |
| **LangChain/LangSmith callback** | Works with popular AI frameworks. Drop in one line — all your AI agent's actions are signed. |
| **OpenTelemetry instrumentation** | For monitoring systems. See security signatures alongside performance metrics. |
| **pytest plugin** | Testing made easy. Write tests with built-in signature verification fixtures. |
| **FastAPI/Flask/Django middleware** | Add to your web app with 2 lines of code. All API responses become signed. |
| **Basic ReasoningChain** | Track AI's "thinking process". Each reasoning step is signed and connected. |
| **`.tcreceipt` portable proofs** | Package a signed tool output into a JSON receipt that customers or auditors can verify offline. |
| **Standards export** | Export receipts as SCITT-shaped JSON, W3C VC envelopes, or in-toto Statements. |
| **Chain anchoring** | Export a chain-head checkpoint with `tc anchor export` and verify it later with `tc anchor verify`. |
| **Tool PKI** | Certify tools with source-code hashes, permissions, expiry, and revocation checks before execution. |

---

### Pro ($99/mo per team)

| Feature | What it does |
|---------|--------------|
| **PolicyEngine** | Define rules in simple YAML: "Block transactions over $10,000" or "Require approval for medical data". |
| **ExecutionGraph** | Visual map of everything the AI did. Like a detective board showing who called whom and when. |
| **Streaming ReasoningChain** | Real-time signed stream of AI thinking. For applications where you can't wait for full response. |
| **HTML/PDF audit exports** | One-click beautiful reports for auditors. Show compliance without technical knowledge. |
| **Merkle audit trails** | Mathematical proof that history wasn't altered. Same technology as Bitcoin. |
| **RFC 3161 TSA timestamps** | Legal-grade time certification from official servers. Proves WHEN something happened. |

---

### Enterprise (Custom pricing)

| Feature | What it does |
|---------|--------------|
| **SOC2/HIPAA/FDA compliance** | Pre-built templates for healthcare, finance, pharma regulations. Pass audits faster. |
| **External KMS/HSM** | Use your company's existing security vaults for keys. Integration with AWS KMS, Azure Key Vault, etc. |
| **On-premise deployment** | Everything runs on YOUR servers. No data leaves your building. |
| **Analytics dashboard** | Real-time charts: how many signatures, failures, suspicious patterns. |
| **Redis HA** | High-availability for massive scale. Millions of signatures per second. |
| **Air-gapped deployments** | For ultra-secure environments with no internet connection. |
| **SLA + 24/7 support** | Dedicated team, guaranteed response times, phone support. |

---

## 🇷🇺 Русский

### Что такое TrustChain?

TrustChain — это **цифровой нотариус для ИИ**. Когда ИИ-ассистент использует инструменты (ищет в интернете, обращается к базе данных, вызывает API), TrustChain создаёт защищённую от подделки квитанцию. Если кто-то попытается изменить данные — вы сразу узнаете.

---

### Open Source (Бесплатно навсегда)

| Функция | Что делает |
|---------|------------|
| **Ed25519 криптографическая подпись** | Каждый ответ ИИ получает уникальную "цифровую печать", доказывающую подлинность. Как сургучная печать на королевских письмах, только невзламываемая. |
| **Chain of Trust (Цепочка доверия)** | Связывает несколько операций. Если шаг 2 зависит от шага 1 — они криптографически связаны. Измени один — вся цепочка рухнет. |
| **Защита от replay-атак** | Не даёт использовать старый валидный ответ как новый. Каждый ответ — одноразовый. |
| **AsyncTrustChain** | Для современных быстрых приложений (FastAPI, async Python). Подписывает ответы без замедления. |
| **Интеграция с Pydantic v2** | Ваши Python-модели данных подписываются автоматически. Определил класс — он уже подписан. |
| **LangChain/LangSmith callback** | Работает с популярными AI-фреймворками. Одна строка кода — все действия агента подписаны. |
| **OpenTelemetry инструментация** | Для систем мониторинга. Подписи безопасности рядом с метриками производительности. |
| **pytest плагин** | Простое тестирование. Готовые фикстуры для проверки подписей. |
| **Middleware для FastAPI/Flask/Django** | Добавляется в приложение за 2 строки. Все API-ответы становятся подписанными. |
| **Basic ReasoningChain** | Отслеживает "процесс мышления" ИИ. Каждый шаг рассуждения подписан и связан. |
| **`.tcreceipt` переносимые доказательства** | Упаковывает подписанный результат инструмента в JSON-квитанцию для офлайн-проверки клиентом или аудитором. |
| **Экспорт в стандарты** | Экспортирует квитанции как SCITT-shaped JSON, W3C VC envelope или in-toto Statement. |
| **Anchoring цепочки** | Создаёт checkpoint HEAD цепочки через `tc anchor export` и проверяет его позже через `tc anchor verify`. |
| **Tool PKI** | Сертифицирует инструменты: hash исходного кода, permissions, срок действия и revocation перед выполнением. |

---

### Pro ($99/мес за команду)

| Функция | Что делает |
|---------|------------|
| **PolicyEngine** | Задавайте правила простым YAML: "Блокировать транзакции свыше $10,000" или "Требовать одобрение для медицинских данных". |
| **ExecutionGraph** | Визуальная карта всего, что делал ИИ. Как доска детектива — кто кого вызывал и когда. |
| **Streaming ReasoningChain** | Подписанный поток "мышления" ИИ в реальном времени. Для приложений, которые не могут ждать полного ответа. |
| **HTML/PDF экспорт аудита** | Красивые отчёты для аудиторов одним кликом. Показать соответствие требованиям без технических знаний. |
| **Merkle-деревья аудита** | Математическое доказательство, что история не изменена. Та же технология, что в Bitcoin. |
| **RFC 3161 TSA метки времени** | Юридически значимая сертификация времени от официальных серверов. Доказывает, КОГДА что-то произошло. |

---

### Enterprise (Индивидуальная цена)

| Функция | Что делает |
|---------|------------|
| **Соответствие SOC2/HIPAA/FDA** | Готовые шаблоны для регуляций здравоохранения, финансов, фармацевтики. Проходите аудиты быстрее. |
| **Внешние KMS/HSM** | Используйте существующие хранилища ключей компании. Интеграция с AWS KMS, Azure Key Vault и др. |
| **Развёртывание on-premise** | Всё работает на ВАШИХ серверах. Никакие данные не покидают здание. |
| **Аналитическая панель** | Графики в реальном времени: сколько подписей, сбоев, подозрительных паттернов. |
| **Redis HA** | Высокая доступность для огромных масштабов. Миллионы подписей в секунду. |
| **Air-gapped развёртывание** | Для сверхзащищённых сред без интернет-подключения. |
| **SLA + поддержка 24/7** | Выделенная команда, гарантированное время ответа, телефонная поддержка. |

---

## Quick Start

```python
# Install
pip install trustchain

# Use
from trustchain import TrustChain

tc = TrustChain()

@tc.tool("my_api")
def get_data(query: str):
    return {"result": "secret data"}

response = get_data("test")
print(response.signature)  # Уникальная подпись / Unique signature
print(tc.verify(response))  # True = не изменено / not tampered
```
