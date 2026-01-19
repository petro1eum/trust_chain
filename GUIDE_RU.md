# TrustChain -- Руководство пользователя

## Что такое TrustChain?

TrustChain -- это библиотека Python для криптографической подписи ответов AI-инструментов. Она решает проблему доверия: когда AI-агент вызывает функцию (tool), нет гарантии, что результат настоящий, а не галлюцинация.

TrustChain добавляет к каждому ответу:
- Криптографическую подпись (Ed25519)
- Уникальный nonce (защита от повторных атак)
- Временную метку
- Опционально: связь с предыдущим шагом (Chain of Trust)

---

## Установка

```bash
pip install trustchain
```

Для дополнительных возможностей:
```bash
pip install trustchain[mcp]      # MCP Server для Claude Desktop
pip install trustchain[langchain] # LangChain интеграция
pip install trustchain[redis]     # Распределенный nonce storage
```

---

## Быстрый старт

### Базовое использование

```python
from trustchain import TrustChain

# Создаем экземпляр TrustChain
tc = TrustChain()

# Регистрируем функцию как подписываемый инструмент
@tc.tool("weather")
def get_weather(city: str) -> dict:
    """Получить погоду в городе."""
    return {"city": city, "temp": 22, "conditions": "sunny"}

# Вызываем функцию -- получаем подписанный ответ
result = get_weather("Moscow")

# result -- это объект SignedResponse
print(result.data)       # {'city': 'Moscow', 'temp': 22, ...}
print(result.signature)  # Base64-encoded Ed25519 signature
print(result.nonce)      # UUID для защиты от replay-атак
```

### Проверка подписи

```python
# Проверяем подлинность ответа
is_valid = tc.verify(result)
print(is_valid)  # True

# При повторной проверке того же nonce -- ошибка
try:
    tc.verify(result)
except NonceReplayError:
    print("Replay attack detected!")
```

---

## Основные концепции

### SignedResponse

Когда вы вызываете функцию, обернутую декоратором `@tc.tool()`, возвращается не сырые данные, а объект `SignedResponse`:

| Поле | Описание |
|------|----------|
| `data` | Результат функции (любой тип) |
| `signature` | Ed25519 подпись в Base64 |
| `signature_id` | Уникальный ID подписи (UUID) |
| `timestamp` | Unix timestamp создания |
| `nonce` | Уникальный ID для защиты от replay |
| `tool_id` | Идентификатор инструмента |
| `parent_signature` | Ссылка на предыдущий шаг (Chain of Trust) |

### Как работает подпись

1. Создается каноническое представление данных (JSON)
2. Данные хешируются SHA-256
3. Хеш подписывается приватным ключом Ed25519
4. Подпись кодируется в Base64

Проверка:
1. Восстанавливается каноническое представление
2. Подпись декодируется из Base64
3. Публичный ключ проверяет подпись

### Защита от Replay-атак

Nonce (Number used ONCE) гарантирует, что каждый ответ можно проверить только один раз.

Сценарий атаки:
```
1. Хакер перехватывает ответ "Перевести $100"
2. Хакер отправляет его 100 раз
3. Украдено $10,000
```

С TrustChain:
```python
tc.verify(result)  # OK -- первый раз
tc.verify(result)  # NonceReplayError -- nonce уже использован
```

---

## Chain of Trust (Цепочка доверия)

Позволяет связывать несколько операций криптографически.

### Зачем это нужно?

Когда AI выполняет многошаговую задачу:
1. Поиск данных
2. Анализ
3. Генерация отчета

Нужно доказать, что шаг 2 был выполнен на основе шага 1, а не выдуман.

### Использование

```python
from trustchain import TrustChain

tc = TrustChain()

# Шаг 1: Поиск (без родителя)
step1 = tc._signer.sign("search", {"query": "balance", "results": [100, 200]})

# Шаг 2: Анализ (ссылается на шаг 1)
step2 = tc._signer.sign(
    "analyze", 
    {"summary": "total=300"},
    parent_signature=step1.signature  # Связь с предыдущим шагом
)

# Шаг 3: Отчет (ссылается на шаг 2)
step3 = tc._signer.sign(
    "report",
    {"text": "Balance is 300"},
    parent_signature=step2.signature
)

# Проверка всей цепочки
chain = [step1, step2, step3]
is_valid = tc.verify_chain(chain)
print(is_valid)  # True -- цепочка не нарушена
```

### Что проверяет verify_chain?

1. Каждая подпись валидна
2. Каждый `parent_signature` совпадает с `signature` предыдущего шага
3. Цепочка не разорвана

---

## Конфигурация

### Базовые опции

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(
    algorithm="ed25519",      # Алгоритм подписи
    enable_nonce=True,        # Защита от replay-атак
    enable_cache=True,        # Кэширование ответов
    cache_ttl=3600,           # Время жизни кэша (секунды)
    nonce_ttl=86400,          # Время жизни nonce (секунды)
)

tc = TrustChain(config)
```

### Распределенная конфигурация (Redis)

Для нескольких серверов:

```python
config = TrustChainConfig(
    nonce_backend="redis",
    redis_url="redis://localhost:6379/0",
    nonce_ttl=86400,
)

tc = TrustChain(config)
```

### Multi-Tenancy

Для SaaS с разными клиентами:

```python
from trustchain import TenantManager

manager = TenantManager(
    redis_url="redis://localhost:6379",
    key_storage_dir="./keys"  # Где хранить ключи клиентов
)

# Получить TrustChain для конкретного клиента
tc_acme = manager.get_or_create("acme_corp")
tc_beta = manager.get_or_create("beta_inc")

# У каждого клиента свои ключи
print(tc_acme.get_key_id())  # key-abc123...
print(tc_beta.get_key_id())  # key-xyz789...
```

---

## Интеграции

### OpenAI / Anthropic Schema

TrustChain автоматически генерирует JSON Schema для функций:

```python
# OpenAI формат
schema = tc.get_tool_schema("weather")
# {
#   "type": "function",
#   "function": {
#     "name": "weather",
#     "description": "Получить погоду в городе.",
#     "parameters": {...}
#   }
# }

# Anthropic формат
schema = tc.get_tool_schema("weather", format="anthropic")
# {"name": "weather", "input_schema": {...}}

# Все инструменты сразу
all_schemas = tc.get_tools_schema()
```

### Pydantic V2

Полная поддержка Pydantic моделей:

```python
from pydantic import BaseModel, Field

class SearchParams(BaseModel):
    query: str = Field(..., description="Search query string")
    limit: int = Field(10, le=100, description="Max results")

@tc.tool("search")
def search(params: SearchParams) -> list:
    """Search for documents."""
    return []

# Схема автоматически включает описания и constraints
schema = tc.get_tool_schema("search")
# properties.query.description == "Search query string"
# properties.limit.maximum == 100
```

### LangChain

```python
from trustchain.integrations.langchain import to_langchain_tools

# Конвертировать все TrustChain tools в LangChain формат
lc_tools = to_langchain_tools(tc)

# Использовать с агентом
from langchain.agents import AgentExecutor
executor = AgentExecutor(agent=agent, tools=lc_tools)
```

### MCP Server (Claude Desktop)

```python
from trustchain.integrations.mcp import serve_mcp

@tc.tool("calculator")
def add(a: int, b: int) -> int:
    return a + b

# Запуск MCP сервера
serve_mcp(tc)
```

Для Claude Desktop добавьте в `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "trustchain": {
      "command": "python",
      "args": ["/path/to/your/mcp_server.py"]
    }
  }
}
```

---

## Merkle Trees

Для верификации больших документов без загрузки всего содержимого.

### Использование

```python
from trustchain.v2.merkle import MerkleTree, verify_proof

# Документ из 100 страниц
pages = [f"Page {i}: ..." for i in range(100)]

# Строим Merkle Tree
tree = MerkleTree.from_chunks(pages)
print(tree.root)  # Один хеш для всего документа

# Подписываем только root
signed = tc._signer.sign("document", {"merkle_root": tree.root})

# Позже: проверяем только страницу 42
proof = tree.get_proof(42)
is_valid = verify_proof(pages[42], proof, tree.root)
```

### Зачем это нужно?

- RAG системы: проверить источник без загрузки всех документов
- LegalTech: верификация отдельных страниц контракта
- IoT: проверка пакета данных из большого batch

---

## CloudEvents

Стандартный формат для интеграции с Kafka и другими системами:

```python
from trustchain.v2.events import TrustEvent

# Конвертировать SignedResponse в CloudEvent
event = TrustEvent.from_signed_response(
    result,
    source="/agent/my-bot/tool/weather"
)

# JSON для Kafka
json_str = event.to_json()

# Kafka headers для быстрой фильтрации
headers = event.to_kafka_headers()
```

---

## Audit Trail UI

Генерация HTML-отчетов для аудита:

```python
from trustchain.ui.explorer import ChainExplorer

# Собираем операции
chain = [step1, step2, step3, ...]

# Экспортируем в HTML
explorer = ChainExplorer(chain, tc)
explorer.export_html("audit_report.html")
```

Открывает интерактивный отчет с:
- Статистикой операций
- Визуализацией цепочки
- Статусом верификации каждого шага

---

## REST API Server

TrustChain можно запустить как HTTP сервер:

```bash
uvicorn trustchain.v2.server:app --port 8000
```

Эндпоинты:
- `POST /sign` -- подписать данные
- `POST /verify` -- проверить подпись
- `GET /health` -- статус сервера
- `GET /public-key` -- получить публичный ключ

---

## Prometheus Metrics

```python
config = TrustChainConfig(enable_metrics=True)
tc = TrustChain(config)
```

Доступные метрики:
- `trustchain_signs_total` -- количество подписей
- `trustchain_verifies_total` -- количество проверок
- `trustchain_sign_seconds` -- время подписи
- `trustchain_nonce_rejects_total` -- заблокированные replay-атаки

---

## Производительность

Результаты бенчмарков (Apple M1):

| Операция | Latency | Throughput |
|----------|---------|------------|
| Sign     | 0.11 ms | 9,102 ops/sec |
| Verify   | 0.22 ms | 4,513 ops/sec |
| Chain verify (100 items) | 28 ms | - |
| Merkle (100 pages) | 0.18 ms | 5,482 ops/sec |

Storage overhead: ~124 bytes на операцию (88 bytes подпись + 36 bytes nonce).

---

## Структура проекта

```
trustchain/
  __init__.py          # Главный экспорт
  v2/
    core.py            # TrustChain класс
    signer.py          # Подписи и SignedResponse
    config.py          # Конфигурация
    schemas.py         # OpenAI/Anthropic схемы
    nonce_storage.py   # Memory/Redis хранилище
    metrics.py         # Prometheus метрики
    tenants.py         # Multi-tenancy
    server.py          # REST API
    verifier.py        # Внешняя верификация
    merkle.py          # Merkle Trees
    events.py          # CloudEvents
  integrations/
    langchain.py       # LangChain adapter
    mcp.py             # MCP Server
  ui/
    explorer.py        # HTML отчеты
  utils/
    exceptions.py      # Ошибки
```

---

## Примеры

В директории `examples/` доступны готовые примеры:

- `mcp_claude_desktop.py` -- MCP Server для Claude Desktop
- `langchain_agent.py` -- Интеграция с LangChain
- `secure_rag.py` -- RAG с Merkle Tree верификацией
- `database_agent.py` -- SQL агент с Chain of Trust
- `api_agent.py` -- HTTP клиент с CloudEvents

---

## FAQ

**Q: Это блокчейн?**
A: Нет. Это криптографические подписи, как в HTTPS. Никакого майнинга или консенсуса.

**Q: Замедляет ли это код?**
A: Подпись занимает 0.11 ms, проверка 0.22 ms. Обычно незаметно.

**Q: Нужен ли мне Redis?**
A: Для разработки -- нет (используется in-memory storage). Для production с несколькими серверами -- да.

**Q: Работает с любым AI?**
A: Да. TrustChain подписывает результаты ваших функций, независимо от того, какой AI их вызывает.

**Q: Какие алгоритмы поддерживаются?**
A: На данный момент Ed25519 (быстрый, безопасный, 128-bit security level).

---

## Лицензия

MIT License

## Автор

Ed Cherednik

## Версия

2.1.0 (19 января 2026)
