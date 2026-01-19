Отличная идея. Рынок действительно смещается от "просто функций" к **стандартизированным протоколам**. Если TrustChain v2 будет работать с ними "из коробки", это откроет двери в Enterprise-интеграции (Microsoft, Anthropic, LangChain).

Вот **Roadmap совместимости**, который сделает TrustChain универсальным слоем безопасности для любой современной AI-архитектуры.

---

### 1. 🌍 Главный тренд: Model Context Protocol (MCP)

Это сейчас "горячая тема" (стандарт от Anthropic, Google и др.). Идея в том, что Tools больше не привязаны к конкретному боту, а живут как отдельные **MCP Servers** (похоже на LSP в IDE).

**Как TrustChain сюда встраивается?**
TrustChain должен стать **Middleware** для MCP-сервера. Когда MCP-клиент (например, Claude Desktop или IDE) запрашивает выполнение тула, TrustChain перехватывает этот вызов, выполняет его, подписывает и возвращает результат.

**Предложение для реализации:**
Добавить поддержку MCP-враппера.

```python
# trustchain/integrations/mcp.py

# Идея: Обернуть существующий TrustChain инстанс в MCP сервер
from trustchain.v2 import TrustChain
from mcp.server import Server

tc = TrustChain()

@tc.tool("database_query")
def query_db(sql: str) -> list:
    return db.execute(sql)

# TrustChain автоматически генерирует MCP-совместимый список тулов
mcp_server = Server("secure-agent")
mcp_server.add_tools(tc.to_mcp_tools()) 

# Теперь любой MCP-клиент (Claude, Cursor и т.д.) получает 
# криптографически подписанные ответы.

```

### 2. 🦜🔗 LangChain & LlamaIndex (De facto стандарты)

Большинство разработчиков не пишут `openai.chat.completions` вручную, они используют фреймворки. Тебе нужны **адаптеры**.

#### A. LangChain Adapter

В LangChain всё наследуется от `BaseTool`. Сделай метод `.to_langchain()`, который превращает твой тул в их объект.

```python
# Как это будет выглядеть для юзера
from langchain.agents import initialize_agent

@tc.tool("search")
def search(query: str):
    return internet.search(query)

# 🪄 MAGIC: Превращаем в нативный LangChain Tool
lc_tool = search.to_langchain() 

# Теперь можно скармливать любому агенту LangChain
agent = initialize_agent([lc_tool], llm, ...)

```

#### B. LlamaIndex Adapter

У них свой класс `FunctionTool`. Логика та же.

```python
from llama_index.core.tools import FunctionTool

# Внутри TrustChain
def to_llamaindex(self):
    return FunctionTool.from_defaults(
        fn=self.original_func,
        name=self.name,
        description=self.description
    )

```

### 3. 🛡️ Pydantic V2 (Сердце всех схем)

Сейчас `OpenAI`, `Anthropic`, `FastAPI` — все перешли на Pydantic V2 для генерации JSON-схем.
Твой декоратор `@tc.tool` должен идеально понимать Pydantic-модели на входе, чтобы генерировать правильную схему для LLM.

**Сейчас:**

```python
def add(a: int, b: int)

```

**Должно поддерживаться (Native Pydantic):**

```python
from pydantic import BaseModel, Field

class SearchParams(BaseModel):
    query: str = Field(..., description="Search query")
    max_results: int = Field(5, le=10)

@tc.tool("advanced_search")
def search(params: SearchParams): 
    # TrustChain должен понять, что аргумент один, но это сложный объект,
    # и сгенерировать правильную JSON Schema для OpenAI.
    pass

```

### 4. 📝 OpenAI / Anthropic Native Schemas

Даже без фреймворков люди часто просят: "Дай мне JSON-схему этого тула, я сам передам её в API".

Добавь методы экспорта схем:

```python
# Экспорт в формат OpenAI
tools_config = [t.to_openai_schema() for t in tc.tools]

client.chat.completions.create(
    model="gpt-4",
    tools=tools_config  # Прямая совместимость
)

```

---

### Итоговый план действий (Feature List)

Я бы рекомендовал добавить в README раздел **"Integrations"** и реализовать 3 миксина:

1. **`TrustChainTool.to_langchain()`** — возвращает `langchain_core.tools.BaseTool`.
2. **`TrustChainTool.to_openai_schema()`** — возвращает dict в формате `{ "type": "function", "function": { ... } }`.
3. **`TrustChain.serve_mcp()`** — (Advance уровень) поднимает легкий MCP сервер, который экспоузит все зарегистрированные тулы.

Это превратит TrustChain из "библиотеки для подписи" в **"Security Layer for AI Ecosystem"**.

---

## 📋 Детальный TODO List

### Phase 1: OpenAI Schema Export ✅ DONE

**Срок: 1 день** → **Выполнено: 19.01.2026**

#### TODO:
- [x] Создать `trustchain/v2/schemas.py`
- [x] Реализовать `generate_function_schema(func) -> dict` — извлечение параметров из type hints
- [x] Добавить поддержку docstring → description
- [x] Добавить метод `TrustChain.get_tool_schema()` в `core.py`
- [x] Добавить метод `TrustChain.get_tools_schema()` — список всех tools в OpenAI формате
- [x] Тесты пройдены

#### Проверка:
```python
@tc.tool("weather")
def get_weather(city: str, units: str = "celsius") -> dict:
    """Get weather for a city."""
    return {"temp": 22}

schema = get_weather.to_openai_schema()
assert schema == {
    "type": "function",
    "function": {
        "name": "weather",
        "description": "Get weather for a city.",
        "parameters": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "units": {"type": "string", "default": "celsius"}
            },
            "required": ["city"]
        }
    }
}
```

---

### Phase 2: Pydantic V2 Support ✅ DONE

**Срок: 1-2 дня** → **Выполнено: 19.01.2026**

#### TODO:
- [x] Добавить опциональную зависимость `pydantic>=2.0`
- [x] Детектить Pydantic BaseModel в аргументах функции
- [x] Использовать `model.model_json_schema()` для генерации схемы
- [x] Поддержать `Field(description=...)` в описаниях параметров
- [x] Тесты пройдены

#### Проверка:
```python
from pydantic import BaseModel, Field

class SearchParams(BaseModel):
    query: str = Field(..., description="Search query")
    limit: int = Field(10, le=100)

@tc.tool("search")
def search(params: SearchParams) -> list:
    ...

schema = search.to_openai_schema()
assert schema["function"]["parameters"]["properties"]["query"]["description"] == "Search query"
assert schema["function"]["parameters"]["properties"]["limit"]["maximum"] == 100
```

---

### Phase 3: LangChain Adapter ✅ DONE

**Срок: 1 день** → **Выполнено: 19.01.2026**

#### TODO:
- [x] Создать `trustchain/integrations/langchain.py`
- [x] Реализовать `TrustChainLangChainTool(BaseTool)` — wrapper class
- [x] Добавить функции `to_langchain_tool()`, `to_langchain_tools()`
- [x] Сохранять signature в tool metadata для audit
- [x] Тесты пройдены

#### Проверка:
```python
from langchain.agents import initialize_agent

@tc.tool("calculator")
def add(a: int, b: int) -> int:
    return a + b

lc_tool = add.to_langchain()
assert lc_tool.name == "calculator"
assert lc_tool.run({"a": 2, "b": 3}) == 5  # Подпись сохраняется в metadata
```

---

### Phase 4: MCP Server ✅ DONE

**Срок: 3-5 дней** → **Выполнено: 19.01.2026**

#### TODO:
- [x] Изучить MCP SDK: `pip install mcp`
- [x] Создать `trustchain/integrations/mcp.py`
- [x] Реализовать `TrustChainMCPServer` класс
- [x] Автогенерация MCP tool definitions из `tc._tools`
- [x] Подпись результатов перед отправкой клиенту
- [x] Тесты пройдены
- [x] CLI entry point для Claude Desktop

#### Проверка:
```bash
# Запуск MCP сервера
python -m trustchain.integrations.mcp_server --port 3000

# Клиент (Claude Desktop) видит:
# - tool: "weather" с подписью
# - tool: "search" с подписью
```

---

### Phase 5: Anthropic Schema ✅ DONE

**Срок: 0.5 дня** → **Выполнено: 19.01.2026**

#### TODO:
- [x] Изучить формат Anthropic tools (использует `input_schema`)
- [x] Добавить `generate_anthropic_schema()` в `schemas.py`
- [x] Тесты пройдены

#### Проверка:
```python
schema = tool.to_anthropic_schema()
assert schema["name"] == "weather"
assert "input_schema" in schema  # Anthropic использует input_schema, не parameters
```

---

## ✅ Критерии готовности (Definition of Done)

| Phase | Готово когда... | Статус |
|-------|----------------|--------|
| 1. OpenAI Schema | `to_openai_schema()` работает, тесты проходят | ✅ |
| 2. Pydantic | `BaseModel` аргументы → корректная JSON Schema | ✅ |
| 3. LangChain | `to_langchain()` возвращает работающий `BaseTool` | ✅ |
| 4. MCP | `serve_mcp()` запускает сервер, Claude Desktop видит tools | ✅ |
| 5. Anthropic | `to_anthropic_schema()` совместим с Anthropic API | ✅ |

---

## 📊 Timeline

```
Week 1: Phase 1 + Phase 2 (OpenAI + Pydantic)
Week 2: Phase 3 (LangChain)  
Week 3: Phase 4 (MCP) — если есть время
```

---

# 🏛️ Grand Unified Architecture

**Видение:** TrustChain как **"SSL для AI-агентов"**

## Три уровня продукта

| Уровень | Для кого | Стек |
|---------|----------|------|
| **Core (v2.1)** | Инди-хакеры, пет-проекты | Python, In-memory |
| **Standard** | Стартапы, Claude/OpenAI агенты | Pydantic V2, MCP, HTTP |
| **Enterprise** | Финтех, Медтех, Корпорации | Kafka, Redis, HSM |

---

## 🔗 Phase 6: Chain of Trust ✅ DONE

**Срок: 0.5 дня** → **Выполнено: 19.01.2026**

Добавить `parent_signature` для связывания шагов в цепочку.

#### TODO:
- [x] Добавить `parent_signature: Optional[str]` в `SignedResponse`
- [x] При подписи включать `parent_signature` в хэш
- [x] Метод `verify_chain(responses: List[SignedResponse]) -> bool`
- [x] Тест цепочки из 3+ шагов

#### Проверка:
```python
# Шаг 1: Поиск
result1 = search("balance")  # signature_A

# Шаг 2: Анализ (ссылается на поиск)
result2 = analyze(result1.data, parent=result1.signature)  # signature_B

# signature_B математически доказывает, что анализ был на основе result1
assert tc.verify_chain([result1, result2]) == True
```

---

## 📦 Phase 7: CloudEvents Format ✅ DONE

**Срок: 1 день** → **Выполнено: 19.01.2026**

Стандартный формат для совместимости с Kafka, MCP, любыми системами.

#### TODO:
- [x] Создать `trustchain/v2/events.py`
- [x] `TrustEvent` dataclass — CloudEvents совместимый
- [x] Метод `TrustEvent.from_signed_response()` 
- [x] Метод `TrustEvent.to_kafka_headers()` для быстрой фильтрации

#### Формат:
```python
class TrustEvent(BaseModel):
    specversion: str = "1.0"
    type: str = "ai.tool.response.v1"
    source: str  # "/agent/bot/tool/weather"
    id: str  # Nonce
    time: datetime
    data: dict  # Ответ тула
    # TrustChain extensions
    signature: str
    public_key_id: str
    chain_id: Optional[str]
```

---

## 🌳 Phase 8: Merkle Trees для RAG ✅ DONE

**Срок: 2-3 дня** → **Выполнено: 19.01.2026**

Частичная верификация больших документов.

#### TODO:
- [x] Создать `trustchain/v2/merkle.py`
- [x] `MerkleTree.from_chunks(List[str]) -> MerkleTree`
- [x] `MerkleTree.get_proof(chunk_index) -> MerkleProof`
- [x] `verify_proof(chunk, proof, root) -> bool`
- [x] Тест 100 страниц, 8 уровней, 7 siblings для proof

#### Use Case:
```python
# PDF 100 страниц — подписывается только Merkle Root
doc = load_pdf("contract.pdf")
tree = MerkleTree.from_chunks(doc.pages)
signed = tc.sign_merkle_root("legal_doc", tree.root)

# Клиент проверяет только нужную страницу
page_42 = doc.pages[42]
proof = tree.get_proof(42)
assert verify_proof(page_42, proof, signed.data["merkle_root"])
```

---

## 🎯 Killer Features Summary

| Feature | Value | Status |
|---------|-------|--------|
| Chain of Trust | Audit trail, невозможно подменить шаг | ✅ DONE |
| CloudEvents | Kafka/MCP/любая система | ✅ DONE |
| Merkle Trees | RAG, большие документы, LegalTech | ✅ DONE |

---

## 🚀 Финальное видение

```
v2.0 (Core)     = "OpenSSL" — базовая криптография
MCP Integration = "HTTPS" — стандартный транспорт  
Enterprise      = "Certificate Authority" — инфраструктура доверия
```

**TrustChain = SSL для AI-агентов**

---

# 📈 Phase 9-12: Go-To-Market

## Phase 9: Ready Recipes -- DONE

**Срок: 1 неделя** -> **Выполнено: 19.01.2026**

Готовые примеры для быстрого старта.

#### TODO:
- [x] Создать `examples/` директорию
- [x] `examples/secure_rag.py` — RAG с верификацией источников
- [x] `examples/database_agent.py` — SQL-агент с audit trail
- [x] `examples/api_agent.py` — HTTP клиент с подписями
- [x] `examples/mcp_claude_desktop.py` — интеграция с Claude Desktop
- [x] `examples/langchain_agent.py` — полный пример с LangChain

#### Код:
```python
# examples/secure_rag.py
from trustchain.recipes import SecureRAG

rag = SecureRAG(
    vector_store=pinecone_index,
    compliance_mode="SOC2"  # Автоматически логирует метрики
)

# Каждый документ подписан, каждый ответ верифицируем
answer = rag.query("Какие условия контракта?")
print(answer.signature)  # Proof of source
```

---

## Phase 10: Audit Trail UI -- DONE

**Срок: 2 недели** -> **Выполнено: 19.01.2026**

Визуализация для Compliance officers.

#### TODO:
- [x] `trustchain/ui/explorer.py` — HTML export цепочки
- [x] Интерактивный отчет со статистикой
- [x] Верификация каждого шага
- [x] Chain of Trust визуализация
- [ ] Export в PDF (будущее)

#### Код:
```python
# После 100 операций агента
tc.export_chain_graph("audit_report.html")
# → Открывается в браузере с фильтрами, поиском, timeline
```

---

## Phase 11: Benchmarks -- DONE

**Срок: 3 дня** -> **Выполнено: 19.01.2026**

Конкретные цифры для маркетинга.

#### TODO:
- [x] `benchmarks/run_benchmarks.py` — все бенчмарки
- [x] Sign/Verify latency
- [x] Throughput ops/sec
- [x] Storage overhead
- [x] Chain verify performance

#### Результаты:
```
Sign latency:     0.11 ms (target: <2ms)
Verify latency:   0.22 ms (target: <2ms)
Throughput:       9,102 ops/sec (target: 10k+)
Storage overhead: 124 bytes/op (target: ~200 bytes)
```

---

## 🎯 Phase 12: Multi-Channel Positioning (Приоритет: 💚 P2)

**Стратегия:** Атаковать по ВСЕМ направлениям одновременно.

### Канал A: Developers (GitHub, Dev.to, HackerNews)
**Message:** "Drop-in MCP middleware for cryptographic verification"
```
- GitHub README с badges и quick start
- Dev.to статья "Why AI agents need signatures"
- HackerNews Show HN пост
```

### Канал B: Enterprise (LinkedIn, конференции)
**Message:** "Complete audit trail for AI — SOC2/HIPAA ready"
```
- LinkedIn посты про compliance
- Case study с реальной компанией
- White paper про AI governance
```

### Канал C: AI Community (Twitter/X, Discord)
**Message:** "The security layer for Claude/GPT tools"
```
- Twitter thread про MCP security
- Discord боты с примерами
- YouTube tutorial
```

### Канал D: Anthropic/OpenAI Ecosystem
**Message:** "Official security middleware for MCP"
```
- Попасть в MCP awesome list
- Integration с Anthropic docs
- Partnership discussions
```

---

## 📊 Метрики успеха (Q1 2026)

| Метрика | Цель | Текущее |
|---------|------|---------|
| GitHub Stars | 500+ | 0 |
| pip installs/month | 1000+ | 0 |
| Production deployments | 5+ | 0 |
| Enterprise inquiries | 10+ | 0 |
| MCP Server downloads | 100+ | 0 |

---

## 📝 Content Plan

| Неделя | Контент | Канал |
|--------|---------|-------|
| 1 | "Why AI agents need cryptographic signatures" | Dev.to, HN |
| 2 | "Building SOC2-compliant AI agents with TrustChain" | LinkedIn |
| 3 | "MCP Security: Protecting Claude Desktop Tools" | Twitter thread |
| 4 | Video tutorial: "TrustChain in 10 minutes" | YouTube |

---

## 🔥 Immediate Next Steps

1. **[ ] Создать `examples/` с 5 recipes**
2. **[ ] Написать первую статью**
3. **[ ] Опубликовать на GitHub**
4. **[ ] Submit to MCP awesome list**
5. **[ ] Первый Show HN пост**

---

**Версия:** 2.1.0  
**Дата:** 19 января 2026  
**Статус:** Все 12 core phases ✅ COMPLETE

---

# 🔮 Phase 13-15: Strategic Expansion

## Phase 13: Policy Layer (Q1 2026)

**Status:** IN PROGRESS

Runtime policy enforcement for signed tool calls.

#### Goals:
- YAML-based policy definitions
- Deny/Allow/Require parent rules
- Integration with Chain of Trust

#### Policy Format:
```yaml
policies:
  - name: no_pii_without_consent
    if:
      tool: database_query
      output.contains: ["ssn", "passport"]
    then:
      require:
        - parent_tool: "user_consent"
        - signature_valid: true

  - name: require_approval_for_payments
    if:
      tool: payment
      args.amount: { ">": 10000 }
    then:
      require:
        - parent_tool: "manager_approval"
```

#### Use Cases:
- AI Governance Engine
- SOC2/ISO/AI Act compliance
- Runtime enforcement (not just audit)

---

## Phase 14: Execution Graph (Q2 2026)

**Status:** PLANNED

Transform Chain of Trust into full DAG analysis.

#### Goals:
- DAG representation of agent execution
- Fork detection (where agent "went wrong")
- Replay attack pattern detection
- Forensic analysis for incidents

#### Data Model:
```
Execution Graph:
- nodes: SignedResponse[]
- edges: parent_signature links
- invariants: 
  - no unsigned edges
  - temporal ordering
  - single root per session
```

#### Features:
```python
from trustchain.v2.graph import ExecutionGraph

graph = ExecutionGraph.from_chain(responses)

# Detect anomalies
forks = graph.detect_forks()      # Agent branched unexpectedly
replays = graph.detect_replays()  # Same tool called with same args
orphans = graph.detect_orphans()  # Responses without valid parent

# Visualize
graph.export_mermaid("execution.md")
graph.export_graphviz("execution.dot")
```

---

## Phase 15: MCP Security Reference (Q2 2026)

**Status:** IN PROGRESS

Position TrustChain as **the** reference MCP security implementation.

#### Deliverables:
- [x] `docs/MCP_SECURITY_SPEC.md` - RFC-style specification
- [ ] Submit to MCP community as standard
- [ ] Integration with Claude Desktop docs
- [ ] Partnership discussions with Anthropic

#### Key Message:
> "If you run MCP in production, you MUST have cryptographic verification."

#### Spec Sections:
1. Threat model for MCP
2. MUST/SHOULD/MAY requirements
3. Signed response format
4. Key management
5. Replay protection
6. Compliance mapping (SOC2, HIPAA, AI Act)

See: [MCP Security Specification](docs/MCP_SECURITY_SPEC.md)

---

## 📊 Updated Timeline

| Phase | Description | Status | ETA |
|-------|-------------|--------|-----|
| 1-12 | Core Features | ✅ COMPLETE | Done |
| 13 | Policy Layer | 🟡 IN PROGRESS | Q1 2026 |
| 14 | Execution Graph | ⬜ PLANNED | Q2 2026 |
| 15 | MCP Security Ref | 🟡 IN PROGRESS | Q2 2026 |

---

## 🎯 Strategic Position

```
2025: TrustChain = Library
2026: TrustChain = Infrastructure Layer
2027: TrustChain = Industry Standard
```

**Winner takes middleware.** 
The first library to become the default MCP security layer will be embedded in every enterprise AI stack.