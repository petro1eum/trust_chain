# TrustChain -- 사용자 가이드

## TrustChain이란?

TrustChain은 AI 도구 응답의 암호화 서명을 위한 Python 라이브러리입니다. 신뢰 문제를 해결합니다: AI 에이전트가 함수(도구)를 호출할 때 결과가 실제이며 환각이 아닌지 보장할 수 없습니다.

TrustChain은 모든 응답에 다음을 추가합니다:
- 암호화 서명 (Ed25519)
- 고유 논스 (재생 공격 보호)
- 타임스탬프
- 선택적: 이전 단계 링크 (신뢰 체인)

---

## 요구사항

- **Python 3.10+** (3.13 권장)
- 패키지 관리자: `uv` (권장) 또는 `pip`

---

## 설치

빠른 설치를 위해 **uv** 사용을 권장합니다:

```bash
uv pip install trustchain
```

또는 표준 pip:

```bash
pip install trustchain
```

추가 기능:

```bash
uv pip install trustchain[integrations]  # LangChain + MCP
uv pip install trustchain[ai]            # OpenAI + Anthropic + LangChain
uv pip install trustchain[mcp]           # MCP 서버만
uv pip install trustchain[redis]         # 분산 논스 저장소
uv pip install trustchain[all]           # 모두
```

---

## 빠른 시작

### 기본 사용법

```python
from trustchain import TrustChain

# TrustChain 인스턴스 생성
tc = TrustChain()

# 함수를 서명된 도구로 등록
@tc.tool("weather")
def get_weather(city: str) -> dict:
    """도시의 날씨를 가져옵니다."""
    return {"city": city, "temp": 22, "conditions": "sunny"}

# 함수 호출 -- 서명된 응답 받기
result = get_weather("서울")

# result는 SignedResponse 객체입니다
print(result.data)       # {'city': '서울', 'temp': 22, ...}
print(result.signature)  # Base64로 인코딩된 Ed25519 서명
print(result.nonce)      # 재생 보호용 UUID
```

### 서명 검증

```python
# 응답 진위 확인
is_valid = tc.verify(result)
print(is_valid)  # True

# 동일한 논스의 반복 검증 -- 오류
try:
    tc.verify(result)
except NonceReplayError:
    print("재생 공격 감지!")
```

---

## 핵심 개념

### SignedResponse

`@tc.tool()` 데코레이터로 래핑된 함수를 호출하면 원시 데이터가 아닌 `SignedResponse` 객체를 반환합니다:

| 필드 | 설명 |
|------|------|
| `data` | 함수 결과 (모든 타입) |
| `signature` | Base64 형식의 Ed25519 서명 |
| `signature_id` | 고유 서명 ID (UUID) |
| `timestamp` | 생성 Unix 타임스탬프 |
| `nonce` | 재생 보호용 고유 ID |
| `tool_id` | 도구 식별자 |
| `parent_signature` | 이전 단계 링크 (신뢰 체인) |

### 서명 작동 방식

1. 데이터의 정규 표현 생성 (JSON)
2. SHA-256으로 데이터 해시
3. Ed25519 개인 키로 해시 서명
4. Base64로 서명 인코딩

검증:
1. 정규 표현 복원
2. Base64에서 서명 디코딩
3. 공개 키로 서명 검증

### 재생 공격 보호

논스(한 번만 사용되는 숫자)는 각 응답이 한 번만 검증될 수 있음을 보장합니다.

공격 시나리오:
```
1. 해커가 "100달러 이체" 응답 가로채기
2. 해커가 100번 전송
3. 10,000달러 도난
```

TrustChain 사용 시:
```python
tc.verify(result)  # OK -- 첫 번째
tc.verify(result)  # NonceReplayError -- 논스 이미 사용됨
```

---

## 신뢰 체인 (Chain of Trust)

여러 작업을 암호화적으로 연결할 수 있습니다.

### 왜 필요한가요?

AI가 다단계 작업을 수행할 때:
1. 데이터 검색
2. 분석
3. 보고서 생성

2단계가 1단계를 기반으로 수행되었으며 조작되지 않았음을 증명해야 합니다.

### 사용법

```python
from trustchain import TrustChain

tc = TrustChain()

# 단계 1: 검색 (부모 없음)
step1 = tc._signer.sign("search", {"query": "balance", "results": [100, 200]})

# 단계 2: 분석 (단계 1 참조)
step2 = tc._signer.sign(
    "analyze", 
    {"summary": "total=300"},
    parent_signature=step1.signature
)

# 단계 3: 보고서 (단계 2 참조)
step3 = tc._signer.sign(
    "report",
    {"text": "Balance is 300"},
    parent_signature=step2.signature
)

# 전체 체인 검증
chain = [step1, step2, step3]
is_valid = tc.verify_chain(chain)
print(is_valid)  # True -- 체인 무결
```

### verify_chain이 확인하는 것:

1. 각 서명이 유효함
2. 각 `parent_signature`가 이전 단계의 `signature`와 일치
3. 체인이 끊어지지 않음

---

## 구성

### 기본 옵션

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(
    algorithm="ed25519",      # 서명 알고리즘
    enable_nonce=True,        # 재생 공격 보호
    enable_cache=True,        # 응답 캐싱
    cache_ttl=3600,           # 캐시 수명 (초)
    nonce_ttl=86400,          # 논스 수명 (초)
    key_file="keys.json",     # 키 저장 파일
)

tc = TrustChain(config)
```

### 키 로테이션

```python
old_key = tc.get_key_id()
new_key = tc.rotate_keys()

print(f"로테이션: {old_key[:16]} -> {new_key[:16]}")
public_key = tc.export_public_key()
```

> 로테이션 후 모든 이전 서명이 무효화됩니다!

### 분산 구성 (Redis)

```python
config = TrustChainConfig(
    nonce_backend="redis",
    redis_url="redis://localhost:6379/0",
    nonce_ttl=86400,
)
tc = TrustChain(config)
```

### 멀티 테넌시

```python
from trustchain import TenantManager

manager = TenantManager(
    redis_url="redis://localhost:6379",
    key_storage_dir="./keys"
)

tc_acme = manager.get_or_create("acme_corp")
tc_beta = manager.get_or_create("beta_inc")
```

---

## 통합

### OpenAI / Anthropic 스키마

```python
schema = tc.get_tool_schema("weather")
schema = tc.get_tool_schema("weather", format="anthropic")
all_schemas = tc.get_tools_schema()
```

### Pydantic V2

```python
from pydantic import BaseModel, Field

class SearchParams(BaseModel):
    query: str = Field(..., description="검색 쿼리 문자열")
    limit: int = Field(10, le=100)

@tc.tool("search")
def search(params: SearchParams) -> list:
    return []
```

### LangChain

```python
from trustchain.integrations.langchain import to_langchain_tools
lc_tools = to_langchain_tools(tc)
```

### MCP 서버 (Claude Desktop)

```python
from trustchain.integrations.mcp import serve_mcp
serve_mcp(tc)
```

---

## Merkle 트리

```python
from trustchain.v2.merkle import MerkleTree, verify_proof

pages = [f"Page {i}: ..." for i in range(100)]
tree = MerkleTree.from_chunks(pages)

proof = tree.get_proof(42)
is_valid = verify_proof(pages[42], proof, tree.root)
```

---

## CloudEvents

```python
from trustchain.v2.events import TrustEvent

event = TrustEvent.from_signed_response(result, source="/agent/bot")
json_str = event.to_json()
```

---

## 감사 UI

```python
from trustchain.ui.explorer import ChainExplorer

explorer = ChainExplorer(chain, tc)
explorer.export_html("audit_report.html")
```

---

## REST API 서버

```bash
uvicorn trustchain.v2.server:app --port 8000
```

---

## Prometheus 메트릭

```python
config = TrustChainConfig(enable_metrics=True)
tc = TrustChain(config)
```

---

## 성능

| 작업 | 지연 시간 | 처리량 |
|------|----------|--------|
| 서명 | 0.11 ms | 9,102 ops/초 |
| 검증 | 0.22 ms | 4,513 ops/초 |
| 체인 검증 (100개) | 28 ms | - |
| Merkle (100페이지) | 0.18 ms | 5,482 ops/초 |

---

## 예제

### Jupyter Notebooks

| Notebook | 설명 |
|----------|------|
| trustchain_tutorial.ipynb | 기본 튜토리얼 |
| trustchain_advanced.ipynb | 고급 |
| trustchain_pro.ipynb | 전체 API 참조 |

### Python 스크립트

- `mcp_claude_desktop.py` — MCP 서버
- `langchain_agent.py` — LangChain 통합
- `secure_rag.py` — Merkle을 사용한 RAG
- `database_agent.py` — SQL 에이전트
- `api_agent.py` — HTTP 클라이언트

---

## FAQ

**Q: 이것이 블록체인인가요?**
A: 아니요. HTTPS의 암호화 서명과 같습니다.

**Q: 코드가 느려지나요?**
A: 서명: 0.11 ms, 검증: 0.22 ms. 일반적으로 눈에 띄지 않습니다.

**Q: Redis가 필요한가요?**
A: 개발용으로는 아니요. 여러 서버가 있는 프로덕션에서는 예.

**Q: 모든 AI와 작동하나요?**
A: 예. TrustChain은 함수 결과에 서명합니다.

---

## 라이선스

MIT License

## 저자

Ed Cherednik

## 버전

2.1.0 (2026년 1월 19일)
