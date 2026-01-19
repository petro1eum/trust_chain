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

## 신뢰 체인

여러 작업을 암호화적으로 연결할 수 있습니다.

### 왜 필요한가요?

AI가 다단계 작업을 수행할 때:
1. 데이터 검색
2. 분석
3. 보고서 생성

2단계가 1단계를 기반으로 수행되었으며 조작되지 않았음을 증명해야 합니다.

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
```

> 로테이션 후 모든 이전 서명이 무효화됩니다!

---

## 성능

벤치마크 결과 (Apple M1):

| 작업 | 지연 시간 | 처리량 |
|------|----------|--------|
| 서명 | 0.11 ms | 9,102 ops/초 |
| 검증 | 0.22 ms | 4,513 ops/초 |

---

## 라이선스

MIT

## 저자

Ed Cherednik

## 버전

2.1.0
