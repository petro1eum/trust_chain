# Domain Surfaces and Trust Boundaries

Документ фиксирует назначение доменов и границы доверия в экосистеме TrustChain.

> **Канонический источник** по ролям, плоскостям доступа (P0–P5) и матрице use cases — в репозитории TrustChain_Platform: `docs/ROLES_AND_TRUST_BOUNDARIES.md` и `docs/USE_CASES_AND_SURFACE_MAP.md`. Этот OSS-документ описывает только назначение доменов и должен ему не противоречить.

## Назначение доменов

- `market.trust-chain.ai` — коммерческая поверхность (маркетинг, тарифы, конверсия).
- `panel.trust-chain.ai` — поверхность интеграции и активации (онбординг).
- `trust-chain.ai` — рабочая поверхность агента (runtime UX).
- `app.trust-chain.ai` — административная control plane.
- `keys.trust-chain.ai` — публичный trust-портал для независимой офлайн-верификации.

## Trust boundary

- **Public plane**: `market`, `keys`.
- **Onboarding plane**: `panel`.
- **Runtime plane**: `trust-chain.ai`.
- **Admin plane**: `app`.

## Роль `keys.trust-chain.ai`

`keys` — не checkout и не admin UI. Это витрина доверия:

- объяснение trust-модели;
- доступ к публичным артефактам верификации;
- ссылки на API для программного получения сертификатов и CRL.

## Публичные endpoint'ы для верификаторов

- `GET /api/pub/root-ca`
- `GET /api/pub/ca`
- `GET /api/pub/crl`
- `GET /api/pub/agents/{agent_id}/cert`
- `POST /api/pub/verify` — опциональная онлайн-проверка подписи (доверие к ответу сервера; офлайн-путь строже). Полная проверка `.tcreceipt` — офлайн через `tc-verify`.

## Обязательные навигационные связи

- `market -> panel`
- `market -> keys`
- `panel -> trust-chain.ai`
- `keys -> panel`
- `keys -> market`

## Антипаттерны

- Пускать холодный трафик сразу в `app` (control plane).
- Путать публичную trust-плоскость с админской плоскостью.
- Смешивать коммерческий onboarding и низкоуровневые admin-операции на одной стартовой странице.
