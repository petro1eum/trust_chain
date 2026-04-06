# Domain Surfaces and Trust Boundaries

Документ фиксирует назначение доменов и границы доверия в экосистеме TrustChain.

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
