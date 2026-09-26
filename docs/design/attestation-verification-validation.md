# Приёмка реорганизации проверок и лога аттестации

Дата: 24.09.2026. Pipeline revision: **2**. План A–F реализован.

## Реализованная цепочка

```text
endorsements → snp_signature → vcek_correspondence → platform_policy
→ hcl_key → quote_signature → quote_binding → quoted_pcrs → reference
→ ima_reference → boot_aggregate → pcr10
```

Цепочка ARK → ASK → VCEK проверяется до использования VCEK. Подписанные поля SNP
оцениваются после подписи. Тип leaf-сертификата проверяется после подписи quote;
ошибка сертификата сохраняет stage `certificate`. Все binding flags подтверждаются
одним transcript; частичные artifacts доступны только после своих зависимостей.
`coverage.ima_entries` становится ненулевым после всех measurement checks.

Ядро остаётся чистым verifier. Типы результата вынесены в `lib/src/result.rs`,
`verify_snapshot` collector переиспользует общие quote helpers. Result/archive v2
и binding v1 сохранены; runtime metadata вынесены из результата.

Терминал проходит по фактическим checks, печатает все IMA entries перед итогом
`ima_reference`; при раннем отказе список явно помечен unverified. JSON/DER blobs
заменены контекстом этапов и короткими fingerprints. Только caller events имеют
реальное время. Цвет успешных статусов — ANSI 32. Финальная сводка разделяет
Evidence и Application. Реальный пример всех 47 entries — в
`confidential-ai-example/example-output.md`.

Caller хранит одноразовый live run с monotonic deadline и связью inputs/result.
Deadline проверяется после rendering, при TLS/identity admission и перед чтением
credentials. Collection и verification измеряются отдельно.

## Выполненные проверки

| Проверка | Результат |
|---|---|
| Rust core | 13 tests passed: signature/binding/PCR, ordered IMA, boot aggregate, оба режима PCR 10 |
| Collector | 7 tests passed; сервер собран с общими snapshot helpers |
| Native transport | 2 Rust tests passed; Python reconnect test отвергает смену leaf до application bytes |
| Python binding в рабочей `.venv` | 6 tests passed; API boundaries, metadata и result schema |
| Python caller | 28 tests passed: порядок вывода, 300 entries при раннем отказе, partial AK, controls, runtime mismatch, deadline, credential gate |
| Настоящее сохранённое hardware evidence | 28 replay cases passed; контроль stage, partial artifacts, flags и coverage |
| Python / CLI / WASM | 7 одинаковых результатов на одних bytes/context, включая IMA/PCR10 mismatch |
| Chromium / Firefox | Worker parity прошёл; у WASM нет network/clock/RNG imports |
| Установленное MV3 расширение Chromium | Worker/CSP/replay прошли; смешанные JS/WASM и неверная source identity отвергнуты |
| Firefox / Safari packaging | Пакеты собраны; Safari runtime здесь не запускался |
| Dependency guard | Native transport/clock/network/RNG зависимости отсутствуют в portable runtime graph |
| Нормальный `make dev-chat` | Обнаружил изменившиеся source fingerprints при том же 0.4.0, пересобрал/переустановил wheels, запустил новый Python process |
| Container runtime | Проверил caller/native bytes по embedded manifest без checkout |
| Реальные live archives | 4 records из `.venv`/container прошли result/archive schemas и сверку runtime sidecar с финальными artifacts |

Replay выполнен на историческом evidence с явно заданным временем 1790178808.
30 локальных прогонов: p95 **20.12 ms**, включая Python serialization,
без collection/network. Это не end-to-end latency и не live admission.

## Изолированная live-приёмка

Время: 2026-09-24T11:54:37.260336+00:00 — 2026-09-24T11:54:53.942410+00:00.
Использованы штатная `/mnt/confidential-ai-example/.venv`, собранный container,
настоящий TPM collector и AMD-endorsed SNP evidence. HTTP/TLS endpoints находились
на отдельных локальных портах. Downstream — синтетический OpenAI-compatible
responder с тестовыми credentials; проверка inference не выполнялась.

- `.venv`: match — VERIFIED/ADMITTED, один synthetic application request;
  mismatch — POLICY_MISMATCH/DENIED, ноль application requests.
- Container: такие же match/mismatch решения и количество запросов.
- Другой origin с тем же сертификатом, неверный TLS hostname и изменившаяся
  service identity отвергнуты; application requests не отправлены.
- 18 запросов discovery/report, **0** запросов с credentials.
- Match: все 12 stages пройдены, 47 подтверждённых entries.
- Mismatch: отказ на `ima_reference`, coverage 0, последующие stages отсутствуют.
- Staging listeners завершены harness после проверки.

## Идентичность финальных сборок

Оба Python packages: 0.4.0; pipeline revision 2. Rust 1.98.0, native release target
`x86_64-unknown-linux-gnu`; WASM release target `wasm32-unknown-unknown`.
Core source hash совпадает в Python, CLI и WASM. Wrapper hashes, target, features,
profile и flags доступны в `build_info` и manifest. Источники включают dirty edits;
Git HEAD не используется как единственный идентификатор.

| Artifact | SHA-256 / image ID |
|---|---|
| confai-transport wheel | `f4c5641a70ca4b4f9ccd40b914290fc0f98365a52c69dd564d3cefb20f4798c0` |
| confai-transport native binary | `20368662ecb2959528558c564f87e84c49bb8659667545592bb18968a50d2704` |
| confido-verifier wheel | `bcdf09dd7ac08ff95c59c30ea48bcba2f8e6710d62f4f207c1bb20a811cd1591` |
| confido-verifier native binary | `5b1be30271d81deb656565e80c984b68a4ff91b839760990fc57bd4344c6111e` |
| Rust core source | `526ab31e0c5ad9c539a8d92d238776f62546b41dbfdb1ed2b6d3ecf400551b21` |
| Python caller source | `e6b098edc4cfad170b8e1dc93d4620514c9e7c6a271b3d449439d04ca89e7748` |
| WASM binary | `599a133845bbe68e578a2c60efe20822930dcdc2612ef43428f7a3f0ff72509e` |
| Container image | `sha256:216257eb53d21df07be01d67bb97946f8701f81d10924c6774630d32087a832b` |

Локальные полные records:

- `/mnt/confidential-ai-example/build/runtime.json`
- `/mnt/confidential-ai-example/build-manifest.json`
- `/mnt/confido/extension/dist/{chromium,firefox,safari}/runtime-manifest.json`
- `/tmp/confido-flow-v2-replay.json`
- `/tmp/confido-flow-v2-stage/acceptance.json`
- `/tmp/confido-flow-v2-stage.log`
- `/tmp/confido-flow-v2-dev-chat.log`

Flint и sidecar не потребляют stages и для этой реорганизации дополнительных
изменений не требуют. Рабочие изменения находятся в текущих ветках
`revision/attestation-update`; новые commits этой реализацией не создавались.
