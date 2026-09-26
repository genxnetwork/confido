# Confido 0.4 — реализация и проверка

Реализованы изменения в Confido, Confidential AI Example, GA4GH Service Info
Sidecar и Flint. Подробные API и команды — в [migration guide](../migration-0.4.md).

## Архитектура

- `confido` принимает только bytes, policy, expected nonce и evaluation time.
  HTTP, TPM collection, TLS, credentials, clocks и admission вынесены к callers.
- Python `confido_verifier` и WASM вызывают одно portable Rust ядро. Normal
  dependency graphs не содержат OpenSSL, TPM, reqwest, Tokio или browser APIs.
- App-owned `_confai_transport` проверяет точный DER, hostname и validity; TLS
  resumption отключён, чтобы каждое новое соединение проходило peer verification.
- Wire v1 сохранён. Policy/result/archive/application-decision используют v2.
- Extension хранит WASM локально и выполняет проверку в Worker. Пользователь
  выбирает policy; архивы переоцениваются и отображаются как historical replay.

## Выполненные проверки

| Проверка | Наблюдаемый результат |
|---|---|
| Rust verifier | 11 tests passed: quote binding, signed PCR mapping, IMA/PCR10, malformed HCL, chain signature/validity/CA/path-length |
| Rust collector | 6 tests passed; wire binding v1 сохранён |
| App transport Rust | 2 tests passed: certificate/hostname/expiry и origin scope |
| Installed Python verifier | 5 tests passed: explicit context, input limits, no old transport API, v2 result schema |
| Python app | 11 tests passed: decline/failure credential gates, SDK transport, KDS retries/cache, policy path, реальный loopback TLS reconnect/rotation |
| Hardware archive replay | 21 cases passed, включая SNP/HCL/quote/PCR/IMA/reference/challenge/validity mutations |
| CLI | v1 → v2 migration и replay; результат идентичен Python на тех же bytes/context; схемы валидны |
| Chromium 153.0.8010.12 / Firefox 155.0 | По 5 идентичных Python/WASM результатов, включая реальный hardware archive и отрицательные варианты |
| Chromium установленное MV3 extension | Worker, локальный archive UI и строгий CSP прошли; нет unsafe-eval |
| Chromium live demo | match → verified; mismatch → policy_mismatch; локальная WASM-проверка, штатный HTTPS, без credentials/native host |
| Sidecar | `go test ./...` passed; wire advertisement fixture и отсутствие verification/admission claims |
| GA4GH contract | Frozen v1 schema + extension прошли; четыре некорректные мутации отклонены |
| Native + container hardware staging | Живой TPM collector; match отправил 1 synthetic chat request, mismatch 0; cross-origin/hostname/metadata failures blocked |
| Credential isolation | В финальном staging 0 credential-bearing discovery/report requests |
| Packaging | Оба wheels установлены с SHA-256 provenance; локальный container собран и прошёл pair acceptance |
| Deployment templates | Canonical Flint Nginx равен обоим Confido mirrors; shell syntax и diff whitespace checks прошли |

Live browser harness использует временную копию manifest с заранее выданными
теми же четырьмя optional hosts. Production manifest сохраняет optional permissions;
интерактивный permission dialog не является покрытой этим тестом проверкой.
Новые публичные permissions/маршруты и live deployment настройки не добавлялись.

Hardware inputs и private keys остаются в приватных `/tmp` staging directories.
В репозиторий сохраняются только результаты тестов и хеши build artifacts в
[manifest](evidence-verifier-0.4-manifest.json). Downstream в staging синтетический;
результаты не подтверждают фактическую внешнюю inference.

В последнем отдельном native replay benchmark: 30 samples, p95 около 2.9 ms,
включая caller serialization и Rust checks, без сети. Это измерение этой VM,
а не обещание производительности браузеров или других устройств.

## Границы подтверждённой поддержки

- Firefox проверен как реальный engine/Worker; установка подписанного add-on и
  live Firefox delivery ещё не проверены.
- Safari adapter сгенерирован; конвертация Xcode, подпись и acceptance на macOS
  остаются необходимыми. Linux/WebKit результаты не заменяют Safari acceptance.
- Public CA provisioning и синхронная production certificate rotation не
  выполнялись. Flint configure теперь проверяет validity, SAN и key correspondence;
  реальная TLS leaf substitution проверена изолированным тестом приложения.
- Verifier не устанавливает соответствие evidence наблюдаемому browser TLS peer,
  не реализует session binding/relay resistance, не выдаёт application admission.
- Fixed AMD chain validation не является универсальным PKIX builder. Automated
  revocation/advisory lookup, application/model/GPU appraisal остаются вне профиля.

Команды для воспроизведения сохранены в README, extension README и scripts.
Существующий `server/run.sh` с логикой остановки прежнего collector сохранён.
Исторические отчёты 0.3 в `docs/revision/` не переписывались.
