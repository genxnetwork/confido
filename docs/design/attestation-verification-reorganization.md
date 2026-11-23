# План реорганизации проверок и лога аттестации

Дата: 24.09.2026. Статус: реализовано и проверено. Итоги — [отчёт приёмки](attestation-verification-validation.md).
Основание: текущие исходники Confido/Confidential AI Example и предоставленный лог от 11:02:34 UTC.

Цель: показать фактическую цепочку проверок и данные каждого этапа в понятном порядке; обеспечить запуск той сборки verifier, которой соответствует приложение.

## 1. Что было установлено по коду до реализации

| Место | Текущее поведение | Требуемое изменение |
|---|---|---|
| `confidential-ai-example/.venv` | Установленный native verifier содержит старый текст `endorsements` и не содержит `vcek_correspondence`, хотя версия пакета — `0.4.0` | Проверять идентичность сборки и совместимость этапов, обновлять реальное окружение запуска |
| `confidential-ai-example/Makefile` | `dev-chat` запускает Python без проверки актуальности native wheel | Перед запуском проверять исходники → wheel → установленную библиотеку |
| `scripts/dev_info.py` в приложении | Сравнивает provenance установленного wheel с `build/wheels`; оба могут быть одинаково устаревшими | Дополнить проверкой fingerprint исходников и реально установленного binary |
| `confido/lib/src/verify.rs` | Порядок SNP исправлен в исходниках; reported/committed TCB проверяется под именем `snp_signature` | Оставить в `snp_signature` криптографическую подпись; согласованность TCB отнести к проверкам подписанных полей |
| `confido/lib/src/formats.rs` | `quote()` объединяет signature, формат TPM, binding и PCR; `verify_snapshot()` повторно разбирает HCL | Разделить внутренние проверки, переиспользовать разобранный AK в полном verifier |
| `confido/lib/src/verify.rs`, `reference.rs` | Один этап `measurements` скрывает сравнение IMA, boot aggregate и PCR 10; подробности найденных различий отбрасываются | Выделить этапы и сохранить полезную диагностику отказа |
| `confidential-ai-example/demo/collection.py` | Строка с обещанным порядком захардкожена; все `checks` печатаются после `verify()`; общее время включает печать | Формировать вывод по фактическому результату, измерять collection и verify отдельно |
| `confidential-ai-example/demo/attestation_log.py` | Сначала все `PASSED`, затем все модули, SNP/HCL/quote и fingerprints; Python ещё раз сравнивает IMA с reference | Распределить данные по этапам, использовать решения Rust; убрать повторное сравнение из formatter |
| `confidential-ai-example/confai-promter.py` | Проверка совместимости ограничена `__version__`; итог evidence и решение приложения представлены раздельно, но краткая сводка содержит только evidence | Проверять контракт runtime до discovery; завершать вывод понятным итогом evidence и admission |

В представленном логе 47 записей IMA: boot aggregate и 46 модулей. Все записи уже выводятся; проблема в их месте и связи с результатом проверки.

## 2. Целевая последовательность

Ограничения размера, разбор envelope и проверка поддерживаемого профиля предшествуют криптографии. Они не подтверждают доверие к полям report. Получение report/KDS/reference относится к caller и показывается как сбор входов.

| Порядок | Stage в результате | Смысл и данные рядом с этапом |
|---|---|---|
| 1 | `endorsements` | Закреплённый ARK, цепочка ARK → ASK → VCEK, ограничения и validity. Fingerprint VCEK |
| 2 | `snp_signature` | Подпись SNP через доверенный VCEK. Компактный идентификатор SNP/HCL payload |
| 3 | `vcek_correspondence` | Подписанные product/chip/TCB соответствуют VCEK; reported/committed TCB удовлетворяют текущему требованию профиля |
| 4 | `platform_policy` | Launch measurement, TCB floor, VMPL, debug/migration; рядом подтверждённые значения |
| 5 | `hcl_key` | HCL hash связан с `report_data`; получен AK. Fingerprint AK |
| 6 | `quote_signature` | AK проверяет подпись TPM quote; проверен поддерживаемый формат подписанного сообщения |
| 7 | `quote_binding` | После проверки подписи разбирается включённый leaf-сертификат и проверяется единый transcript nonce/certificate/IMA |
| 8 | `quoted_pcrs` | Signed banks/selection/positions и digest соответствуют переданным PCR. Значение PCR 10 |
| 9 | `reference` | Точные bytes reference соответствуют закреплённому SHA-256. Reference ID и fingerprint |
| 10 | `ima_reference` | Совпадают количество, порядок и содержимое IMA entries. Все записи выводятся внутри этого блока перед его итогом |
| 11 | `boot_aggregate` | Boot aggregate согласуется с подтверждёнными PCR для выбранного алгоритма |
| 12 | `pcr10` | Проверен PCR 10; явно указан режим `enrolled_sha256` либо `template_digest_replay` |
| 13 | Финальный result | `verified` появляется только после всех обязательных проверок |

Формат/тип leaf-сертификата может по-прежнему давать отказ `certificate`. Его разбор должен находиться после SNP/HCL и подписи quote; криптографическая проверка quote не зависит от DER этого сертификата.

`quote_binding` проверяет один SHA-256 transcript. Совпадение nonce, сертификата и IMA нельзя объявлять тремя независимыми успешными проверками, если общий transcript не совпал. Wire v1 и сериализация IMA для binding сохраняются.

После verifier приложение выполняет проверку реального HTTPS peer, identity сервиса и собственного admission. Эти результаты не добавляются в `VerificationResult` как утверждения библиотеки. Ожидание nonce и допустимый срок использования результата контролирует caller.

## 3. Контракт результата и организация ядра

Изменять `verify.rs`, `formats.rs`, `reference.rs` небольшими этапами, переиспользуя существующие криптографические функции.

- Внутри Rust определить идентификаторы этапов и типизированные результаты вспомогательных проверок. `verify_inner()` становится явной последовательностью вызовов и записи `Check`.
- Разделить quote на проверку подписи/декодирование подписанного сообщения, проверку transcript и проверку PCR. Передавать разобранные AK и quote между шагами.
- Сохранить публичный `verify_snapshot()` как композицию общих helpers: его вызывает `server/src/main.rs` для локальной проверки snapshot. Он не должен незаметно превратиться в полный evidence verifier.
- Разделить сравнение IMA, boot aggregate и PCR 10. Ошибка сравнения должна содержать индекс, имя и конкретное различие; число подробностей ограничивается, а все входные entries остаются в архиве и списке.
- `snp_signature` сообщает только о подписи. Для несогласованных reported/committed TCB использовать отдельную причину `snp_tcb_inconsistent` со статусом `invalid_evidence` на этапе `vcek_correspondence`.
- При декомпозиции quote и measurements сохранять существующие верхнеуровневые reason codes (`quote_binding_invalid`, `measurement_mismatch`); точный отказ определяется новым stage и detail. Единственное запланированное исправление причины — TCB, указанное выше. Новые коды вводить только с явным обновлением contract/mutation cases.
- Доступные проверенные claims/artifacts заполнять после своих зависимостей: platform после signature/correspondence/policy, AK после HCL, certificate binding после подписанного quote/transcript. Admission всегда требует итоговый `status == verified`.
- `coverage` должна описывать подтверждённое покрытие. `coverage.ima_entries` заполняется после успешных `ima_reference`, `boot_aggregate` и `pcr10`; до этого полученное количество показывается как observed. Наличие `pcr10_method` указывает способ проверки, а её успех определяется только соответствующим `Check`.
- Раннее заполнение частичных `verified_artifacts` требует обновления formatter: сейчас при любом непустом объекте он одновременно обращается к certificate и AK. Читать каждое поле независимо; после успешного HCL и отказа quote можно показать подтверждённый AK, не заявляя certificate binding. Аналогично наличие подписанных platform claims не означает успешную platform policy.

Форма `VerificationResult` и `Check {stage, status, reason, detail}` достаточна: schema v2 уже допускает строковые stage. Для этого изменения не нужны новые поля или result v3. `quote` и `measurements` заменяются перечисленными детальными stage; новый набор фиксируется как `pipeline_revision = 2` в metadata runtime. Отсутствие этого marker считается legacy runtime. Новый caller требует revision 2; сохранённый старый результат можно показать в legacy-режиме, а новый verdict получить повторным `verify` старых inputs. Потребители и metadata переходят на revision 2 вместе с декомпозицией, а не заранее.

Formatter не разбирает текст `detail` для определения успеха и не выполняет собственное сравнение измерений. Идентификаторы этапов управляют размещением блока, `status/reason` — результатом, `detail` — объяснением от Rust.

Встроенная копия result schema находится также в `schemas/verification-archive-v2.json`. Изменения ограничений/schema examples должны синхронно учитываться там. Старые архивы остаются читаемыми: их сохранённые крупные этапы отображаются как legacy, а подробные новые этапы появляются только после повторного `verify` по исходным bytes/context.

## 4. Реорганизация отображения

В `demo/attestation_log.py` разделить ответственность существующих функций:

- `log()` — события caller с реальным временем и оформлением.
- Небольшие renderers — контекст конкретного этапа: AMD/SNP, AK, quote/binding, PCR, reference, IMA.
- `describe_verification()` — проход по возвращённым `checks` в их фактическом порядке и вызов соответствующего renderer.
- Renderer списка IMA — вывод каждой entry в исходном порядке. Только форматирование исходных данных, без повторной security-проверки.

`describe_report()` и `describe_reference()` больше не печатают весь отчёт после всех проверок. Их форматирующие части распределяются по этапам. Удалить callback `show_received_evidence`, который сейчас выполняется после полного обхода `checks`.

Правила вывода:

1. События collection показываются сразу: nonce создан/отправляется, report получен, endorsements/reference загружены. Загруженные bytes ещё не обозначаются проверенными.
2. После возврата `verify()` показывается упорядоченный блок результатов. Не обозначать его как поток реальных мгновений исполнения каждой криптографической проверки: в ядре нет clocks и logging callbacks. У блока есть evaluation time, у отдельных строк результата нет выдуманных timestamps/durations.
3. Идентификаторы и hashes располагаются возле своих этапов. Один fingerprint не повторяется в нескольких местах. Основной fingerprint сертификата — SHA-256 DER; PEM при необходимости явно помечается как fingerprint представления.
4. Все модули — по одной компактной строке, без timestamp, с индексом, именем и сокращённым hash. Полные значения сохраняются в raw archive. Boot aggregate выделяется как отдельная запись; количество модулей не включает его.
5. В успешной цепочке список размещается перед итоговой строкой `ima_reference`. Нейтральные строки списка сами по себе не означают `PASSED`; подтверждение даёт результат Rust. При отказе до IMA список всё равно показывается один раз в блоке received/unverified после фактического отказа.
6. При несовпадении IMA выводится полученный полный список и диагностика различий от Rust. Последующие криптографические/measurement stages не изображаются выполненными. Неизвестный stage отображается нейтрально по его фактическому status и detail.
7. PCR 10 выводится с методом проверки из `coverage.pcr10_method`. Закреплённое значение не описывается как replay.
8. Спокойный ANSI green 32 — успешные статусы; обычный текст — основной вывод; тёмно-серый — номера/служебные детали; red — отказ. Сохранить `CONFIDO_COLOR` и escape control characters.
9. Короткая итоговая сводка — после transport/admission или после отказа. В ней отдельно указаны evidence result и решение приложения; полный список проверок второй раз не печатается.

Пример формы успешного вывода (иллюстрация, не результат выполненной проверки):

```text
[11:02:34] Nonce generated: 32 bytes
[11:02:34] POST /tee-report: sending nonce in JSON body ...
[11:02:36] Inputs collected

VERIFICATION RESULTS  24.09.2026 11:02:36 UTC
  PASSED  AMD certificate chain
  PASSED  SNP report signature
  PASSED  VCEK correspondence and TCB consistency
  PASSED  Platform policy
  PASSED  HCL → AK                 AK SHA-256 ...
  PASSED  Quote signature
  PASSED  Quote nonce/certificate/IMA binding
  PASSED  Signed PCR mapping       PCR 10 ...
  PASSED  Pinned reference         SHA-256 ...
  IMA entries: 47 — boot aggregate + 46 modules
          000  boot_aggregate      sha256:...
          001  autofs4.ko          sha256:...
          ... все записи, без пропусков ...
          046  xt_nat.ko           sha256:...
  PASSED  IMA reference            exact content and order
  PASSED  Boot aggregate
  PASSED  PCR 10                   enrolled_sha256

[11:02:36] HTTPS peer and service identity verified
ATTESTATION SUMMARY
  Evidence: VERIFIED
  Application: ADMITTED
```

Приложение выводит `ADMITTED` только после успешного собственного решения. Ошибка TLS при `Evidence: VERIFIED` остаётся `Application: DENIED`.

## 5. Актуальность runtime и установка

Изменения: `bindings/python`, `bindings/wasm`, CLI, app `Makefile`, `scripts/{install_wheels,dev_info,build_manifest}.py`, startup в `confai-promter.py`.

1. Экспортировать metadata сборки: package version, `pipeline_revision`, fingerprint исходников. Это константы/runtime metadata, а не часть детерминированного результата `verify`.
2. Формировать fingerprint по детерминированному списку исходников и параметров сборки, включая `lib`, `protocol`, соответствующий binding, Cargo manifests/locks и build scripts. Учитывать содержимое и пути, добавление/удаление файлов и незакоммиченные изменения. Git HEAD и флаг dirty недостаточны. Отдельно учитывать transport wheel. Список входов задаётся явно: артефакты сборки, caches, `.git`, credentials и operator secrets в него не входят. Версию toolchain/target/features сохранять в manifest. Для container/extension дополнительно фиксировать содержимое Python/JS callers и renderers, чтобы новая библиотека со старым интерфейсом также различалась.
3. При сборке сохранять manifest исходников → wheel SHA-256 → SHA-256 содержащегося native artifact. Перед записью manifest убедиться, что входной fingerprint не изменился за время сборки и что экспортированный новой библиотекой source fingerprint совпадает с рассчитанным. Копирование нового manifest поверх старого binary не должно проходить проверку. Fingerprint общего Rust ядра хранится отдельно от fingerprint target-specific wrapper, поэтому Python/WASM могут подтвердить одно ядро при разных hashes artifacts.
4. `dev-info` сопоставляет текущие исходники, manifest локального wheel и реально импортируемый binary, а не только данные `pip direct_url`.
5. Добавить к `make dev-chat` проверку runtime. При изменении исходников автоматически выполнить существующий build/install pipeline; при актуальном состоянии переиспользовать установленный artifact. После установки запускать новый Python process: уже импортированный native module не обновляется установкой wheel в том же процессе.
6. Прямой запуск `confai-promter.py` до discovery проверяет поддерживаемый pipeline и соответствие доступному build manifest. При несовместимости выдаёт точную диагностику и команду обновления. В container используется manifest собранного образа; наличие checkout на машине пользователя не требуется.
7. Сохранить build/runtime metadata и caller timings рядом с run archive отдельным диагностическим record, сохранив форму archive v2. Environment paths и build hashes не добавляются в cryptographic claims. Для WASM/CLI доступны аналогичные metadata и build manifest; результат verify на одинаковых входах остаётся одинаковым.
8. Обязательный приёмочный запуск проводится из `/mnt/confidential-ai-example/.venv`, которым пользуется `make dev-chat`, затем из собранного контейнера. Успех временного `/tmp` окружения не заменяет эту проверку.

## 6. Caller, время и остальные потребители

- В `demo/collection.py` убрать захардкоженный список будущих успешных этапов. До вызова достаточно события о начале локальной проверки; дальнейший порядок берётся из `checks`.
- Измерять collection и `verify()` отдельно монотонными часами, завершать измерение `verify()` сразу по его возврату. Время печати не входит в это измерение. В Rust не добавляются clocks.
- Проверять срок challenge перед verify, после его возврата и перед admission/первым допуском credentials. Состояние challenge принадлежит caller; historical replay не выдаётся за live admission. Внутренний объект live run хранит monotonic deadline, связь с конкретными inputs/result и состояние использования challenge. Сериализованный historical archive не восстанавливает такую live-сессию. Сверка deadline после печати обязательна: полный список IMA может выводиться долго, а `verify()` к этому моменту уже завершён.
- `demo/admission.py` и `confai-promter.py` сохраняют проверку HTTPS peer/identity и credential gate. Отображение частичных успешных этапов не должно разрешать chat.
- Обновить CLI и `extension/src/{worker,ui}.js` для metadata/pipeline revision и новых stage. Worker использует bundled WASM; stale JS/WASM combination обнаруживается до обработки evidence. Перестановка строк или текстовый `detail` не определяют verdict.
- Для расширения достаточно корректно отображать детальные `checks` и итог evidence; терминальный layout и browser TLS admission не переносятся в этот этап работ.
- `confido/server` затрагивается совместимостью общего `verify_snapshot` и его tests. Flint/sidecar не потребляют `Check`, поэтому deployment routes, wire advertisement и их код для этой реорганизации менять не требуется.

## 7. Порядок реализации и приёмка

| Шаг | Изменения | Проверяемый результат |
|---|---|---|
| A | Обновить рабочую `.venv`, добавить build metadata и runtime freshness guard | Лог запуска использует текущий `vcek_correspondence`; искусственно устаревший wheel с тем же `0.4.0` обнаруживается до discovery |
| B | Разделить quote/measurement helpers и stage в Rust, согласовать pipeline revision | Повреждённая SNP signature отсекается до VCEK correspondence/HCL/leaf; плохая quote signature — до её bindings/PCR; verdict для существующих fixtures сохраняется |
| C | Пересобрать bindings/CLI, обновить потребителей и legacy rendering | Actual installed Python, CLI и WASM возвращают одинаковые результаты для одинаковых bytes/context; старые archives читаются/replay выполняется |
| D | Переработать terminal renderers и summary, убрать Python-сравнение IMA | Все модули стоят у IMA, нет повторного блока report, нет ложных per-stage timestamps, подпись показана раньше списка |
| E | Разделить timing и проверить caller deadline/admission | Отказ verifier, expiry или TLS mismatch удерживает credentials; `VERIFIED` и `ADMITTED` показаны как разные результаты |
| F | Выполнить acceptance из штатных runtime и записать manifest результатов | Новые match/mismatch логи относятся к тем же artifacts, которые запускает пользователь |

Необходимые проверки:

- Существующие Rust unit tests и hardware archive mutations; добавить только сценарии порядка/зависимостей, которые меняет декомпозиция. Для quote отдельно подпись, binding и PCR digest. Для reference — count/order/duplicate/content, boot aggregate и оба режима PCR 10.
- Границы partial result: на каждом отказе отсутствуют неподтверждённые artifacts/claims и последующие `PASSED`; все три binding flags становятся true только после общего transcript match. Отдельный сценарий: HCL прошёл, quote не прошёл — formatter показывает AK, не обращается к отсутствующему certificate и не падает. `false` у binding без выполненного этапа отображается как «не подтверждено», а не как доказанное несовпадение.
- Renderer: успешный отчёт, signature failure с полным unverified списком, IMA mismatch, более 256 entries, malformed entry, корректный подсчёт boot aggregate/modules и escape terminal controls.
- Freshness guard: изменились исходники при том же package version; wheel и `.venv` одинаково устарели; новый wheel существует, но установлен старый; transport wheel устарел отдельно; source fingerprint изменился во время сборки; manifest новый, а загруженный binary старый. Проверяется фактический запуск через штатный entry point и новый процесс после установки.
- Installed Python/CLI/WASM parity и схемы result/archive; сохранить no-network/no-clock/no-RNG свойства WASM verifier. Browser checks в Chromium/Firefox; Safari build не обозначать как runtime acceptance без Safari.
- Collector snapshot tests после переиспользования quote helpers; app admission/transport tests после переноса отображения и deadline checks.
- Окончательные match/mismatch replay в рабочей `.venv` и container; hardware replay явно обозначается историческим. Для admission использовать существующий локальный synthetic harness, который фиксирует отсутствие credentials до допуска.

Готовность: текущий source, wheel, установленный модуль и зафиксированный runtime имеют согласованные fingerprints; порядок результата объясняется зависимостями проверок; терминал показывает эти результаты и все IMA entries без повторной верификации в Python; сводка завершает весь flow.

## 8. Карта изменений по файлам

| Файлы | Конкретная ответственность после изменения |
|---|---|
| `confido/lib/src/verify.rs` | Оркестрация этапов, причины отказа, корректные partial claims/artifacts и coverage |
| Новый `confido/lib/src/result.rs`, `lib/src/lib.rs` | Типы результата и идентификаторы этапов; публичные exports сохраняют доступность существующих типов |
| `confido/lib/src/formats.rs` | Общие чистые helpers для quote signature/decode, transcript и signed PCR; композиция `verify_snapshot` для collector |
| `confido/lib/src/reference.rs` | Отдельные IMA comparison, boot aggregate и PCR 10; bounded диагностика различий |
| `confido/bindings/{python,wasm}/src/lib.rs`, `client/src/main.rs`, build scripts/manifests | Экспорт metadata ядра и wrapper; согласованная версия pipeline; существующий `verify` остаётся вызовом общего ядра |
| `confido/extension/build.py`, `extension/src/{worker,ui}.js` | Сопоставление bundled JS/WASM по manifest, поддержка нового набора checks, отображение фактического результата |
| `confidential-ai-example/demo/collection.py` | Только получение входов, lifecycle challenge, вызов verifier и caller timings; rendering переносится к вызывающему UI |
| `confidential-ai-example/demo/attestation_log.py` | Проход по реальным checks, небольшие renderers этапов, полный список IMA и оформление; без повторного IMA comparison |
| `confidential-ai-example/confai-promter.py`, `demo/admission.py` | Startup runtime check, запуск rendering, проверка deadline при admission, итог evidence/application и credential gate |
| `confidential-ai-example/Makefile`, `Dockerfile`, `scripts/{install_wheels,dev_info,build_manifest}.py` | Проверяемый путь source → artifact → installed runtime; rebuild при необходимости; manifest внутри container |
| `confido/schemas/verification-{result,archive}-v2.json`, `docs/migration-0.4.md`, app `README.md`, `example-output.md` | Описание новых stage и pipeline revision, правила legacy replay, пример итогового вывода и команды обновления |
| Rust/Python tests, `confido/scripts/{replay_checks,browser_checks}.py`, app acceptance harness, CI | Проверки зависимостей этапов, presentation trust labels, совпадения runtime и существующих admission guarantees |

Пункты A–F выполнены. Результаты тестов, live-приёмки в рабочей `.venv` и container, ограничения browser acceptance и fingerprints реально использованных artifacts записаны в [отчёте приёмки](attestation-verification-validation.md).
