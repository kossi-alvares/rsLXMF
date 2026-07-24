# TODO

## Выполнено

- [x] Перевести загрузку сообщений `PropagationClient` на публичный
  `rns_runtime::link_client::LinkSession`.
- [x] Добавить в rsReticulum открытие Link по уже известному публичному ключу
  (`e8c1c8d`).
- [x] Исправить возможность выполнять Link identification в фоновой Tokio-задаче
  (`4a236de`).
- [x] Перевести peer-to-peer `PropagationSyncTask` на `LinkSession` и общий
  Resource API rsReticulum.
- [x] Удалить из `PropagationClient` и `PropagationSyncTask` собственные
  реализации Link handshake, request/response, Resource transfer и proof
  processing (`d51b5e4`).
- [x] Добавить в rsReticulum общий builder standalone announce-пакетов
  (`221fa8b`).
- [x] Перевести propagation и control announce в rsLXMF на общий announce API
  rsReticulum (`542575b`).
- [x] Расширить долгоживущий `LinkSession` high-level отправкой payload с
  автоматическим выбором packet/resource и ожиданием delivery proof.
- [x] Перевести рабочий исходящий Direct path `lxmd` на runtime-owned
  `LinkSessionHandle`, сохранив LXMF-очередь, retry и delivery events в
  `LinkDeliveryManager`.
- [x] Перевести propagation deposits на одноразовый runtime-owned
  `LinkSessionHandle` с identification до отправки и закрытием после proof.
- [x] Отключить legacy Link/Resource fallback для production-сборок:
  Direct и propagation требуют настроенный `ReticulumHandle`.
- [x] Исключить legacy LinkRequest destination channel, transport errors и
  inbound wire handlers из production-компиляции `LinkDeliveryManager`.
- [x] Удалить переходные legacy-тесты Link creation/transport capacity,
  establishment timeout и Direct Link reuse; reuse покрыт тестом
  `LinkSessionHandle` в rsReticulum.
- [x] Удалить legacy wire-тесты исходящих Direct packet proof, backchannel и
  LinkClose; эквивалентная доставка и proof backchannel покрыты тестом
  `LinkSessionHandle` в rsReticulum.
- [x] Перенести проверку Link identification из legacy Direct engine в тест
  runtime-owned `LinkSessionHandle` в rsReticulum.
- [x] Удалить legacy wire-тесты исходящего Resource split/proof/reject/cancel;
  протокольные состояния, сегментация и reassembly покрыты в rsReticulum.
- [x] Убрать legacy HMU/REQ/Resource proof/reject и Link packet proof handlers
  из публичного production API `LinkDeliveryManager`.
- [x] Исключить ручной Link/Resource driver из production-ветки `tick()` и
  закрывать runtime-owned сессию при отмене активной доставки.
- [x] Удалить последние тесты, создававшие обходной test-only Direct Link без
  `ReticulumHandle`; сохранить независимые тесты LXMF backchannel-состояний.
- [x] Удалить legacy Link variant, transfer state и transport event channel из
  модели `LinkDeliveryManager`; исходящие сессии теперь только runtime-owned.
- [x] Физически удалить из `link_delivery.rs` отключённые legacy inbound
  handlers, ручную ветку `tick()` и Link/Resource wire helpers.
- [x] Завершить разделение `LinkDeliveryManager`: в rsLXMF остались очереди,
  retry, LXMF-состояния и backchannel-маршрутизация; Link lifecycle и transfer
  принадлежат публичным API rsReticulum.
- [x] Сохранить входящие backchannel-ссылки через `LinkManager` без ручной
  обработки Resource ADV/parts/HMU/proofs в rsLXMF; использовать нативные
  receipt/error типы `LinkManager` без адаптера в `lxmd`.
- [x] Удалить прямую зависимость rsLXMF от `rns-link`; Link state и таймауты
  экспортируются публичным runtime API rsReticulum.
- [x] Перевести рабочий opportunistic delivery path `lxmd` с ручной сборки
  DATA-пакета на `try_send_pre_encrypted_packet` rsReticulum.
- [x] Проверить полный workspace rsLXMF после рефакторинга: проходят core,
  tools, examples, CLI и doc tests.

## Следующие шаги

- [x] Удалить оставшиеся неиспользуемые структуры и зависимости низкого уровня
  (`rns-link`, Resource transfer primitives и ручные wire headers), если после
  миграции они больше не нужны rsLXMF. Неиспользуемый `ResourceResult` удалён;
  `rns-wire` и `rns-protocol` сохранены для используемых packet parsing и LXMF
  sync message types.
- [ ] Добавить интеграционные сетевые тесты для:
  - [x] direct delivery короткого сообщения между двумя `LinkManager`;
  - [x] direct delivery через Resource между двумя `LinkManager`;
  - [x] повторного использования Direct Link;
  - [x] backchannel delivery с proof после LINKIDENTIFY;
  - [x] propagation download и peer sync через shared instance.
- [ ] Сопоставить оставшийся публичный API rsLXMF с Python LXMF и зафиксировать
  известные несовпадения.
- [ ] Выполнить финальный прогон `cargo check --workspace --all-targets` и
  `cargo test --workspace` в обоих репозиториях.

## Резюме за 24 июля 2026

Сегодня загрузка сообщений с propagation node и синхронизация между
propagation peers были переведены с собственных сетевых машин rsLXMF на
публичные `LinkSession` и Resource API rsReticulum. Для этого в rsReticulum
добавлено открытие Link по известному публичному ключу, исправлена task-safety
identification и добавлен общий builder announce-пакетов.

После переключения рабочих путей из rsLXMF удалено 2317 строк дублирующего
Link/Resource-кода. Propagation и control announce теперь также формируются
через rsReticulum. Полный набор тестов rsLXMF прошёл; изменения находятся
только в ветках `dev`, push не выполнялся.
