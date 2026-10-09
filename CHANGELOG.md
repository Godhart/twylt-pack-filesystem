# 0.6.0 — 2026-10-08

- Replace copied workspace/transport checks with TWYLT >=1.1.1 APIs.
- Move shared business helpers into shared/filesystem_common; keep tool-only code with its tool.
- Remove source-copy generation; deploy source tree without building a Python pack.
- Support optional nested transport cwd outside workspace and common network policy.
- Preserve existing scenarios, add actual builder launcher checks, refresh schemas and ADR.

# Changelog

## 0.5.0 — 2026-10-02

Текстовые статы дополнены encoding_source (bom/utf8/explicit), line_ending
(lf/crlf/cr/mixed/none) и indentation (space/tab/mixed/none). Поля доступны
в fs_stat и include_stats в list/find/glob. Для binary/unknown — null.
Поведение определения encoding и общий контроль рабочей области сохранены.
Выход fs_stat 1.1.0, выход поисковых команд 2.2.0; входные контракты не изменены.

## 0.4.0 — 2026-10-02

Добавлены fs_stat (байты, text/binary/unknown, точное число строк) и fs_chmod
(POSIX octal mode, dry_run, без рекурсии). В list/find/glob добавлены include_stats,
stats_encoding и stats_max_bytes, в Entry — nullable stats. Статы читают только
файлы возвращаемой страницы. Политика рабочей области 1.0.0 не изменена.
Вход find 2.2.0, list/glob 2.1.0; выходы всех поисковых команд 2.1.0.
Контракты новых команд 1.0.0. Прежние регрессии сохранены.

## 0.3.0 — 2026-10-02

Добавлен необязательный content-фильтр для fs_find: текст/regex, Unicode ignore_case,
encoding, max_bytes и skip_binary. Прежняя схема результата и правила пагинации
сохранены. Фильтры содержимого не добавлены в list/glob. Входная схема fs_find 2.1.0.
Проверки рабочей области и журнал инцидентов сохранены без изменения политики.
Новые тесты дополняют полный набор регрессий предыдущего выпуска.

## 0.2.0 — 2026-10-02

Несовместимое изменение: обязательный TWYLT_WORKSPACE_ROOT и виртуальные пути.
Общая политика ссылок/границ, preflight рекурсивных операций, защита файлового
транспорта TWYLT. Журнал инцидентов JSONL, внешний sink и fail-closed при ошибках.
В Git дополнительно ограничены remotes, конфигурация, hooks и служебные хранилища.
Сохранены регрессии прежних версий, обновлены ожидания для запрещённых ссылок;
добавлены проверки обходов и журналирования. См. WORKSPACE.md.

## 0.1.0 — 2026-10-02

- Первый набор из 11 TWYLT-инструментов файловой системы.
- Общий обход с глубиной, regex/glob, типом, POSIX-владельцем/правами, os.access и пагинацией.
- Чтение текста, JSON/YAML/TOML и Markdown AST; запись текста и структурированных данных.
- Copy/move/delete с явной перезаписью и рекурсивным удалением.
- Генератор автономных обёрток, примеры, схемы, тесты и ADR.
