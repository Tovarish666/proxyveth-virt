#!/usr/bin/env python3
"""
build.py — собрать единый proxyveth.py из апстрима ProxyControlService v3.3.

Почему сборкой, а не форком: апстрим живой, и правки должны переноситься на
новую версию, а не расходиться с ней навсегда. Каждая правка ищется как точная
подстрока и обязана встретиться ровно один раз — если апстрим сдвинулся,
сборка падает и говорит, какая именно правка отвалилась, вместо того чтобы
молча выдать полурабочий файл.

Что добавляется к v3.3:

  1. Развязка virt/real. Колонка `real` в таблице говорит, какой октет у
     модема на его мини-сервере; `n` остаётся тем, что видит mp.space.
     Нужно, когда номера модемов с разных мини-серверов пересекаются.

  2. Посредник Host. Одного DNAT мало: прошивка E3372 сверяет заголовок Host
     и на чужой отвечает 307 Redirect. Проверено на живом модеме — один и тот
     же пакет, разница только в заголовке:
         Host: 192.168.64.1    -> 307
         Host: 192.168.101.1   -> 200
     Посредник занимает виртуальный адрес внутри namespace, правит Host в
     запросе и адрес в Location ответа.

  3. Безопасные номера таблиц маршрутизации. При RT_TABLE_BASE=100 модемы
     153/154/155 попадают в таблицы 253/254/255 — default/main/local, и
     ns_down выполняет `ip route flush table main`. Хост теряет сеть вместе
     с SSH. Пока N_MAX был 200, это ждало своего часа.

  4. N_MAX поднят с 200 до 254 — весь диапазон третьего октета.

Применение:

    python3 build.py --fetch                 скачать апстрим и собрать
    python3 build.py upstream.py -o out.py   собрать из локальной копии
    python3 build.py upstream.py --check     только проверить применимость
"""
import argparse
import sys
import urllib.request

UPSTREAM = ("https://raw.githubusercontent.com/Tovarish666/"
            "ProxyControlService/main/proxyveth.py")
MARK = "#  Посредник Host"

# ── Блок посредника целиком ─────────────────────────────────────────────────
HOSTFIX_BLOCK = '''# ════════════════════════════════════════════════════════════════════════════
#  Посредник Host: 192.168.<n>.1  ->  192.168.<real>.1
#
#  Зачем он вообще. Развязка адресов делается маршрутом и NAT, но этого мало:
#  веб-сервер E3372 сверяет заголовок Host со своим адресом. Клиент про подмену
#  не знает и шлёт виртуальный — модем отвечает 307 Temporary Redirect и не
#  отдаёт сессию. Замерено на живом модеме, один пакет, одна разница:
#
#      GET http://192.168.64.1/...   Host: 192.168.64.1     -> 307
#      GET http://192.168.64.1/...   Host: 192.168.101.1    -> 200 OK
#
#  Переписать заголовок на уровне пакетов нельзя — это уже содержимое потока.
#  Поэтому виртуальный адрес занимает этот посредник: слушает 192.168.<n>.1:80
#  внутри namespace и пересылает запрос на реальный адрес с правильным Host.
#
#  Он же чинит обратное направление. На `GET /` модем отвечает
#  `Location: http://192.168.<real>.1/html/index.html` — светит реальный адрес,
#  и браузер уходит туда, где для него ничего нет. Меняем обратно.
#
#  Правил DNAT при этом не ставим: PREROUTING перехватил бы пакет раньше
#  локальной доставки, и посредник никогда бы его не увидел.
#
#  Цена: отдельный процесс на namespace, ~20 МБ. Значимо при сотнях модемов —
#  тогда это первое, что стоит переписать на компилируемом языке.
# ════════════════════════════════════════════════════════════════════════════
HOSTFIX_HDR_END = re.compile(rb"\\r?\\n\\r?\\n")
HOSTFIX_ABS_URI = re.compile(rb"^(\\S+)\\s+https?://[^/\\s]+(\\S*)\\s+(HTTP/\\d\\.\\d)$", re.I)
HOSTFIX_MAX_HDR = 32 * 1024


def hostfix_pidfile(n):
    return RUN_DIR / f"hostfix_{n}.pid"


def _pid_is_hostfix(pid, n):
    """Это посредник именно для N?

    Сверяем позицию, а не вхождение: аргументы `_hostfix <virt> <real>`, и у
    пары 64->101 в командной строке есть и «64», и «101». Проверка «str(n) in
    fields» опознала бы этот процесс ещё и как посредник для 101.
    """
    try:
        parts = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", "replace")
    except OSError:
        return False
    fields = [p for p in parts.split("\\x00") if p]
    try:
        i = fields.index("_hostfix")
    except ValueError:
        return False
    return len(fields) > i + 1 and fields[i + 1] == str(n)


def hostfix_pid(n):
    pf = hostfix_pidfile(n)
    try:
        pid = int(pf.read_text().strip())
    except (OSError, ValueError):
        pid = None
    if pid and _pid_is_hostfix(pid, n):
        return pid
    # Pid-файл соврал или потерян. `ip netns exec` не всегда делает чистый exec,
    # и записанный pid может принадлежать уже мёртвой оболочке — а сам посредник
    # при этом жив и держит адрес. Без этого прохода они копятся при каждом
    # restart, и следующий ns_up падает на «адрес уже занят».
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        cand = int(entry.name)
        if _pid_is_hostfix(cand, n):
            try:
                _write_private(pf, str(cand))
            except OSError:
                pass
            return cand
    return None


def hostfix_rewrite_request(head, host):
    """Подменить Host, погасить keep-alive, привести request-line к origin-form."""
    lines = head.split(b"\\r\\n")
    out, seen_host, seen_conn = [], False, False
    for i, line in enumerate(lines):
        low = line.lower()
        if i == 0:
            # HTTP-прокси присылает absolute-form (GET http://host/path). Веб-сервер
            # модема такого не понимает и молча ждёт, пока клиент не отвалится.
            m = HOSTFIX_ABS_URI.match(line)
            if m:
                line = m.group(1) + b" " + (m.group(2) or b"/") + b" " + m.group(3)
            out.append(line)
        elif low.startswith(b"host:"):
            out.append(f"Host: {host}".encode())
            seen_host = True
        elif low.startswith(b"connection:") or low.startswith(b"proxy-connection:"):
            if not seen_conn:
                out.append(b"Connection: close")
                seen_conn = True
        else:
            out.append(line)
    if not seen_host:
        out.insert(1, f"Host: {host}".encode())
    if not seen_conn:
        out.append(b"Connection: close")
    return b"\\r\\n".join(out)


async def _hostfix_pump(src, dst):
    try:
        while True:
            chunk = await src.read(65536)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            dst.close()
        except OSError:
            pass


class _HostfixProxy:
    def __init__(self, virt, real):
        self.virt = f"192.168.{virt}.1"
        self.real = f"192.168.{real}.1"

    async def _relay_response(self, rreader, cwriter):
        """Ответ: заголовки правим, тело переливаем как есть."""
        buf = b""
        while True:
            chunk = await rreader.read(8192)
            if not chunk:
                break
            buf += chunk
            m = HOSTFIX_HDR_END.search(buf)
            if m:
                head = buf[:m.start()].replace(self.real.encode(), self.virt.encode())
                cwriter.write(head + b"\\r\\n\\r\\n" + buf[m.end():])
                await cwriter.drain()
                await _hostfix_pump(rreader, cwriter)
                return
            if len(buf) > HOSTFIX_MAX_HDR:
                break
        if buf:
            cwriter.write(buf)
            await cwriter.drain()
        await _hostfix_pump(rreader, cwriter)

    async def handle(self, creader, cwriter):
        rwriter = None
        try:
            # Заголовки нужны целиком: Host правится прежде, чем хоть байт уйдёт.
            buf = b""
            while True:
                chunk = await asyncio.wait_for(creader.read(8192), timeout=15)
                if not chunk:
                    return
                buf += chunk
                m = HOSTFIX_HDR_END.search(buf)
                if m:
                    head, rest = buf[:m.start()], buf[m.end():]
                    break
                if len(buf) > HOSTFIX_MAX_HDR:
                    return
            rreader, rwriter = await asyncio.wait_for(
                asyncio.open_connection(self.real, 80), timeout=10)
            rwriter.write(hostfix_rewrite_request(head, self.real) + b"\\r\\n\\r\\n" + rest)
            await rwriter.drain()
            await asyncio.gather(self._relay_response(rreader, cwriter),
                                 _hostfix_pump(creader, rwriter))
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            for w in (cwriter, rwriter):
                try:
                    if w is not None:
                        w.close()
                except OSError:
                    pass


def hostfix_serve(virt, real):
    """Тело внутреннего режима `proxyveth _hostfix <virt> <real>`."""
    async def run():
        proxy = _HostfixProxy(virt, real)
        server = await asyncio.start_server(proxy.handle, f"192.168.{virt}.1", 80)
        async with server:
            await server.serve_forever()
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


def hostfix_start(n, real):
    """Запуск внутри namespace самовызовом: setns+exec, pid у Popen — наш."""
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    p = subprocess.Popen(
        ["ip", "netns", "exec", f"ns_{n}", sys.executable, str(SELF),
         "_hostfix", str(n), str(real)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL, start_new_session=True)
    _write_private(hostfix_pidfile(n), str(p.pid))
    # Порт должен успеть открыться: следом идёт проверка веб-морды.
    for _ in range(25):
        if shq(["ss", "-ltn"], ns=n).stdout.count(f"192.168.{n}.1:80"):
            break
        if p.poll() is not None:
            raise RuntimeError(f"посредник Host для ns_{n} умер на старте")
        time.sleep(0.2)
    return p.pid


def hostfix_stop(n):
    # Не один pid, а все: если прошлый снос не добил, их могло накопиться.
    for _ in range(8):
        pid = hostfix_pid(n)
        if not pid:
            break
        killed = False
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                killed = True
                break
            for _ in range(20):
                if not _pid_is_hostfix(pid, n):
                    killed = True
                    break
                time.sleep(0.1)
            if killed:
                break
        if not killed:
            break
    hostfix_pidfile(n).unlink(missing_ok=True)


'''

PATCHES = [

    # ── Шапка ───────────────────────────────────────────────────────────────
    ("docstring: описание версии",
     '''  • proxyveth rescue — снять всё и отключить автозапуск одной командой.
"""''',
     '''  • proxyveth rescue — снять всё и отключить автозапуск одной командой.

v3.4 — развязка виртуального и реального октета:
  • Колонка real в таблице: n — номер, под которым модем видит mp.space,
    real — октет модема на его мини-сервере. Нужно, когда номера модемов с
    разных мини-серверов пересекаются и свести их в одну ВМ иначе нельзя.
    Нет колонки real → real = n → поведение v3.3 без единого лишнего правила.
  • Посредник Host вместо DNAT: прошивка сверяет заголовок Host и на чужой
    отвечает 307. Проверено на живом модеме.
  • rt_table(): номера 253/254/255 заняты ядром под default/main/local, и
    ns_down на модеме 154 стирал main вместе с SSH.
  • N_MAX 200 -> 254.
"""'''),

    ("импорт asyncio",
     "import csv\nimport fcntl",
     "import asyncio\nimport csv\nimport fcntl"),

    ("SELF: путь к самому себе",
     'SCRIPT_PATH = Path("/usr/local/bin/proxyveth.py")',
     'SCRIPT_PATH = Path("/usr/local/bin/proxyveth.py")\n'
     '# Реальный путь запуска: посредник поднимается самовызовом, и symlink,\n'
     '# из-под которого нас позвали, для exec не годится.\n'
     'SELF = Path(__file__).resolve()'),

    ("N_MAX: весь диапазон третьего октета",
     "N_MIN, N_MAX = 1, 200",
     "N_MIN, N_MAX = 1, 254"),

    # Обе величины всегда одинаковы на всех установках, поэтому это умолчания
    # в коде, а не строки, которые надо не забыть прописать руками.
    ("VETH_PREFIX: уйти с eth* из-под mp.space",
     'VETH_PREFIX = os.getenv("VETH_PREFIX", "eth")',
     '# НЕ eth: mp.space считает интерфейсы eth* своими и сбрасывает на них IPv4,\n'
     '# если такого модема нет в его конфиге. Адрес исчезает, следом ядро\n'
     '# выбрасывает default из таблицы, и sing-box пишет «no route to host» на\n'
     '# адрес SOCKS5. Снаружи выглядит как «модем то отвечает, то нет», и ищется\n'
     '# это долго. Проверено на живом парке.\n'
     'VETH_PREFIX = os.getenv("VETH_PREFIX", "mdm")'),

    ("RT_TABLE_BASE: увести номера от системных таблиц",
     'RT_TABLE_BASE = int(os.getenv("RT_TABLE_BASE", "100"))',
     '# НЕ 100: тогда модемы 153/154/155 попадают в таблицы 253/254/255 —\n'
     '# default/main/local, — и ns_down выполняет `ip route flush table main`,\n'
     '# снося маршрутизацию хоста вместе с SSH. rt_table() ниже страхует и от\n'
     '# базы 100, но правильнее туда просто не попадать.\n'
     'RT_TABLE_BASE = int(os.getenv("RT_TABLE_BASE", "1000"))'),

    # ── Разбор таблицы ──────────────────────────────────────────────────────
    ("parse_rows: колонка real",
     '''_ALT_HEADERS = {"host": "proxy_host", "ip": "proxy_host", "server": "proxy_host",
                "port": "proxy_port", "user": "login", "username": "login",
                "pass": "password", "pwd": "password"}''',
     '''_ALT_HEADERS = {"host": "proxy_host", "ip": "proxy_host", "server": "proxy_host",
                "port": "proxy_port", "user": "login", "username": "login",
                "pass": "password", "pwd": "password",
                # Октет модема на его мини-сервере. Синонимы — потому что
                # таблицу ведут руками и колонку называют по-разному.
                "real": "real", "real_n": "real", "modem": "real",
                "modem_n": "real", "modem_ip": "real", "mgmt": "real"}


def parse_real(raw, n):
    """Октет модема на дальней стороне SOCKS5.

    Принимает и «102», и «192.168.102.100» (адрес мини-сервера в сети модема),
    и «192.168.102.1» (адрес веб-морды) — берётся третий октет. Так колонку
    можно заполнять копипастой из любого места, где этот адрес уже записан.

    Пусто — виртуализация не нужна, real = n, поведение v3.3.
    """
    raw = (raw or "").strip()
    if not raw:
        return n
    if raw.count(".") == 3:
        try:
            parts = [int(p) for p in raw.split(".")]
        except ValueError:
            raise ValueError(f"адрес модема не разбирается: {raw!r}")
        if parts[0] != 192 or parts[1] != 168:
            raise ValueError(f"адрес модема вне 192.168.0.0/16: {raw}")
        raw = str(parts[2])
    real = int(raw)
    if not (N_MIN <= real <= N_MAX):
        raise ValueError(f"октет модема {real} вне {N_MIN}..{N_MAX}")
    return real'''),

    ("parse_rows: real в записи модема",
     '''            if str(n) in modems:
                bad.append(f"стр.{row_idx}: N={n} — дубль, взята первая строка")
                continue
            modems[str(n)] = {"proxy_host": host, "proxy_port": port_i,
                              "login": login, "password": password, "enabled": en}''',
     '''            real = parse_real(rd.get("real", ""), n)
            if str(n) in modems:
                bad.append(f"стр.{row_idx}: N={n} — дубль, взята первая строка")
                continue
            modems[str(n)] = {"proxy_host": host, "proxy_port": port_i,
                              "login": login, "password": password,
                              "real": real, "enabled": en}'''),

    # ── Посредник и безопасные таблицы ──────────────────────────────────────
    ("блок посредника Host",
     '''# ════════════════════════════════════════════════════════════════════════════
#  Namespace up/down
# ════════════════════════════════════════════════════════════════════════════''',
     HOSTFIX_BLOCK +
     '''# ════════════════════════════════════════════════════════════════════════════
#  Namespace up/down
# ════════════════════════════════════════════════════════════════════════════'''),

    ("rt_table(): обход системных таблиц",
     '''def veth_names(n):
    """(имя на хосте, имя внутри namespace)."""''',
     '''def rt_table(n):
    """Номер таблицы маршрутизации для модема N.

    253/254/255 заняты ядром под default/main/local. При RT_TABLE_BASE=100
    модемы 153/154/155 попадают ровно в них, и `ip route flush table 254` в
    ns_down стирает main — хост теряет сеть вместе с SSH. Такие номера уводим
    в свой диапазон.

    Та же ловушка видна в /etc/iproute2/rt_tables: если там заведены алиасы
    вида `254 modem155`, системные таблицы уже переименованы, и `ip rule show`
    показывает `lookup modem156` вместо `lookup local`. Само по себе безвредно,
    но маскирует происходящее.
    """
    rt = RT_TABLE_BASE + n
    return rt if rt not in (0, 253, 254, 255) else 20000 + n


def veth_names(n):
    """(имя на хосте, имя внутри namespace)."""'''),

    # ── ns_up ───────────────────────────────────────────────────────────────
    ("ns_up: таблица и real",
     '''    pp = int(modem["proxy_port"])
    rt = RT_TABLE_BASE + n''',
     '''    pp = int(modem["proxy_port"])
    rt = rt_table(n)
    real = int(modem.get("real") or n)     # октет модема на дальней стороне'''),

    ("ns_up: реальный адрес веб-морды + посредник",
     '''        sh(["ip", "route", "add", f"192.168.{n}.1/32", "dev", f"tun{n}"], ns=n)  # Huawei API''',
     '''        # Веб-морда модема. Адрес реальный: именно он поедет в SOCKS5 CONNECT
        # и именно его знает 3proxy на мини-сервере.
        sh(["ip", "route", "add", f"192.168.{real}.1/32", "dev", f"tun{n}"], ns=n)
        # mp.space ходит только на 192.168.{n}.1. Отдаём этот адрес посреднику:
        # одного NAT мало, прошивка сверяет Host и на чужой отвечает 307.
        if real != n:
            sh(["ip", "addr", "add", f"192.168.{n}.1/32", "dev", vn], ns=n)
            hostfix_start(n, real)
            if verbose:
                log_step(f"ns_{n}: посредник Host 192.168.{n}.1 → 192.168.{real}.1")'''),

    ("ns_up: итоговая строка",
     '''            log_ok(f"ns_{n} ГОТОВ | 192.168.{n}.100 → {proxy_ip}:{pp} | Huawei: 192.168.{n}.1")''',
     '''            mgmt = (f"192.168.{n}.1" if real == n
                    else f"192.168.{n}.1 → 192.168.{real}.1")
            log_ok(f"ns_{n} ГОТОВ | 192.168.{n}.100 → {proxy_ip}:{pp} | Huawei: {mgmt}")'''),

    # ── ns_down / health ────────────────────────────────────────────────────
    ("ns_down: остановить посредник",
     '''    rt = RT_TABLE_BASE + n
    vh, _ = veth_names(n)''',
     '''    rt = rt_table(n)
    vh, _ = veth_names(n)'''),

    ("ns_down: снять посредник перед namespace",
     '''    singbox_stop(n)
    shq(["ip", "netns", "del", f"ns_{n}"])''',
     '''    hostfix_stop(n)
    singbox_stop(n)
    shq(["ip", "netns", "del", f"ns_{n}"])'''),

    ("ns_health: посредник",
     '''    r = shq(["ip", "rule", "show"])
    if f"192.168.{n}.100" not in r.stdout:
        return "rule_missing"
    return "ok"''',
     '''    r = shq(["ip", "rule", "show"])
    if f"192.168.{n}.100" not in r.stdout:
        return "rule_missing"
    # Pid-файл есть только у тех namespace, где посредник нужен (real != n).
    if hostfix_pidfile(n).exists() and not hostfix_pid(n):
        return "hostfix_dead"
    return "ok"'''),

    ("статус: расшифровка hostfix_dead",
     '''    "rule_missing": "нет ip rule на хосте",''',
     '''    "rule_missing": "нет ip rule на хосте",
    "hostfix_dead": "посредник Host не запущен",'''),

    # ── check ───────────────────────────────────────────────────────────────
    ("cmd_check: таблица и real",
     '''    proxy_ip = resolve_host(modem["proxy_host"])
    rt = RT_TABLE_BASE + n''',
     '''    proxy_ip = resolve_host(modem["proxy_host"])
    rt = rt_table(n)
    real = int(modem.get("real") or n)'''),

    ("cmd_check: заголовок с реальным модемом",
     '''    header(f"CHECK ns_{n}  ({modem['proxy_host']}:{modem['proxy_port']})")''',
     '''    header(f"CHECK ns_{n}  ({modem['proxy_host']}:{modem['proxy_port']})"
           + ("" if real == n else f"  → модем {real}"))'''),

    ("cmd_check: маршрут и посредник",
     '''    chk("маршрут Huawei API", f"192.168.{n}.1" in r.stdout)''',
     '''    chk("маршрут Huawei API", f"192.168.{real}.1" in r.stdout,
        "" if real == n else f"(на реальный 192.168.{real}.1)")
    if real != n:
        pid = hostfix_pid(n)
        chk(f"посредник Host 192.168.{n}.1 → 192.168.{real}.1", bool(pid),
            f"pid={pid}" if pid else "не запущен")'''),

    ("cmd_check: различить сломанную подмену и мёртвый модем",
     '''    r = shq(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "6",
             f"http://192.168.{n}.1/api/webserver/SesTokInfo"], ns=n, timeout=12)
    chk("веб-морда модема", r.stdout.strip() == "200", f"HTTP {r.stdout.strip() or '—'}")''',
     '''    r = shq(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "6",
             f"http://192.168.{n}.1/api/webserver/SesTokInfo"], ns=n, timeout=12)
    code = r.stdout.strip()
    virt_ok = chk("веб-морда модема", code == "200", f"HTTP {code or '—'}")
    if real != n and not virt_ok:
        # Два разных диагноза выглядят одинаково — «не отвечает». Спрашиваем
        # реальный адрес в обход посредника и говорим, что именно сломано.
        r2 = shq(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "6",
                  f"http://192.168.{real}.1/api/webserver/SesTokInfo"], ns=n, timeout=12)
        if r2.stdout.strip() == "200":
            log_warn(f"  но 192.168.{real}.1 напрямую отвечает — модем и прокси живы, "
                     f"дело в подмене адреса")
            if code == "307":
                log_warn("  307 — это ответ прошивки на чужой Host: посредник не в цепи")
        else:
            log_warn(f"  192.168.{real}.1 напрямую тоже молчит — дело в модеме или "
                     f"прокси, подмена ни при чём")'''),

    # ── Мелочи ──────────────────────────────────────────────────────────────
    ("cmd_autosync: пересобирать при смене real",
     '''        if any(o.get(f) != n2.get(f) for f in ("proxy_host", "proxy_port", "login", "password")):''',
     '''        if any(o.get(f) != n2.get(f)
               for f in ("proxy_host", "proxy_port", "login", "password", "real")):'''),

    ("cmd_show_config: показывать реальный октет",
     '''        print(f"  {mark} {int(k):>3}  {m['proxy_host']}:{m['proxy_port']}  {m['login']}")''',
     '''        real = int(m.get("real") or int(k))
        via = "" if real == int(k) else f"  → модем {real}"
        print(f"  {mark} {int(k):>3}  {m['proxy_host']}:{m['proxy_port']}  "
              f"{m['login']}{via}")'''),

    ("cleanup: pid-файлы посредников",
     '''        for f in RUN_DIR.glob("ns_*.pid"):
            f.unlink(missing_ok=True)''',
     '''        for f in RUN_DIR.glob("ns_*.pid"):
            f.unlink(missing_ok=True)
        for f in RUN_DIR.glob("hostfix_*.pid"):
            f.unlink(missing_ok=True)'''),

    ("_env_set(): дописать строку в env, не потеряв остальные",
     '''def load_config(required=True):''',
     '''def _env_set(key, value):
    """Записать KEY=value в env-файл, сохранив всё прочее.

    Перезаписывать файл целиком нельзя: там могут лежать чужие строки, а
    установка запускается и на уже настроенной машине.
    """
    _ensure_dirs()
    lines, replaced = [], False
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.strip().startswith(f"{key}="):
                lines.append(f"{key}={value}")
                replaced = True
            else:
                lines.append(line)
    if not replaced:
        lines.append(f"{key}={value}")
    _write_private(ENV_FILE, "\\n".join(lines) + "\\n")


def load_config(required=True):'''),

    ("cmd_setup: спросить таблицу, а не падать",
     '''def cmd_setup():
    header("ProxyVeth — установка")
    if not (SOURCE_URL or SHEET_ID):
        log_fail("Не задан источник конфигурации")
        log_info(f"Пропиши в {ENV_FILE}:  SHEET_CSV_URL=https://docs.google.com/...")
        return 1
    cmd_install()''',
     '''def cmd_setup():
    global SOURCE_URL
    header("ProxyVeth — установка")
    if not (SOURCE_URL or SHEET_ID):
        # Ссылка на таблицу — единственное, что отличает одну установку от
        # другой. Всё остальное зашито в умолчания, спрашивать больше нечего.
        if not sys.stdin.isatty():
            log_fail("Не задан источник конфигурации")
            log_info(f"Пропиши в {ENV_FILE}:  SHEET_CSV_URL=https://docs.google.com/...")
            log_info("Либо запусти установку в терминале — она спросит сама")
            return 1
        print(f"\\n  {B}Таблица модемов{R}")
        print(f"  {D}Колонки: n | real | proxy    (proxy = host:port:login:password)")
        print(f"  Опубликовать: Файл → Поделиться → Опубликовать в интернете → CSV{R}\\n")
        try:
            url = input("  Ссылка на CSV: ").strip()
        except EOFError:
            url = ""
        if not url:
            log_fail("Ссылка не введена — ставить нечего")
            return 1
        if not url.lower().startswith(("http://", "https://")):
            log_fail(f"Это не похоже на ссылку: {url[:60]}")
            return 1
        _env_set("SHEET_CSV_URL", url)
        os.environ["SHEET_CSV_URL"] = url
        SOURCE_URL = url
        log_ok(f"Записано в {ENV_FILE}")
    cmd_install()'''),

    ("main: внутренний режим посредника",
     '''def main():
    if os.geteuid() != 0:''',
     '''def main():
    # Внутренний режим: посредник Host. Запускается сам из ns_up через
    # `ip netns exec`, руками не нужен, поэтому в USAGE не показан.
    if len(sys.argv) >= 4 and sys.argv[1] == "_hostfix":
        hostfix_serve(int(sys.argv[2]), int(sys.argv[3]))
        return
    if os.geteuid() != 0:'''),

    ("USAGE: версия и колонки таблицы",
     '''  Источник:  API_URL | SHEET_CSV_URL | SHEET_ID   (файл {ENV_FILE})''',
     '''  Таблица:   n | real | proxy       где proxy = host:port:login:password
             n    — номер, под которым модем видит mp.space (192.168.n.100)
             real — октет модема на его мини-сервере; пусто = равен n

  Источник:  API_URL | SHEET_CSV_URL | SHEET_ID   (файл {ENV_FILE})'''),

    ("USAGE: версия",
     '''USAGE = f"""{B}ProxyVeth v3.3{R}''',
     '''USAGE = f"""{B}ProxyVeth v3.4{R}'''),
]


def build(src):
    """Применить правки последовательно. Возвращает (текст, список проблем)."""
    problems = []
    out = src
    for desc, old, new in PATCHES:
        c = out.count(old)
        if c != 1:
            problems.append(f"  [!] {desc}: найдено {c} вхождений вместо 1")
            continue
        out = out.replace(old, new, 1)
    return out, problems


def main():
    ap = argparse.ArgumentParser(description="Сборка единого proxyveth.py")
    ap.add_argument("source", nargs="?", help="локальная копия апстрима")
    ap.add_argument("--fetch", action="store_true", help="скачать апстрим с GitHub")
    ap.add_argument("-o", "--output", default="proxyveth.py")
    ap.add_argument("--check", action="store_true", help="только проверить применимость")
    args = ap.parse_args()

    if args.fetch:
        print(f"  качаю {UPSTREAM}")
        try:
            with urllib.request.urlopen(UPSTREAM, timeout=30) as r:
                src = r.read().decode("utf-8")
        except OSError as e:
            print(f"не скачалось: {e}", file=sys.stderr)
            return 1
    elif args.source:
        try:
            with open(args.source, encoding="utf-8") as f:
                src = f.read()
        except OSError as e:
            print(f"не читается {args.source}: {e}", file=sys.stderr)
            return 1
    else:
        ap.error("нужен файл-источник или --fetch")

    if MARK in src:
        print("  источник уже собран — нужен чистый апстрим", file=sys.stderr)
        return 1

    out, problems = build(src)
    if problems:
        print("Сборка НЕ выполнена — апстрим разошёлся с ожиданиями:", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        print("\nПравьте PATCHES под новую версию и запустите снова.", file=sys.stderr)
        return 1

    if args.check:
        print(f"  все {len(PATCHES)} правок применимы")
        return 0

    try:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(out)
    except OSError as e:
        print(f"не записывается {args.output}: {e}", file=sys.stderr)
        return 1

    for desc, _o, _n in PATCHES:
        print(f"  [ok] {desc}")
    print(f"\n  {len(PATCHES)} правок -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
