#!/usr/bin/env python3
"""
ProxyVeth v3.3
SOCKS5 → network namespace → sing-box (tun) → veth → mp.space (source routing).

Главное отличие от v2 — DNS.
  Раньше: /etc/netns/ns_N/resolv.conf = 8.8.8.8 + маршрут 8.8.8.8/32 через хост.
  Это давало (а) утечку — имена резолвились с IP дата-центра, а не модема;
  (б) петлю: mproxy с source 192.168.N.100 → ip rule → ns → маршрут через
  192.168.N.100 → обратно на хост → ip rule → ns → ... пока не кончится TTL.
  Теперь: DNS уходит В ТУННЕЛЬ, sing-box перехватывает его на tun и резолвит
  сам по TCP к 1.1.1.1 через SOCKS5. Ни утечки, ни петли, ни UDP в 3proxy.

Прочее:
  • WAN-интерфейс определяется автоматически (был захардкожен eth0 — на Ubuntu
    24.04 с machine=q35 интерфейс называется ens18/enp6s18, и NAT молча не работал).
  • Никакого shell=True — все команды списками аргументов (данные приходят из
    Google-таблицы, туда можно написать что угодно).
  • Глобальный flock: systemd, watchdog, autosync и руки не топчут друг друга.
  • watchdog перечитывает конфиг каждый проход (раньше держал стартовый навсегда).
  • autosync не сносит больше N% namespace за один проход.
  • up/down all — параллельно (200 модемов больше не упираются в TimeoutStartSec).
  • config.json и конфиги sing-box — 0600, каталоги 0700.
  • cleanup удаляет только свои правила (раньше делал iptables -t nat -F).

v3.2:
  • Имена интерфейсов: на хосте ethN (VETH_PREFIX), внутри namespace — eth0.
    Было veth_ext{N}_host — 16 символов при трёхзначном N, то есть длиннее
    лимита IFNAMSIZ, и модемы с N ≥ 100 не создавались в принципе.
  • Проверка пересечения 192.168.N.0/24 с сетью самой ВМ. Без неё модем N=1
    на ВМ в 192.168.1.0/24 добавляет вторую connected-маршрутку на тот же
    префикс — и ВМ теряет связь с собственной LAN, включая SSH.
  • proxyveth rescue — снять всё и отключить автозапуск одной командой.
"""

import csv
import fcntl
import glob
import io
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

# ── Пути ────────────────────────────────────────────────────────────────────
CONFIG_DIR = Path(os.getenv("PROXYVETH_DIR", "/etc/proxyveth"))
ENV_FILE = CONFIG_DIR / "env"


def _load_env_file():
    """env-файл не перебивает реальное окружение — только дополняет."""
    if not ENV_FILE.exists():
        return
    try:
        lines = ENV_FILE.read_text().splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        os.environ.setdefault(k.strip(), v)


_load_env_file()

CONFIG_FILE = CONFIG_DIR / "config.json"
LOG_DIR = CONFIG_DIR / "logs"
WATCHDOG_LOG = LOG_DIR / "watchdog.log"
SINGBOX_CONF_DIR = CONFIG_DIR / "singbox"
RUN_DIR = Path("/run/proxyveth")
LOCK_FILE = Path("/run/proxyveth.lock")
SCRIPT_PATH = Path("/usr/local/bin/proxyveth.py")

# ── Источник конфигурации ───────────────────────────────────────────────────
# API_URL — задел под Волну 3: панель отдаёт тот же CSV по тому же контракту.
SOURCE_URL = (os.getenv("API_URL") or os.getenv("SHEET_CSV_URL")
              or os.getenv("PROXYVETH_SOURCE_URL", ""))
SHEET_ID = os.getenv("SHEET_ID", "")
SHEET_GID = os.getenv("SHEET_GID", "0")

# ── sing-box ────────────────────────────────────────────────────────────────
SINGBOX_BIN = os.getenv("SINGBOX_BIN", "/usr/local/bin/sing-box")
SINGBOX_VER = os.getenv("SINGBOX_VER", "1.10.0")
SINGBOX_URL = (f"https://github.com/SagerNet/sing-box/releases/download/"
               f"v{SINGBOX_VER}/sing-box-{SINGBOX_VER}-linux-amd64.tar.gz")
# Лог sing-box на каждый namespace. Без него причина «tun не поднялся»
# не видна вообще: раньше вывод уходил в /dev/null, а конфиг после неудачи
# удалялся — диагностировать было нечем.
SINGBOX_LOG_LEVEL = os.getenv("SINGBOX_LOG_LEVEL", "warn")

# ── Сеть ────────────────────────────────────────────────────────────────────
# Резолвер для namespace. Ходит ЧЕРЕЗ туннель, отвечает sing-box (TCP к нему же).
NS_DNS = os.getenv("NS_DNS", "1.1.1.1")
NS_DNS_ALT = os.getenv("NS_DNS_ALT", "8.8.8.8")
# Имена интерфейсов. На хосте — {VETH_PREFIX}{N} (eth41), внутри namespace —
# всегда eth0: там своё пространство имён, и это самое читаемое имя.
# Если добавишь ВМ второй физический адаптер, ядро тоже захочет имя ethN —
# тогда поставь VETH_PREFIX=mdm в /etc/proxyveth/env.
VETH_PREFIX = os.getenv("VETH_PREFIX", "eth")
NS_IFACE = os.getenv("NS_IFACE", "eth0")
RT_TABLE_BASE = int(os.getenv("RT_TABLE_BASE", "100"))
TUN_TIMEOUT = int(os.getenv("TUN_TIMEOUT", "20"))
CURL_TIMEOUT = int(os.getenv("CURL_TIMEOUT", "10"))
WORKERS = int(os.getenv("PROXYVETH_WORKERS", "8"))
N_MIN, N_MAX = 1, 200

# ── Watchdog / autosync ─────────────────────────────────────────────────────
WATCHDOG_INTERVAL = int(os.getenv("WATCHDOG_INTERVAL", "60"))
WATCHDOG_WAN_EVERY = int(os.getenv("WATCHDOG_WAN_EVERY", "10"))
WATCHDOG_MAX_RESTART = int(os.getenv("WATCHDOG_MAX_RESTART", "3"))
# Предохранитель: кто-то поставил фильтр в таблице / отозвал публикацию —
# autosync не должен за 5 минут разобрать прод.
AUTOSYNC_MAX_REMOVE_PCT = int(os.getenv("AUTOSYNC_MAX_REMOVE_PCT", "30"))

R = "\033[0m"; G = "\033[32m"; RD = "\033[31m"; Y = "\033[33m"
C = "\033[36m"; B = "\033[1m"; D = "\033[2m"

if not sys.stdout.isatty() or os.getenv("NO_COLOR"):
    R = G = RD = Y = C = B = D = ""

_HOST_LOCK = threading.Lock()   # хостовые iptables/ip rule из нескольких потоков
_PRINT_LOCK = threading.Lock()  # чтобы 8 потоков не месили вывод построчно
_WAN_IFACE = None


# ════════════════════════════════════════════════════════════════════════════
#  Вывод
# ════════════════════════════════════════════════════════════════════════════
def log_ok(m):   print(f"  {G}✓{R} {m}")
def log_fail(m): print(f"  {RD}✗{R} {m}")
def log_info(m): print(f"  {C}ℹ{R} {m}")
def log_warn(m): print(f"  {Y}⚠{R} {m}")
def log_step(m): print(f"  {D}→{R} {m}")


def header(m):
    print(f"\n{B}{'═' * 62}\n  {m}\n{'═' * 62}{R}")


def wlog(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(WATCHDOG_LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ════════════════════════════════════════════════════════════════════════════
#  Запуск команд (только списками аргументов — никакого shell)
# ════════════════════════════════════════════════════════════════════════════
def sh(args, ns=None, check=True, timeout=60, quiet=False):
    args = [str(a) for a in args]
    if ns is not None:
        args = ["ip", "netns", "exec", f"ns_{ns}"] + args
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        if check:
            raise RuntimeError(f"нет команды: {args[0]}") from e
        return subprocess.CompletedProcess(args, 127, "", str(e))
    except subprocess.TimeoutExpired:
        if check:
            raise RuntimeError(f"timeout {timeout}s: {' '.join(args)}")
        return subprocess.CompletedProcess(args, 124, "", "timeout")
    if check and p.returncode != 0:
        if not quiet:
            log_fail("CMD: " + " ".join(args))
            err = (p.stderr or p.stdout).strip()
            if err:
                log_fail("     " + err.splitlines()[0])
        raise RuntimeError(f"rc={p.returncode}: {' '.join(args)}")
    return p


def shq(args, ns=None, timeout=60):
    """Тихо, без исключений."""
    return sh(args, ns=ns, check=False, timeout=timeout, quiet=True)


def ipt(args, ns=None, table=None, check=True, quiet=None):
    """iptables.

    ВАЖНО: -t <таблица> обязан идти ДО команды (-A/-I/-D/-C), иначе iptables
    ругается «Bad argument». Поэтому таблица — отдельный параметр, а не часть
    правила: собрать её в неправильном порядке физически нельзя.
    -w нужен, чтобы параллельные вызовы не дрались за xtables lock.
    """
    cmd = ["iptables", "-w", "5"]
    if table:
        cmd += ["-t", table]
    cmd += list(args)
    if quiet is None:
        quiet = not check
    return sh(cmd, ns=ns, check=check, quiet=quiet)


def ipt_has(rule, ns=None, table=None):
    return ipt(["-C"] + list(rule), ns=ns, table=table, check=False).returncode == 0


def ipt_add(rule, ns=None, table=None, check=True):
    if ipt_has(rule, ns=ns, table=table):
        return True
    return ipt(["-A"] + list(rule), ns=ns, table=table, check=check).returncode == 0


def ipt_ins(rule, ns=None, table=None, check=True):
    """Вставить первой — важно для ACCEPT'ов, которые должны быть выше DROP."""
    if ipt_has(rule, ns=ns, table=table):
        return True
    return ipt(["-I"] + list(rule), ns=ns, table=table, check=check).returncode == 0


def ipt_del(rule, ns=None, table=None):
    n = 0
    while n < 20 and ipt_has(rule, ns=ns, table=table):
        if ipt(["-D"] + list(rule), ns=ns, table=table, check=False).returncode != 0:
            break
        n += 1
    return n


# ════════════════════════════════════════════════════════════════════════════
#  Блокировка: systemd, watchdog, autosync и руки не должны пересекаться
# ════════════════════════════════════════════════════════════════════════════
class Lock:
    def __init__(self, timeout=120):
        self.timeout = timeout
        self.fd = None

    def __enter__(self):
        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.time() + self.timeout
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.time() >= deadline:
                    os.close(self.fd)
                    self.fd = None
                    raise RuntimeError(
                        f"занято другим процессом proxyveth (>{self.timeout}с). "
                        f"Смотри: systemctl status proxyveth-watchdog")
                time.sleep(0.5)

    def __exit__(self, *a):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None
        return False


# ════════════════════════════════════════════════════════════════════════════
#  Файлы и права
# ════════════════════════════════════════════════════════════════════════════
def _ensure_dirs():
    for d, mode in ((CONFIG_DIR, 0o700), (LOG_DIR, 0o700),
                    (SINGBOX_CONF_DIR, 0o700), (RUN_DIR, 0o700)):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, mode)
        except OSError:
            pass


def _write_private(path, text):
    """Пароли прокси не должны лежать в 0644."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


# ════════════════════════════════════════════════════════════════════════════
#  Сетевое окружение хоста
# ════════════════════════════════════════════════════════════════════════════
def wan_iface():
    """Раньше здесь было eth0 намертво. На Ubuntu 24.04/q35 это ens18 —
    и правило MASQUERADE молча никогда не срабатывало."""
    global _WAN_IFACE
    if _WAN_IFACE:
        return _WAN_IFACE
    env = os.getenv("ETH_WAN")
    if env:
        _WAN_IFACE = env
        return _WAN_IFACE
    r = shq(["ip", "-4", "route", "show", "default"])
    for line in r.stdout.splitlines():
        p = line.split()
        if "dev" in p:
            _WAN_IFACE = p[p.index("dev") + 1]
            return _WAN_IFACE
    _WAN_IFACE = "eth0"
    log_warn("не удалось определить WAN-интерфейс, взят eth0 — задай ETH_WAN в /etc/proxyveth/env")
    return _WAN_IFACE


def is_ns_exists(n):
    r = shq(["ip", "netns", "list"])
    for line in r.stdout.splitlines():
        if line.strip() and line.split()[0] == f"ns_{n}":
            return True
    return False


def active_ns_list():
    r = shq(["ip", "netns", "list"])
    out = []
    for line in r.stdout.splitlines():
        if not line.strip():
            continue
        name = line.split()[0]
        if name.startswith("ns_"):
            try:
                out.append(int(name.split("_", 1)[1]))
            except ValueError:
                pass
    return sorted(out)


def host_veth_names():
    """Наши veth-концы на хосте — по ТИПУ устройства, а не по имени.
    Иначе при VETH_PREFIX=eth проверки спутали бы настоящий eth0 с нашим eth5."""
    out = set()
    r = shq(["ip", "-o", "link", "show", "type", "veth"])
    for line in r.stdout.splitlines():
        f = line.split()
        if len(f) >= 2:
            out.add(f[1].rstrip(":").split("@")[0])
    return out


_HOST_NETS = None
_HOST_NETS_LOCK = threading.Lock()


def host_ipv4_nets(refresh=False):
    """Сети, реально настроенные на ВМ (без наших veth и tun)."""
    global _HOST_NETS
    with _HOST_NETS_LOCK:
        if _HOST_NETS is not None and not refresh:
            return _HOST_NETS
        veths = host_veth_names()
        nets = []
        r = shq(["ip", "-4", "-o", "addr", "show"])
        for line in r.stdout.splitlines():
            f = line.split()
            if len(f) < 4 or f[2] != "inet":
                continue
            iface = f[1]
            if iface == "lo" or iface in veths or iface.startswith("tun"):
                continue
            try:
                nets.append((iface, ipaddress.ip_network(f[3], strict=False)))
            except ValueError:
                continue
        _HOST_NETS = nets
        return _HOST_NETS


def ns_conflict(n):
    """Схема ProxyVeth занимает 192.168.N.0/24 на самом хосте. Если ВМ живёт
    в той же сети — появляется вторая connected-маршрутка на тот же префикс,
    и ВМ теряет связь с собственной LAN (в т.ч. SSH). Ловим ДО создания."""
    net = ipaddress.ip_network(f"192.168.{n}.0/24")
    for iface, hn in host_ipv4_nets():
        if net.overlaps(hn):
            return f"{hn} на {iface}"
    return None


def config_conflicts(config):
    out = []
    for n, _m in enabled_modems(config):
        c = ns_conflict(n)
        if c:
            out.append((n, c))
    return out


def resolve_host(host):
    """SOCKS5-хост обязан быть IP: на него ставится /32-маршрут в обход туннеля.
    Если в таблице имя — резолвим один раз здесь, на хосте."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except OSError as e:
        raise RuntimeError(f"не резолвится SOCKS5-хост {host!r}: {e}")


# ════════════════════════════════════════════════════════════════════════════
#  Конфиг
# ════════════════════════════════════════════════════════════════════════════
def load_config(required=True):
    if not CONFIG_FILE.exists():
        if not required:
            return {"modems": {}}
        log_fail(f"Конфиг не найден: {CONFIG_FILE}")
        log_info("Запусти: proxyveth sync")
        sys.exit(1)
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (OSError, ValueError) as e:
        log_fail(f"Конфиг битый ({e})")
        sys.exit(1)


def save_config(data):
    _ensure_dirs()
    _write_private(CONFIG_FILE, json.dumps(data, indent=2, ensure_ascii=False))


def enabled_modems(config):
    out = []
    for k, v in config.get("modems", {}).items():
        if v.get("enabled", True):
            try:
                out.append((int(k), v))
            except ValueError:
                continue
    return sorted(out, key=lambda x: x[0])


def get_modem(config, n):
    m = config.get("modems", {}).get(str(n))
    if not m:
        log_fail(f"Модем N={n} не найден в конфиге")
        sys.exit(1)
    return m


# ════════════════════════════════════════════════════════════════════════════
#  SYNC
# ════════════════════════════════════════════════════════════════════════════
def fetch_source_csv(attempts=3):
    if not SOURCE_URL and not SHEET_ID:
        log_fail("Не задан источник: API_URL или SHEET_CSV_URL (или SHEET_ID)")
        sys.exit(1)
    url = SOURCE_URL or (f"https://docs.google.com/spreadsheets/d/{SHEET_ID}"
                         f"/export?format=csv&gid={SHEET_GID}")
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "proxyveth/3.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read()
            break
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            last = e
            if i + 1 < attempts:
                time.sleep(2 * (i + 1))
    else:
        log_fail(f"Источник не отвечает: {last}")
        sys.exit(1)

    text = raw.decode("utf-8-sig", errors="replace")
    head = text.lstrip()[:200].lower()
    if head.startswith("<!doctype") or head.startswith("<html"):
        # Классика: у таблицы отозвали публикацию — Google отдаёт страницу логина.
        log_fail("Источник вернул HTML, а не CSV (публикация таблицы отозвана?)")
        sys.exit(1)
    return list(csv.reader(io.StringIO(text)))


_ALT_HEADERS = {"host": "proxy_host", "ip": "proxy_host", "server": "proxy_host",
                "port": "proxy_port", "user": "login", "username": "login",
                "pass": "password", "pwd": "password"}


def parse_rows(rows):
    if len(rows) < 2:
        raise ValueError("Таблица пустая")
    headers = []
    for h in rows[0]:
        h = h.strip().lower().replace(" ", "_")
        headers.append(_ALT_HEADERS.get(h, h))
    log_step(f"Заголовки: {headers}")

    proxy_idx = None
    for i, h in enumerate(headers):
        if h.startswith("proxy") and h not in ("proxy_host", "proxy_port"):
            proxy_idx = i
            break
    has_separate = all(h in headers for h in ("proxy_host", "proxy_port", "login", "password"))
    if proxy_idx is None and not has_separate:
        log_fail("Формат не распознан. Нужно (n, proxy) или (n, proxy_host, proxy_port, login, password)")
        sys.exit(1)

    modems, skipped, bad = {}, 0, []
    for row_idx, row in enumerate(rows[1:], start=2):
        # Одна кривая строка не должна ронять весь sync (в v2 роняла).
        try:
            if not row or not row[0].strip():
                skipped += 1
                continue
            rd = {headers[i]: row[i].strip() for i in range(min(len(headers), len(row)))}
            n = int(rd.get("n", "").strip())
            if not (N_MIN <= n <= N_MAX):
                bad.append(f"стр.{row_idx}: N={n} вне 1..{N_MAX}")
                continue
            if proxy_idx is not None:
                raw = row[proxy_idx].strip() if proxy_idx < len(row) else ""
                parts = raw.split(":")
                if len(parts) < 4:
                    bad.append(f"стр.{row_idx}: N={n} — формат не host:port:login:pass")
                    continue
                host, port, login = parts[0], parts[1], parts[2]
                password = ":".join(parts[3:])
            else:
                host = rd.get("proxy_host", "")
                port = rd.get("proxy_port", "")
                login = rd.get("login", "")
                password = rd.get("password", "")
            host, login = host.strip(), login.strip()
            port_i = int(str(port).strip())
            if not (0 < port_i < 65536):
                raise ValueError("порт вне диапазона")
            if not (host and login and password):
                bad.append(f"стр.{row_idx}: N={n} — пустое поле")
                continue
            if not re.fullmatch(r"[A-Za-z0-9._:\-]+", host):
                bad.append(f"стр.{row_idx}: N={n} — подозрительный host {host!r}")
                continue
            en = rd.get("enabled", "1").strip().lower() not in (
                "0", "false", "no", "off", "нет", "выкл", "disabled")
            if str(n) in modems:
                bad.append(f"стр.{row_idx}: N={n} — дубль, взята первая строка")
                continue
            modems[str(n)] = {"proxy_host": host, "proxy_port": port_i,
                              "login": login, "password": password, "enabled": en}
        except (ValueError, IndexError) as e:
            bad.append(f"стр.{row_idx}: {e}")
            skipped += 1

    for b in bad[:15]:
        log_warn(b)
    if len(bad) > 15:
        log_warn(f"...ещё {len(bad) - 15} проблемных строк")
    log_ok(f"Модемов: {len(modems)} | пропущено: {skipped + len(bad)}")
    return modems


def do_sync(quiet=False):
    if not quiet:
        header("SYNC: источник → config.json")
    modems = parse_rows(fetch_source_csv())
    if not modems:
        log_fail("Ни одного модема — конфиг не трогаю")
        sys.exit(1)
    if CONFIG_FILE.exists() and not quiet:
        old = load_config(required=False).get("modems", {})
        new_n, old_n = set(modems), set(old)
        if new_n - old_n:
            log_info(f"Новые: {sorted(int(x) for x in new_n - old_n)}")
        if old_n - new_n:
            log_warn(f"Пропали из таблицы: {sorted(int(x) for x in old_n - new_n)}")
    config = {"modems": modems,
              "last_sync": datetime.now().isoformat(timespec="seconds")}
    save_config(config)
    if not quiet:
        log_ok(f"Сохранено: {sum(1 for m in modems.values() if m.get('enabled', True))} активных")
    # Конфликт сетей показываем всегда, даже в quiet: он стоит потери связи с ВМ
    for n, c in config_conflicts(config):
        log_fail(f"КОНФЛИКТ СЕТЕЙ: модем N={n} → 192.168.{n}.0/24 пересекается с {c}")
        log_warn(f"  ns_{n} подниматься не будет. Варианты: увести ВМ в другую подсеть, "
                 f"выключить модем (enabled=0) или перенумеровать его.")
    return config


# ════════════════════════════════════════════════════════════════════════════
#  sing-box
# ════════════════════════════════════════════════════════════════════════════
def singbox_config(n, modem, proxy_ip):
    """
    DNS здесь — главное.
      • route.rules ловит всё, что sing-box распознал как DNS (протокол dns),
        и отдаёт внутреннему резолверу вместо того, чтобы гнать UDP наружу;
      • резолвер ходит tcp://1.1.1.1 ЧЕРЕЗ outbound proxy → имена резолвятся
        с exit-IP модема, а не дата-центра, и 3proxy не видит ни одного UDP;
      • strategy ipv4_only — SOCKS5 у 3proxy без IPv6, а AAAA-ответы дают
        долгие таймауты на каждом соединении.
    """
    return {
        "log": {"disabled": False, "level": SINGBOX_LOG_LEVEL,
                "output": str(singbox_log_path(n)), "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "remote", "address": f"tcp://{NS_DNS}", "detour": "proxy"},
                {"tag": "remote-alt", "address": f"tcp://{NS_DNS_ALT}", "detour": "proxy"},
            ],
            "rules": [],
            "final": "remote",
            "strategy": "ipv4_only",
            "disable_cache": False,
            "independent_cache": True,
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": f"tun{n}",
            "address": [f"10.0.{n}.1/30"],
            "mtu": 1420,
            "auto_route": False,
            "strict_route": False,
            "stack": "system",
            "sniff": True,
            "sniff_override_destination": True,
        }],
        "outbounds": [
            {
                "type": "socks",
                "tag": "proxy",
                "server": proxy_ip,
                "server_port": int(modem["proxy_port"]),
                "username": modem["login"],
                "password": modem["password"],
                "version": "5",
                "domain_strategy": "ipv4_only",
            },
            {"type": "dns", "tag": "dns-out"},
        ],
        "route": {
            "rules": [{"protocol": "dns", "outbound": "dns-out"}],
            "final": "proxy",
            "auto_detect_interface": False,
        },
    }


def singbox_conf_path(n):
    return SINGBOX_CONF_DIR / f"modem_{n}.json"


def singbox_log_path(n):
    return LOG_DIR / f"singbox_{n}.log"


def singbox_log_tail(n, lines=4):
    try:
        rows = singbox_log_path(n).read_text(errors="replace").strip().splitlines()
    except OSError:
        return ""
    return " | ".join(r.strip() for r in rows[-lines:] if r.strip())


def singbox_pidfile(n):
    return RUN_DIR / f"ns_{n}.pid"


def singbox_pid(n):
    """Живой pid или None. Зомби (cmdline пуст) считается мёртвым."""
    pf = singbox_pidfile(n)
    pid = None
    try:
        pid = int(pf.read_text().strip())
    except (OSError, ValueError):
        pid = None
    if pid and _pid_is_singbox(pid, n):
        return pid
    # Fallback: процесс пережил потерю pid-файла (рестарт скрипта, ручной запуск)
    r = shq(["pgrep", "-f", f"sing-box.*modem_{n}\\.json"])
    for line in r.stdout.split():
        try:
            cand = int(line)
        except ValueError:
            continue
        if _pid_is_singbox(cand, n):
            try:
                _write_private(pf, str(cand))
            except OSError:
                pass
            return cand
    return None


def _pid_is_singbox(pid, n):
    try:
        cmd = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", "replace")
    except OSError:
        return False
    return "sing-box" in cmd and f"modem_{n}.json" in cmd


def singbox_start(n, conf_path):
    """`ip netns exec` делает setns+exec, поэтому pid у Popen — это pid sing-box."""
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    p = subprocess.Popen(
        ["ip", "netns", "exec", f"ns_{n}", SINGBOX_BIN, "run", "-c", str(conf_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL, start_new_session=True)
    _write_private(singbox_pidfile(n), str(p.pid))
    return p.pid


def singbox_stop(n):
    pid = singbox_pid(n)
    if pid:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                break
            for _ in range(20):
                if not _pid_is_singbox(pid, n):
                    break
                time.sleep(0.1)
            if not _pid_is_singbox(pid, n):
                break
    singbox_pidfile(n).unlink(missing_ok=True)


def wait_tun(n, pid, timeout=TUN_TIMEOUT):
    """sing-box сам создаёт tunN и вешает адрес. Ждём, но не дольше, чем живёт процесс."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _pid_is_singbox(pid, n):
            return False
        r = shq(["ip", "-4", "addr", "show", f"tun{n}"], ns=n)
        if r.returncode == 0 and f"10.0.{n}.1" in r.stdout:
            return True
        time.sleep(0.4)
    return False


# ════════════════════════════════════════════════════════════════════════════
#  Namespace up/down
# ════════════════════════════════════════════════════════════════════════════
def veth_names(n):
    """(имя на хосте, имя внутри namespace)."""
    return f"{VETH_PREFIX}{n}", NS_IFACE


def legacy_host_ifaces(n):
    """Имена из прежних версий — чтобы down/cleanup подобрали хвосты."""
    return [f"veth{n}h", f"veth{n}n", f"veth_ext{n}_host", f"pvtmp{n}"]


def _sysctl(key, value, ns=None):
    shq(["sysctl", "-qw", f"{key}={value}"], ns=ns)


def ns_up(n, modem, verbose=True):
    proxy_ip = resolve_host(modem["proxy_host"])
    pp = int(modem["proxy_port"])
    rt = RT_TABLE_BASE + n
    vh, vn = veth_names(n)
    wan = wan_iface()

    if verbose:
        print(f"\n  {B}── NS {n} ──{R}  {modem['proxy_host']}:{pp}")

    conflict = ns_conflict(n)
    if conflict:
        log_fail(f"ns_{n}: сеть модема 192.168.{n}.0/24 пересекается с сетью ВМ "
                 f"({conflict}). Подъём отменён — иначе ВМ потеряет связь.")
        return False

    if is_ns_exists(n):
        # v2 здесь возвращал успех не глядя — сломанный NS числился поднятым.
        if ns_health(n) == "ok":
            if verbose:
                log_warn(f"ns_{n} уже поднят и здоров — пропуск")
            return True
        if verbose:
            log_warn(f"ns_{n} существует, но нездоров — пересобираю")
        ns_down(n, quiet=True)
        time.sleep(0.5)

    try:
        # 1. Namespace + свой resolv.conf.
        #    Адрес резолвера намеренно уходит в туннель — см. singbox_config().
        sh(["ip", "netns", "add", f"ns_{n}"])
        sh(["ip", "link", "set", "lo", "up"], ns=n)
        ns_etc = Path(f"/etc/netns/ns_{n}")
        ns_etc.mkdir(parents=True, exist_ok=True)
        (ns_etc / "resolv.conf").write_text(
            f"# proxyveth: резолвится sing-box'ом через SOCKS5, не через хост\n"
            f"nameserver {NS_DNS}\n"
            f"nameserver {NS_DNS_ALT}\n"
            f"options timeout:3 attempts:2 single-request\n")

        # 2. veth-пара. Хост: ethN. Внутри ns: eth0.
        #    Peer рождается под временным именем и переименовывается уже внутри
        #    namespace: в момент создания оба конца лежат в корневом namespace
        #    и не могут называться одинаково. Переименование возможно только
        #    пока интерфейс down — поэтому до `ip link set ... up`.
        vtmp = f"pvtmp{n}"
        shq(["ip", "link", "del", vtmp])          # хвост от прошлого падения
        sh(["ip", "link", "add", vh, "type", "veth", "peer", "name", vtmp])
        sh(["ip", "link", "set", vtmp, "netns", f"ns_{n}"])
        sh(["ip", "link", "set", vtmp, "name", vn], ns=n)
        sh(["ip", "addr", "add", f"192.168.{n}.100/24", "dev", vh])
        sh(["ip", "link", "set", vh, "up"])
        sh(["ip", "addr", "add", f"192.168.{n}.254/24", "dev", vn], ns=n)
        sh(["ip", "link", "set", vn, "up"], ns=n)
        # rp_filter при policy routing тихо режет обратный трафик
        _sysctl(f"net.ipv4.conf.{vh}.rp_filter", 0)
        _sysctl(f"net.ipv4.conf.{vn}.rp_filter", 0, ns=n)
        if verbose:
            log_step(f"ns_{n}: veth OK")

        # 3. sing-box (учётки лежат в файле 0600, а не в ps aux)
        conf = singbox_config(n, modem, proxy_ip)
        conf_path = singbox_conf_path(n)
        _write_private(conf_path, json.dumps(conf, indent=2))
        singbox_log_path(n).unlink(missing_ok=True)   # лог только текущей попытки
        pid = singbox_start(n, conf_path)
        if not wait_tun(n, pid):
            # Сообщение должно быть самодостаточным: конфиг ниже удалит ns_down,
            # и «проверь файл X» станет бесполезным советом.
            tail = singbox_log_tail(n)
            chk = shq([SINGBOX_BIN, "check", "-c", str(conf_path)], timeout=15)
            reason = tail or (chk.stderr or chk.stdout).strip().replace("\n", " ")
            raise RuntimeError(f"tun{n} не поднялся за {TUN_TIMEOUT}с"
                               + (f" — sing-box: {reason[:300]}" if reason
                                  else " (sing-box молчит, лог пуст)"))
        if verbose:
            log_step(f"ns_{n}: sing-box OK (pid {pid})")

        # 4. Маршруты внутри ns
        sh(["ip", "route", "add", "default", "dev", f"tun{n}"], ns=n)
        sh(["ip", "route", "add", f"192.168.{n}.1/32", "dev", f"tun{n}"], ns=n)  # Huawei API
        # Единственное исключение из туннеля — сам SOCKS5-хост, иначе sing-box
        # заворачивает собственный аплинк сам в себя.
        sh(["ip", "route", "add", f"{proxy_ip}/32", "via", f"192.168.{n}.100"], ns=n)
        # DNS-исключений больше НЕТ: 8.8.8.8/32 via host давал петлю ns↔host.

        # 5. iptables внутри ns
        _sysctl("net.ipv4.ip_forward", 1, ns=n)
        # DNS в туннель пускаем — его съедает сам sing-box и отвечает по TCP.
        for chain in ("OUTPUT", "FORWARD"):
            ipt_ins([chain, "-o", f"tun{n}", "-p", "udp", "--dport", "53", "-j", "ACCEPT"], ns=n)
        # Остальной UDP режем: mproxy иначе заливает 3proxy тысячами пакетов/сек.
        for chain in ("OUTPUT", "FORWARD"):
            ipt_add([chain, "-o", f"tun{n}", "-p", "udp", "-j", "DROP"], ns=n)
        ipt_add(["POSTROUTING", "-o", f"tun{n}", "-j", "MASQUERADE"], ns=n, table="nat")
        ipt_add(["FORWARD", "-i", vn, "-o", f"tun{n}", "-j", "ACCEPT"], ns=n)
        ipt_add(["FORWARD", "-i", f"tun{n}", "-o", vn, "-j", "ACCEPT"], ns=n)
        # MSS clamp: через SOCKS5+tun крупные пакеты иначе теряются молча.
        # Не критично — если модуля TCPMSS нет, работаем без него.
        ipt_add(["FORWARD", "-o", f"tun{n}", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                 "-j", "TCPMSS", "--clamp-mss-to-pmtu"], ns=n, check=False)

        # 6. Хост: NAT для bypass-трафика + source routing
        with _HOST_LOCK:
            ipt_add(["POSTROUTING", "-s", f"192.168.{n}.0/24",
                     "-o", wan, "-j", "MASQUERADE"], table="nat")
            shq(["ip", "rule", "del", "from", f"192.168.{n}.100", "table", str(rt)])
            sh(["ip", "rule", "add", "from", f"192.168.{n}.100", "table", str(rt)])
            shq(["ip", "route", "flush", "table", str(rt)])
            sh(["ip", "route", "add", "default", "via", f"192.168.{n}.254",
                "dev", vh, "table", str(rt)])

        if verbose:
            log_ok(f"ns_{n} ГОТОВ | 192.168.{n}.100 → {proxy_ip}:{pp} | Huawei: 192.168.{n}.1")
        return True
    except Exception as e:
        log_fail(f"ns_{n}: {e}")
        try:
            ns_down(n, quiet=True)
        except Exception:
            pass
        return False


def ns_down(n, quiet=False):
    if not quiet:
        print(f"  {D}↓ ns_{n}{R}", end="", flush=True)
    rt = RT_TABLE_BASE + n
    vh, _ = veth_names(n)
    wan = wan_iface()

    singbox_stop(n)
    shq(["ip", "netns", "del", f"ns_{n}"])
    shq(["ip", "link", "del", vh])
    for old in legacy_host_ifaces(n):     # хвосты прежних схем именования
        if old != vh:
            shq(["ip", "link", "del", old])
    with _HOST_LOCK:
        while shq(["ip", "rule", "del", "from", f"192.168.{n}.100",
                   "table", str(rt)]).returncode == 0:
            pass
        shq(["ip", "route", "flush", "table", str(rt)])
        ipt_del(["POSTROUTING", "-s", f"192.168.{n}.0/24",
                 "-o", wan, "-j", "MASQUERADE"], table="nat")
    ns_etc = Path(f"/etc/netns/ns_{n}")
    if ns_etc.is_dir():
        shutil.rmtree(ns_etc, ignore_errors=True)
    singbox_conf_path(n).unlink(missing_ok=True)
    singbox_pidfile(n).unlink(missing_ok=True)
    if not quiet:
        print(f" {G}✓{R}")


def ns_health(n):
    """Быстрая проверка без сети."""
    if not is_ns_exists(n):
        return "ns_missing"
    if not singbox_pid(n):
        return "singbox_dead"
    r = shq(["ip", "-4", "addr", "show", f"tun{n}"], ns=n)
    if r.returncode != 0 or f"10.0.{n}.1" not in r.stdout:
        return "tun_missing"
    r = shq(["ip", "route", "show", "default"], ns=n)
    if f"tun{n}" not in r.stdout:
        return "route_missing"
    r = shq(["ip", "rule", "show"])
    if f"192.168.{n}.100" not in r.stdout:
        return "rule_missing"
    return "ok"


def ns_wan_ip(n):
    r = shq(["curl", "-s", "-4", "--max-time", str(CURL_TIMEOUT),
             "http://ip-api.com/line/?fields=query"], ns=n, timeout=CURL_TIMEOUT + 5)
    ip = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return ""


def ns_dns_ok(n, name="ip-api.com"):
    """Проверяет именно DNS: резолв идёт через sing-box, в обход хоста."""
    r = shq(["getent", "ahostsv4", name], ns=n, timeout=15)
    return r.returncode == 0 and bool(r.stdout.strip())


# ════════════════════════════════════════════════════════════════════════════
#  Команды: up / down / restart
# ════════════════════════════════════════════════════════════════════════════
def _parallel(items, fn):
    if len(items) <= 1 or WORKERS <= 1:
        return [fn(i) for i in items]
    with ThreadPoolExecutor(max_workers=min(WORKERS, len(items))) as ex:
        return list(ex.map(fn, items))


def _up_many(modems):
    """Параллельный подъём с построчным прогрессом вместо каши из 8 потоков."""
    total = len(modems)
    done = [0]

    def worker(pair):
        n, m = pair
        res = ns_up(n, m, verbose=False)
        with _PRINT_LOCK:
            done[0] += 1
            mark = f"{G}✓{R}" if res else f"{RD}✗{R}"
            print(f"  {mark} [{done[0]:>3}/{total}] ns_{n}")
        return res

    return _parallel(modems, worker)


def cmd_up(target):
    config = load_config()
    cmd_init(quiet=True)
    host_ipv4_nets(refresh=True)
    with Lock():
        if target == "all":
            header("UP ALL")
            modems = enabled_modems(config)
            log_info(f"Модемов: {len(modems)}, потоков: {min(WORKERS, max(1, len(modems)))}")
            t0 = time.time()
            res = _up_many(modems)
            ok = sum(1 for x in res if x)
            header(f"РЕЗУЛЬТАТ: {ok} ✓ поднято, {len(res) - ok} ✗ ошибок ({time.time() - t0:.0f}с)")
            if ok < len(res):
                log_info("Разбор по одному:  proxyveth check N   |   proxyveth problems")
            return 0 if ok == len(res) else 1
        n = int(target)
        return 0 if ns_up(n, get_modem(config, n)) else 1


def cmd_down(target):
    with Lock():
        if target == "all":
            header("DOWN ALL")
            ns_list = active_ns_list()
            if not ns_list:
                log_info("Нет активных NS")
                return 0
            _parallel(ns_list, lambda n: ns_down(n, quiet=True))
            log_ok(f"Удалено: {len(ns_list)}")
            return 0
        ns_down(int(target))
        return 0


def cmd_restart(target):
    config = load_config()
    with Lock():
        if target == "all":
            header("RESTART ALL")
            ns_list = active_ns_list()
            _parallel(ns_list, lambda n: ns_down(n, quiet=True))
            time.sleep(1)
            res = _up_many(enabled_modems(config))
            ok = sum(1 for x in res if x)
            header(f"РЕЗУЛЬТАТ: {ok}/{len(res)}")
            return 0 if ok == len(res) else 1
        n = int(target)
        ns_down(n)
        time.sleep(1)
        return 0 if ns_up(n, get_modem(config, n)) else 1


# ════════════════════════════════════════════════════════════════════════════
#  Команды: status / check / problems
# ════════════════════════════════════════════════════════════════════════════
_STATUS_TEXT = {
    "ok": "ок",
    "ns_missing": "нет namespace",
    "singbox_dead": "sing-box не запущен",
    "tun_missing": "нет tun-интерфейса",
    "route_missing": "нет default через tun",
    "rule_missing": "нет ip rule на хосте",
    "disabled": "выключен в таблице",
}


def collect_status(config, check_wan=False):
    modems = config.get("modems", {})
    active = set(active_ns_list())
    rows = []

    def one(item):
        n_str, m = item
        n = int(n_str)
        if not m.get("enabled", True):
            return {"n": n, "proxy": f"{m['proxy_host']}:{m['proxy_port']}",
                    "state": "disabled", "wan": "", "up": False}
        state = ns_health(n) if n in active else "ns_missing"
        wan = ns_wan_ip(n) if (check_wan and state == "ok") else ""
        return {"n": n, "proxy": f"{m['proxy_host']}:{m['proxy_port']}",
                "state": state, "wan": wan, "up": state == "ok"}

    items = sorted(modems.items(), key=lambda kv: int(kv[0]))
    rows = _parallel(items, one) if check_wan else [one(i) for i in items]
    return sorted(rows, key=lambda r: r["n"])


def cmd_status(check_wan=False, as_json=False):
    config = load_config()
    rows = collect_status(config, check_wan=check_wan)
    if as_json:
        print(json.dumps({"last_sync": config.get("last_sync"),
                          "wan_iface": wan_iface(),
                          "modems": rows}, ensure_ascii=False, indent=2))
        return 0

    header("STATUS")
    wh = f" │ {'WAN IP':^15}" if check_wan else ""
    print(f"\n  {'N':>3} │ {'Proxy':^28} │ {'Состояние':^22}{wh}")
    print(f"  {'─' * 3}─┼─{'─' * 28}─┼─{'─' * 22}"
          + (f"─┼─{'─' * 15}" if check_wan else ""))
    up = down = dis = 0
    for r in rows:
        if r["state"] == "disabled":
            dis += 1
            col, txt = D, _STATUS_TEXT["disabled"]
        elif r["up"]:
            up += 1
            col, txt = G, _STATUS_TEXT["ok"]
        else:
            down += 1
            col, txt = RD, _STATUS_TEXT.get(r["state"], r["state"])
        w = f" │ {(r['wan'] or '—'):<15}" if check_wan else ""
        print(f"  {r['n']:>3} │ {r['proxy']:<28} │ {col}{txt:<22}{R}{w}")
    print()
    log_info(f"UP:{up}  DOWN:{down}  Выключено:{dis}  Всего:{len(rows)}")
    log_info(f"WAN-интерфейс хоста: {wan_iface()}")
    if config.get("last_sync"):
        log_info(f"Sync: {config['last_sync']}")
    return 0 if down == 0 else 1


def cmd_problems():
    """«Покажи проблемные модемы» — то, ради чего обычно и заходят."""
    config = load_config()
    rows = [r for r in collect_status(config, check_wan=True)
            if r["state"] != "disabled" and (not r["up"] or not r["wan"])]
    header("ПРОБЛЕМНЫЕ МОДЕМЫ")
    if not rows:
        log_ok("Проблемных нет")
        return 0
    for r in rows:
        reason = _STATUS_TEXT.get(r["state"], r["state"])
        if r["up"] and not r["wan"]:
            reason = "namespace живой, но WAN не отвечает (модем/прокси)"
        log_fail(f"N={r['n']:<4} {r['proxy']:<28} {reason}")
    log_info(f"Итого проблемных: {len(rows)}. Подробности: proxyveth check N")
    return 1


def cmd_check(n):
    n = int(n)
    config = load_config()
    modem = get_modem(config, n)
    proxy_ip = resolve_host(modem["proxy_host"])
    rt = RT_TABLE_BASE + n
    vh, vn = veth_names(n)
    header(f"CHECK ns_{n}  ({modem['proxy_host']}:{modem['proxy_port']})")
    bad = 0

    def chk(label, cond, extra=""):
        nonlocal bad
        if cond:
            log_ok(f"{label} {extra}".rstrip())
        else:
            log_fail(f"{label} {extra}".rstrip())
            bad += 1
        return cond

    log_info(f"Интерфейсы: хост {vh}  ↔  внутри ns {vn}")
    conflict = ns_conflict(n)
    if conflict:
        log_fail(f"сеть 192.168.{n}.0/24 пересекается с сетью ВМ ({conflict}) — "
                 f"этот модем принципиально не поднимется на этой ВМ")
        return 1
    if not chk("namespace ns_%d" % n, is_ns_exists(n)):
        log_info(f"Поднять: proxyveth up {n}")
        return 1
    pid = singbox_pid(n)
    chk("sing-box", bool(pid), f"pid={pid}" if pid else "не запущен")
    r = shq(["ip", "-4", "addr", "show", f"tun{n}"], ns=n)
    chk(f"tun{n}", r.returncode == 0 and f"10.0.{n}.1" in r.stdout)
    r = shq(["ip", "route", "show"], ns=n)
    chk("default → tun", f"default dev tun{n}" in r.stdout)
    chk("маршрут Huawei API", f"192.168.{n}.1" in r.stdout)
    chk("bypass до SOCKS5", proxy_ip in r.stdout, f"({proxy_ip})")
    chk("DNS-исключений нет", NS_DNS not in r.stdout,
        "— резолв идёт через туннель, как и должно")
    r = shq(["ip", "rule", "show"])
    chk("ip rule на хосте", f"192.168.{n}.100" in r.stdout, f"table {rt}")
    r = shq(["ip", "route", "show", "table", str(rt)])
    chk(f"таблица {rt}", "default" in r.stdout)
    chk("MASQUERADE на хосте",
        ipt_has(["POSTROUTING", "-s", f"192.168.{n}.0/24",
                 "-o", wan_iface(), "-j", "MASQUERADE"], table="nat"),
        f"({wan_iface()})")
    chk("MASQUERADE внутри ns",
        ipt_has(["POSTROUTING", "-o", f"tun{n}", "-j", "MASQUERADE"], ns=n, table="nat"))

    log_step("DNS внутри namespace...")
    chk("резолв через туннель", ns_dns_ok(n))
    log_step("WAN IP через модем...")
    wan = ns_wan_ip(n)
    chk("выход в интернет", bool(wan), wan or "нет ответа")
    log_step("Huawei API...")
    r = shq(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "6",
             f"http://192.168.{n}.1/api/webserver/SesTokInfo"], ns=n, timeout=12)
    chk("веб-морда модема", r.stdout.strip() == "200", f"HTTP {r.stdout.strip() or '—'}")

    r = shq(["curl", "-s", "-4", "--max-time", "8",
             "--interface", f"192.168.{n}.100", "http://ip-api.com/line/?fields=query"],
            timeout=15)
    host_view = r.stdout.strip()
    chk("хост видит модем (source routing)", bool(host_view), host_view or "нет ответа")
    if wan and host_view and wan != host_view:
        log_warn(f"WAN из ns ({wan}) ≠ WAN с хоста ({host_view}) — трафик утекает мимо туннеля")
        bad += 1

    print()
    if bad:
        log_fail(f"Проблем: {bad}")
    else:
        log_ok("Всё в порядке")
    return 1 if bad else 0


# ════════════════════════════════════════════════════════════════════════════
#  Watchdog
# ════════════════════════════════════════════════════════════════════════════
def _reap():
    """sing-box'ы — прямые дети watchdog-процесса; не подбирать = зомби."""
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except (ChildProcessError, OSError):
            return
        if pid == 0:
            return


def watchdog_pass(pass_number):
    # Конфиг перечитываем КАЖДЫЙ проход: autosync правит его параллельно,
    # в v2 watchdog поднимал модемы со старыми учётками.
    config = load_config(required=False)
    modems = enabled_modems(config)
    host_ipv4_nets(refresh=True)   # сеть ВМ могла смениться между проходами
    check_wan = WATCHDOG_WAN_EVERY > 0 and pass_number % WATCHDOG_WAN_EVERY == 0

    rc_file = CONFIG_DIR / "restart_counts.json"
    counts = {}
    if rc_file.exists():
        try:
            counts = json.loads(rc_file.read_text())
        except (OSError, ValueError):
            counts = {}

    ok = restarted = failed = 0
    for n, modem in modems:
        state = ns_health(n)
        if state == "ok" and check_wan and not ns_wan_ip(n):
            state = "wan_dead"
        if state == "ok":
            ok += 1
            counts.pop(str(n), None)
            continue
        tries = counts.get(str(n), 0)
        if tries >= WATCHDOG_MAX_RESTART:
            failed += 1
            continue
        wlog(f"  ⚠ ns_{n}: {_STATUS_TEXT.get(state, state)} — "
             f"перезапуск ({tries + 1}/{WATCHDOG_MAX_RESTART})")
        ns_down(n, quiet=True)
        time.sleep(1)
        if ns_up(n, modem, verbose=False):
            restarted += 1
            counts.pop(str(n), None)
        else:
            failed += 1
            counts[str(n)] = tries + 1
    try:
        _write_private(rc_file, json.dumps(counts))
    except OSError:
        pass
    return ok, restarted, failed


def cmd_watchdog():
    header("WATCHDOG (один проход)")
    with Lock():
        ok, re_, fa = watchdog_pass(1)
    log_info(f"OK:{ok}  Перезапущено:{re_}  Ошибок:{fa}")
    return 1 if fa else 0


def cmd_watchdog_loop():
    wlog(f"ProxyVeth watchdog запущен (интервал {WATCHDOG_INTERVAL}с, WAN каждые {WATCHDOG_WAN_EVERY})")
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    p = 0
    while not stop.is_set():
        p += 1
        try:
            with Lock(timeout=30):
                ok, re_, fa = watchdog_pass(p)
            if re_ or fa:
                wlog(f"Проход #{p}: OK={ok} перезапущено={re_} ошибок={fa}")
            elif p % 10 == 0:
                wlog(f"Проход #{p}: все {ok} OK")
        except Exception as e:
            wlog(f"Проход #{p} ОШИБКА: {e}")
        _reap()
        stop.wait(WATCHDOG_INTERVAL)
    wlog("ProxyVeth watchdog остановлен")
    return 0


# ════════════════════════════════════════════════════════════════════════════
#  Autosync
# ════════════════════════════════════════════════════════════════════════════
def cmd_autosync():
    old = load_config(required=False).get("modems", {})
    new = do_sync(quiet=True).get("modems", {})

    to_add = set(new) - set(old)
    to_remove = set(old) - set(new)
    to_restart = set()
    for k in set(old) & set(new):
        o, n2 = old[k], new[k]
        if any(o.get(f) != n2.get(f) for f in ("proxy_host", "proxy_port", "login", "password")):
            to_restart.add(k)
        if not n2.get("enabled", True) and o.get("enabled", True):
            to_remove.add(k); to_restart.discard(k)
        if n2.get("enabled", True) and not o.get("enabled", True):
            to_add.add(k); to_restart.discard(k)

    if not (to_add or to_remove or to_restart):
        return 0

    # Предохранитель против «поправил таблицу — разобрал прод».
    live = max(1, len([k for k, v in old.items() if v.get("enabled", True)]))
    pct = 100 * len(to_remove) / live
    if len(to_remove) > 1 and pct > AUTOSYNC_MAX_REMOVE_PCT:
        wlog(f"AUTOSYNC: отказ — источник просит снять {len(to_remove)} из {live} "
             f"NS ({pct:.0f}% > {AUTOSYNC_MAX_REMOVE_PCT}%). Похоже на сломанный источник.")
        wlog(f"AUTOSYNC: снятие пропущено, добавления/перезапуски выполняю. "
             f"Если это осознанно — proxyveth restart all")
        to_remove = set()

    wlog(f"AUTOSYNC: +{len(to_add)} -{len(to_remove)} ~{len(to_restart)}")
    with Lock():
        for k in sorted(to_remove, key=int):
            n = int(k)
            if is_ns_exists(n):
                wlog(f"  СНЯТЬ ns_{n}")
                ns_down(n, quiet=True)
        for k in sorted(to_restart, key=int):
            n, m = int(k), new[k]
            if m.get("enabled", True):
                wlog(f"  ПЕРЕСОБРАТЬ ns_{n}")
                ns_down(n, quiet=True)
                time.sleep(0.5)
                ns_up(n, m, verbose=False)
        for k in sorted(to_add, key=int):
            n, m = int(k), new[k]
            if m.get("enabled", True) and not is_ns_exists(n):
                wlog(f"  ДОБАВИТЬ ns_{n}")
                ns_up(n, m, verbose=False)
    wlog("AUTOSYNC завершён")
    return 0


# ════════════════════════════════════════════════════════════════════════════
#  install / init / cleanup / doctor
# ════════════════════════════════════════════════════════════════════════════
def _apt(args):
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    cmd = ["apt-get", "-o", "DPkg::Lock::Timeout=300", "-qq"] + list(args)
    p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=900)
    if p.returncode != 0:
        raise RuntimeError(f"apt-get {' '.join(args)}: {p.stderr.strip()[:200]}")
    return p


SYSCTL_FILE = Path("/etc/sysctl.d/99-proxyveth.conf")
SYSCTL_BODY = """# proxyveth
net.ipv4.ip_forward = 1
# policy routing + NAT: строгий rp_filter молча режет обратный трафик
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
"""


def cmd_install():
    header("INSTALL")
    _ensure_dirs()
    log_step("apt...")
    _apt(["update"])
    _apt(["install", "-y", "wget", "curl", "iproute2", "iptables",
          "python3", "ca-certificates", "psmisc"])
    log_ok("Пакеты установлены")

    SYSCTL_FILE.write_text(SYSCTL_BODY)
    shq(["sysctl", "-q", "--system"])
    log_ok("sysctl: ip_forward=1, rp_filter=0")

    if not Path("/dev/net/tun").exists():
        log_fail("/dev/net/tun не найден — sing-box работать не будет")
    else:
        log_ok("/dev/net/tun OK")

    if Path(SINGBOX_BIN).exists() and shq([SINGBOX_BIN, "version"]).returncode == 0:
        ver = shq([SINGBOX_BIN, "version"]).stdout.strip().splitlines()[0]
        log_ok(f"sing-box уже стоит: {ver}")
    else:
        log_step(f"Скачиваем sing-box v{SINGBOX_VER}...")
        tgz = "/tmp/sing-box.tar.gz"
        tmpd = "/tmp/sing-box-unpack"
        shutil.rmtree(tmpd, ignore_errors=True)
        os.makedirs(tmpd, exist_ok=True)
        sh(["wget", "-q", "-O", tgz, SINGBOX_URL], timeout=300)
        sh(["tar", "-xzf", tgz, "-C", tmpd], timeout=120)
        found = glob.glob(f"{tmpd}/**/sing-box", recursive=True)
        if not found:
            raise RuntimeError("в архиве нет бинарника sing-box")
        shutil.move(found[0], SINGBOX_BIN)
        os.chmod(SINGBOX_BIN, 0o755)
        shutil.rmtree(tmpd, ignore_errors=True)
        Path(tgz).unlink(missing_ok=True)
        if shq([SINGBOX_BIN, "version"]).returncode != 0:
            raise RuntimeError("скачанный sing-box не запускается")
        log_ok(f"sing-box v{SINGBOX_VER} установлен")

    link = Path("/usr/local/bin/proxyveth")
    if SCRIPT_PATH.exists():
        try:
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(SCRIPT_PATH)
        except OSError:
            pass
    log_ok(f"WAN-интерфейс: {wan_iface()}")
    return 0


def cmd_init(quiet=False):
    if not quiet:
        header("INIT")
    if not Path("/dev/net/tun").exists():
        log_fail("/dev/net/tun не найден")
        sys.exit(1)
    _ensure_dirs()
    _sysctl("net.ipv4.ip_forward", 1)
    _sysctl("net.ipv4.conf.all.rp_filter", 0)
    _sysctl("net.ipv4.conf.default.rp_filter", 0)
    if not quiet:
        log_ok(f"ip_forward=1, rp_filter=0, WAN={wan_iface()}")
    return 0


def cmd_cleanup():
    header("CLEANUP")
    with Lock():
        for n in active_ns_list():
            ns_down(n, quiet=True)
        # Раньше здесь был iptables -t nat -F — он сносил и правила mp.space.
        # Удаляем ровно те строки, что показал -S, а не «похожие»: интерфейс
        # в старом правиле мог быть другим (переименовали, сменили WAN).
        r = shq(["iptables", "-w", "5", "-t", "nat", "-S", "POSTROUTING"])
        removed = 0
        for line in r.stdout.splitlines():
            if not line.startswith("-A POSTROUTING") or "MASQUERADE" not in line:
                continue
            if not re.search(r"-s 192\.168\.\d+\.0/24\b", line):
                continue
            try:
                spec = shlex.split(line)[1:]      # выкидываем -A
            except ValueError:
                continue
            if ipt(["-D"] + spec, table="nat", check=False).returncode == 0:
                removed += 1
        # Осиротевшие veth (в т.ч. под именами прежних версий). Ищем по типу
        # устройства, поэтому настоящий eth0 сюда не попадёт при VETH_PREFIX=eth.
        pat = re.compile(rf"^(?:{re.escape(VETH_PREFIX)}|pvtmp)\d+$"
                         rf"|^veth\d+[hn]$|^veth_ext\d+_host$")
        for name in host_veth_names():
            if pat.match(name):
                shq(["ip", "link", "del", name])
        for path in glob.glob("/etc/netns/ns_*"):
            shutil.rmtree(path, ignore_errors=True)
        for f in SINGBOX_CONF_DIR.glob("modem_*.json"):
            f.unlink(missing_ok=True)
        for f in RUN_DIR.glob("ns_*.pid"):
            f.unlink(missing_ok=True)
        (CONFIG_DIR / "restart_counts.json").unlink(missing_ok=True)
    log_ok(f"Очистка завершена (снято правил NAT: {removed})")
    return 0


def cmd_rescue():
    """Аварийный выход: снять всё своё и отключить автозапуск.
    Ровно для случая «ВМ потеряла сеть, зашёл через qm guest exec»."""
    header("RESCUE")
    log_warn("Снимаю все namespace и отключаю автозапуск proxyveth")
    for unit in ("proxyveth-watchdog.service", "proxyveth-autosync.timer",
                 "proxyveth-autosync.service", "proxyveth.service"):
        shq(["systemctl", "disable", "--now", unit], timeout=120)
    cmd_cleanup()
    log_ok("Готово — сеть ВМ должна вернуться в исходное состояние")
    log_info("Включить обратно:  proxyveth systemd && proxyveth up all")
    return 0


def cmd_doctor():
    header("DOCTOR")
    bad = 0

    def chk(label, cond, extra=""):
        nonlocal bad
        (log_ok if cond else log_fail)(f"{label} {extra}".rstrip())
        if not cond:
            bad += 1
        return cond

    chk("/dev/net/tun", Path("/dev/net/tun").exists())
    chk("sing-box", Path(SINGBOX_BIN).exists() and shq([SINGBOX_BIN, "version"]).returncode == 0,
        shq([SINGBOX_BIN, "version"]).stdout.strip().splitlines()[0]
        if Path(SINGBOX_BIN).exists() else "не установлен")
    r = shq(["sysctl", "-n", "net.ipv4.ip_forward"])
    chk("ip_forward", r.stdout.strip() == "1")
    chk("iptables, таблица nat", shq(["iptables", "-w", "5", "-t", "nat", "-S"]).returncode == 0)
    chk("модуль TCPMSS",
        ipt(["-C", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
             "-j", "TCPMSS", "--clamp-mss-to-pmtu"], check=False).returncode in (0, 1),
        "(необязателен)")
    chk("WAN-интерфейс определён", wan_iface() != "eth0" or
        shq(["ip", "link", "show", "eth0"]).returncode == 0, f"({wan_iface()})")

    # DNS хоста — отдельным блоком, это исторически самая больная точка
    log_step("DNS хоста...")
    rc = Path("/etc/resolv.conf")
    chk("resolv.conf не immutable",
        "i" not in (shq(["lsattr", "-l", "/etc/resolv.conf"]).stdout or ""),
        "" if rc.exists() else "(файла нет)")
    ok_names = 0
    for name in ("github.com", "docs.google.com"):
        if shq(["getent", "ahostsv4", name], timeout=15).returncode == 0:
            ok_names += 1
    chk("хост резолвит имена", ok_names == 2, f"{ok_names}/2")

    log_info(f"Имена интерфейсов: хост {VETH_PREFIX}N, внутри namespace {NS_IFACE}")
    nets = ", ".join(f"{i}:{s}" for i, s in host_ipv4_nets(refresh=True)) or "нет"
    log_info(f"Сети самой ВМ: {nets}")

    chk("конфиг существует", CONFIG_FILE.exists(), str(CONFIG_FILE))
    if CONFIG_FILE.exists():
        mode = oct(CONFIG_FILE.stat().st_mode & 0o777)
        chk("права на конфиг", CONFIG_FILE.stat().st_mode & 0o077 == 0, mode)
        confl = config_conflicts(load_config(required=False))
        chk("сети модемов не пересекаются с сетью ВМ", not confl,
            ("конфликтуют N=" + ",".join(str(n) for n, _ in confl)) if confl else "")
    chk("источник задан", bool(SOURCE_URL or SHEET_ID),
        (SOURCE_URL[:50] + "...") if SOURCE_URL else "")

    for unit in ("proxyveth.service", "proxyveth-watchdog.service", "proxyveth-autosync.timer"):
        st = shq(["systemctl", "is-enabled", unit]).stdout.strip() or "нет"
        chk(f"unit {unit}", st == "enabled", st)

    ns_list = active_ns_list()
    log_info(f"Активных namespace: {len(ns_list)}")
    if ns_list:
        n = ns_list[0]
        log_step(f"Пробный DNS в ns_{n} (должен идти через туннель)...")
        chk(f"DNS внутри ns_{n}", ns_dns_ok(n))
    print()
    (log_fail if bad else log_ok)(f"Проблем: {bad}" if bad else "Всё в порядке")
    return 1 if bad else 0


# ════════════════════════════════════════════════════════════════════════════
#  systemd
# ════════════════════════════════════════════════════════════════════════════
UNITS = {
    "proxyveth.service": """[Unit]
Description=ProxyVeth - SOCKS5 to veth for mp.space
After=network-online.target
Wants=network-online.target
After=mproxy.service nodejs-server.service

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=-{env}
ExecStart={py} {script} init
# «-» намеренно: при 80 модемах один недоступный не должен помечать юнит
# как failed — иначе watchdog, который и должен его чинить, не стартует вовсе.
ExecStart=-{py} {script} up all
ExecStop={py} {script} down all
TimeoutStartSec=900
TimeoutStopSec=300

[Install]
WantedBy=multi-user.target
""",
    "proxyveth-watchdog.service": """[Unit]
Description=ProxyVeth Watchdog
After=proxyveth.service
Wants=proxyveth.service

[Service]
Type=simple
EnvironmentFile=-{env}
ExecStart={py} {script} watchdog-loop
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
""",
    "proxyveth-autosync.service": """[Unit]
Description=ProxyVeth Autosync
After=proxyveth.service

[Service]
Type=oneshot
EnvironmentFile=-{env}
ExecStart={py} {script} autosync
TimeoutStartSec=600
""",
    "proxyveth-autosync.timer": """[Unit]
Description=ProxyVeth Autosync every 5 min

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
""",
}


def cmd_systemd():
    header("SYSTEMD")
    ctx = {"py": "/usr/bin/python3", "script": str(SCRIPT_PATH), "env": str(ENV_FILE)}
    for name, body in UNITS.items():
        Path(f"/etc/systemd/system/{name}").write_text(body.format(**ctx))
    sh(["systemctl", "daemon-reload"])
    for unit in ("proxyveth.service", "proxyveth-watchdog.service", "proxyveth-autosync.timer"):
        sh(["systemctl", "enable", unit])
    log_ok("Юниты записаны и включены")
    return 0


def cmd_setup():
    header("ProxyVeth — установка")
    if not (SOURCE_URL or SHEET_ID):
        log_fail("Не задан источник конфигурации")
        log_info(f"Пропиши в {ENV_FILE}:  SHEET_CSV_URL=https://docs.google.com/...")
        return 1
    cmd_install()
    do_sync()
    cmd_init()
    cmd_up("all")
    cmd_systemd()
    active = len(active_ns_list())
    total = len(enabled_modems(load_config()))
    print(f"\n{G}{'═' * 62}\n  ProxyVeth установлен: {active}/{total} NS активно\n{'═' * 62}{R}")
    log_info("Дальше: proxyveth status --wan   |   proxyveth doctor")
    return 0


def cmd_show_config():
    config = load_config()
    modems = config.get("modems", {})
    en = sum(1 for m in modems.values() if m.get("enabled", True))
    print(f"\n  {CONFIG_FILE}   Sync: {config.get('last_sync', '—')}")
    print(f"  Модемов: {len(modems)} (активных: {en})   WAN: {wan_iface()}\n")
    for k in sorted(modems, key=int):
        m = modems[k]
        mark = f"{G}✓{R}" if m.get("enabled", True) else f"{RD}✗{R}"
        print(f"  {mark} {int(k):>3}  {m['proxy_host']}:{m['proxy_port']}  {m['login']}")
    return 0


# ════════════════════════════════════════════════════════════════════════════
#  main
# ════════════════════════════════════════════════════════════════════════════
USAGE = f"""{B}ProxyVeth v3.3{R}

  proxyveth sync                 обновить config.json из источника
  proxyveth autosync             sync + применить разницу (add/remove/restart)
  proxyveth up [N|all]           поднять namespace
  proxyveth down [N|all]         снять namespace
  proxyveth restart [N|all]      пересобрать namespace
  proxyveth status [--wan|--json]
  proxyveth check N              полная диагностика одного модема
  proxyveth problems             только проблемные модемы
  proxyveth doctor               проверка окружения (в т.ч. DNS)
  proxyveth watchdog             один проход мониторинга
  proxyveth watchdog-loop        демон (systemd)
  proxyveth install              зависимости + sing-box
  proxyveth init                 sysctl перед подъёмом NS
  proxyveth systemd              записать/включить юниты
  proxyveth setup                install + sync + up all + systemd
  proxyveth show-config
  proxyveth cleanup              снять всё своё (namespace, правила, конфиги)
  proxyveth rescue               cleanup + отключить автозапуск (ВМ без сети)

  Источник:  API_URL | SHEET_CSV_URL | SHEET_ID   (файл {ENV_FILE})
  Интерфейсы: {VETH_PREFIX}N на хосте, {NS_IFACE} внутри namespace (VETH_PREFIX=)
"""


def main():
    if os.geteuid() != 0:
        log_fail("Нужен root")
        sys.exit(1)
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(0)

    cmd = sys.argv[1].lower().replace("-", "_")
    args = sys.argv[2:]
    arg = args[0] if args else None

    try:
        if cmd in ("help", "__help", "h"):
            print(USAGE); rc = 0
        elif cmd == "sync":
            do_sync(); rc = 0
        elif cmd == "autosync":
            rc = cmd_autosync()
        elif cmd == "install":
            rc = cmd_install()
        elif cmd == "init":
            rc = cmd_init()
        elif cmd == "setup":
            rc = cmd_setup()
        elif cmd == "systemd":
            rc = cmd_systemd()
        elif cmd == "cleanup":
            rc = cmd_cleanup()
        elif cmd == "rescue":
            rc = cmd_rescue()
        elif cmd == "doctor":
            rc = cmd_doctor()
        elif cmd == "problems":
            rc = cmd_problems()
        elif cmd == "show_config":
            rc = cmd_show_config()
        elif cmd == "watchdog":
            rc = cmd_watchdog()
        elif cmd == "watchdog_loop":
            rc = cmd_watchdog_loop()
        elif cmd == "status":
            rc = cmd_status(check_wan="--wan" in args, as_json="--json" in args)
        elif cmd == "check":
            if not arg:
                log_fail("proxyveth check N"); rc = 1
            else:
                rc = cmd_check(arg)
        elif cmd in ("up", "down", "restart"):
            if not arg:
                log_fail(f"proxyveth {cmd} [N|all]"); rc = 1
            else:
                fn = {"up": cmd_up, "down": cmd_down, "restart": cmd_restart}[cmd]
                rc = fn(arg)
        else:
            log_fail(f"Неизвестная команда: {sys.argv[1]}")
            print(USAGE)
            rc = 1
    except KeyboardInterrupt:
        print(f"\n{Y}Прервано{R}")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        log_fail(f"Ошибка: {e}")
        sys.exit(1)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
