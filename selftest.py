#!/usr/bin/env python3
"""
selftest.py — проверка сборки без запуска: разбор таблицы и выбор таблиц маршрутизации.

Ничего не меняет в системе, root не нужен. Гоняется на Linux (модуль импортирует
fcntl, которого нет на Windows).

    python3 selftest.py [путь к proxyveth.py]
"""
import importlib.util
import sys

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'v' if ok else 'x'} {label}: {got!r}" + ("" if ok else f"  ожидалось {want!r}"))
    if not ok:
        fails.append(label)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "proxyveth.py"
    spec = importlib.util.spec_from_file_location("pv", path)
    pv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pv)

    version = next(l for l in pv.USAGE.splitlines() if "ProxyVeth" in l).strip()
    print(f"\n  собрано: {version}\n")

    # ── Таблица ровно в том виде, в каком её ведут руками ───────────────────
    print("  таблица n | real | proxy")
    rows = [["n", "real", "proxy"],
            ["64", "101", "192.168.1.254:15000:modem101:te5xg83ted"],
            ["246", "102", "192.168.1.254:15002:modem102:v4yeyzh43n"]]
    m = pv.parse_rows(rows)
    check("модемов разобрано", len(m), 2)
    check("n=64 -> real", m["64"]["real"], 101)
    check("n=64 -> host", m["64"]["proxy_host"], "192.168.1.254")
    check("n=64 -> port", m["64"]["proxy_port"], 15000)
    check("n=64 -> login", m["64"]["login"], "modem101")
    check("n=64 -> password", m["64"]["password"], "te5xg83ted")
    check("n=246 -> real", m["246"]["real"], 102)

    # ── Совместимость: старая таблица без колонки real ─────────────────────
    print("\n  старая таблица без real (поведение v3.3)")
    m2 = pv.parse_rows([["n", "proxy"], ["41", "95.165.86.25:12001:log:pass"]])
    check("real равен n", m2["41"]["real"], 41)

    # ── Раздельные колонки тоже должны работать ────────────────────────────
    print("\n  раздельные колонки")
    m3 = pv.parse_rows([["n", "real", "proxy_host", "proxy_port", "login", "password"],
                        ["7", "192.168.115.100", "10.0.0.1", "3128", "u", "p"]])
    check("real из полного адреса", m3["7"]["real"], 115)

    # ── parse_real: формы записи ───────────────────────────────────────────
    print("\n  формы записи real")
    for raw, want in (("101", 101), ("192.168.101.100", 101),
                      ("192.168.101.1", 101), ("", 64), ("  102 ", 102)):
        check(f"{raw!r}", pv.parse_real(raw, 64), want)

    print("\n  отвергается заведомо неверное")
    for raw in ("10.0.0.1", "300", "abc"):
        try:
            pv.parse_real(raw, 64)
            print(f"  x {raw!r}: принято, а не должно")
            fails.append(raw)
        except ValueError as e:
            print(f"  v {raw!r}: отвергнуто ({str(e)[:48]})")

    # ── Таблицы маршрутизации: 253/254/255 заняты ядром ────────────────────
    print("\n  номера таблиц маршрутизации")
    check("n=64", pv.rt_table(64), 164)
    check("n=152", pv.rt_table(152), 252)
    check("n=153 (было бы default)", pv.rt_table(153), 20153)
    check("n=154 (было бы main)", pv.rt_table(154), 20154)
    check("n=155 (было бы local)", pv.rt_table(155), 20155)
    check("n=156", pv.rt_table(156), 256)
    check("n=254", pv.rt_table(254), 354)

    # ── Диапазон номеров ───────────────────────────────────────────────────
    print("\n  диапазон n")
    check("N_MAX", pv.N_MAX, 254)

    # ── Посредник: правка заголовков без сети ──────────────────────────────
    print("\n  посредник Host")
    req = (b"GET /api/webserver/SesTokInfo HTTP/1.1\r\n"
           b"Host: 192.168.64.1\r\n"
           b"Connection: keep-alive\r\n"
           b"User-Agent: test")
    out = pv.hostfix_rewrite_request(req, "192.168.101.1")
    check("Host подменён", b"Host: 192.168.101.1" in out, True)
    check("виртуальный убран", b"Host: 192.168.64.1" in out, False)
    check("keep-alive погашен", b"Connection: close" in out, True)
    check("остальное цело", b"User-Agent: test" in out, True)

    absolute = b"GET http://192.168.64.1/html/index.html HTTP/1.1\r\nHost: 192.168.64.1"
    out2 = pv.hostfix_rewrite_request(absolute, "192.168.101.1")
    check("absolute-form -> origin-form",
          out2.split(b"\r\n")[0], b"GET /html/index.html HTTP/1.1")

    print()
    if fails:
        print(f"  ПРОВАЛОВ: {len(fails)} -> {fails}\n")
        return 1
    print("  всё сходится\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
