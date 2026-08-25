#!/usr/bin/env bash
# =============================================================================
#  install.sh — установка ProxyVeth одной командой.
#
#      bash <(curl -sSL https://raw.githubusercontent.com/Tovarish666/proxyveth-virt/main/install.sh)
#
#  Именно `bash <(...)`, а не `curl | bash`: во втором случае стандартный ввод
#  занят самим скриптом, и спросить ссылку на таблицу уже не получится.
#
#  Что делает: кладёт proxyveth.py на место, спрашивает таблицу, ставит
#  зависимости и sing-box, синхронизирует конфиг, поднимает namespace и
#  включает systemd. Настраивать после этого нечего — всё остальное зашито
#  в умолчания.
# =============================================================================
set -uo pipefail

REPO=${PROXYVETH_REPO:-Tovarish666/proxyveth-virt}
BRANCH=${PROXYVETH_BRANCH:-main}
RAW="https://raw.githubusercontent.com/$REPO/$BRANCH/proxyveth.py"
# Переопределяется ради проверки установщика на машине, где уже стоит боевой
# ProxyVeth: PROXYVETH_BIN=/tmp/pv.py PROXYVETH_DIR=/tmp/pvtest bash install.sh
DEST=${PROXYVETH_BIN:-/usr/local/bin/proxyveth.py}
LINK=$(dirname "$DEST")/proxyveth

G=$'\033[32m'; RD=$'\033[31m'; Y=$'\033[33m'; C=$'\033[36m'
B=$'\033[1m'; D=$'\033[2m'; R=$'\033[0m'

ok()   { printf '  %s✓%s %s\n' "$G" "$R" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$RD" "$R" "$*" >&2; }
info() { printf '  %sℹ%s %s\n' "$C" "$R" "$*"; }
step() { printf '  %s→%s %s\n' "$D" "$R" "$*"; }
head_() { printf '\n%s%s\n  %s\n%s%s\n' "$B" "$(printf '═%.0s' {1..62})" "$*" "$(printf '═%.0s' {1..62})" "$R"; }

head_ "ProxyVeth — установка"

# ── Проверки окружения ──────────────────────────────────────────────────────
[ "$(id -u)" = 0 ] || { bad "нужен root"; exit 1; }

command -v systemctl >/dev/null 2>&1 || {
    bad "нет systemd — автозапуск и watchdog работать не будут"
    exit 1
}

if ! command -v ip >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    step "ставлю базовые пакеты..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq iproute2 python3 >/dev/null 2>&1
fi

for c in ip python3; do
    command -v "$c" >/dev/null 2>&1 || { bad "нет $c и поставить не вышло"; exit 1; }
done

# ── Скачивание ──────────────────────────────────────────────────────────────
fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y -qq curl >/dev/null 2>&1 && curl -fsSL "$1" -o "$2"
    fi
}

if [ -f "$DEST" ]; then
    info "уже установлен — обновляю"
    cp -a "$DEST" "$DEST.bak.$(date +%Y%m%d-%H%M%S)"
fi

step "качаю proxyveth.py..."
tmp=$(mktemp) || { bad "нет места под временный файл"; exit 1; }
if ! fetch "$RAW" "$tmp"; then
    bad "не скачалось: $RAW"
    rm -f "$tmp"; exit 1
fi

# Файл должен быть похож на то, что мы ждём: пустая страница с ошибкой от
# GitHub тоже скачивается успешно, и без проверки мы бы её и установили.
if ! head -1 "$tmp" | grep -q '^#!/usr/bin/env python3'; then
    bad "скачалось не то — начало файла не похоже на python-скрипт"
    head -3 "$tmp" >&2
    rm -f "$tmp"; exit 1
fi
python3 -c "import ast,sys; ast.parse(open(sys.argv[1],encoding='utf-8').read())" "$tmp" 2>/dev/null || {
    bad "скачанный файл не разбирается как python"
    rm -f "$tmp"; exit 1
}

install -m 755 "$tmp" "$DEST"
rm -f "$tmp"
ln -sf "$DEST" "$LINK"
ok "$DEST  ($(wc -l < "$DEST") строк)"

# ── Дальше всё делает сам proxyveth ─────────────────────────────────────────
# exec, чтобы стандартный ввод остался терминалом: setup спросит таблицу.
exec "$DEST" setup
