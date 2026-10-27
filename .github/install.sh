#!/bin/sh
# IP Menubar: установка и обновление одной командой.
#   curl -fsSL https://github.com/nikitaaromanovv/ip-menubar/releases/latest/download/install.sh | sh
# Файл публикуется в релизе; контрольная сумма DMG вписывается при сборке.
set -eu

VERSION="@VERSION@"
SHA256="@SHA256@"
URL="https://github.com/nikitaaromanovv/ip-menubar/releases/download/v$VERSION/IP-Menubar.dmg"
NAME="IP Menubar.app"

main() {
    case "$SHA256" in
        *@*) echo "Запустите install.sh из релиза: github.com/nikitaaromanovv/ip-menubar/releases"; exit 1 ;;
    esac
    [ "$(uname -s)" = Darwin ] || { echo "Только macOS"; exit 1; }
    major=$(sw_vers -productVersion | cut -d. -f1)
    [ "$major" -ge 13 ] || { echo "Нужна macOS 13 или новее"; exit 1; }

    if [ -w /Applications ]; then
        dest="/Applications"
    else
        dest="$HOME/Applications"
        mkdir -p "$dest"
    fi

    tmp=$(mktemp -d)
    trap 'hdiutil detach "$tmp/mnt" -quiet >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT INT TERM

    echo "IP Menubar $VERSION: загрузка"
    curl -fL --progress-bar -o "$tmp/IP-Menubar.dmg" "$URL"
    actual=$(shasum -a 256 "$tmp/IP-Menubar.dmg" | cut -d' ' -f1)
    [ "$actual" = "$SHA256" ] || { echo "Контрольная сумма не совпала, установка отменена"; exit 1; }

    mkdir "$tmp/mnt"
    hdiutil attach -nobrowse -readonly -noautoopen -mountpoint "$tmp/mnt" "$tmp/IP-Menubar.dmg" -quiet </dev/null

    if pgrep -x "IP Menubar" >/dev/null 2>&1; then
        echo "Завершение запущенной версии"
        osascript -e 'tell application id "com.local.ipmenubar" to quit' </dev/null >/dev/null 2>&1 || true
        i=0
        while pgrep -x "IP Menubar" >/dev/null 2>&1 && [ "$i" -lt 10 ]; do sleep 0.5; i=$((i + 1)); done
        pkill -x "IP Menubar" >/dev/null 2>&1 || true
    fi

    echo "Установка в $dest"
    rm -rf "${dest:?}/${NAME:?}"
    ditto "$tmp/mnt/$NAME" "$dest/$NAME"
    xattr -dr com.apple.quarantine "$dest/$NAME" 2>/dev/null || true

    open "$dest/$NAME"
    echo "Готово: значок IP Menubar в строке меню"
}

main "$@"
