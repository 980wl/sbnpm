#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo '请用 sudo bash install.sh [选项]。' >&2
    exit 1
fi
if ! command -v apt-get >/dev/null || [[ ! -d /run/systemd/system ]]; then
    echo '此安装器需要 Debian/Ubuntu、APT 和运行中的 systemd。' >&2
    exit 1
fi

apt_run() {
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 "$@"
}

claim_sb=false
update_menu=false
install_args=()
for arg in "$@"; do
    case "$arg" in
        --claim-sb) claim_sb=true ;;
        --update-menu) update_menu=true ;;
        *) install_args+=("$arg") ;;
    esac
done
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
app=/opt/sbnpm/sbnpm.py
shortcut=/usr/local/bin/sb
backup=/usr/local/bin/sb.pre-sbnpm
if $update_menu; then
    if $claim_sb || [[ ${#install_args[@]} -ne 0 || ! -f /etc/sbnpm/state.json || ! -x "$app" ]]; then
        echo '此选项仅用于已安装的 sbnpm。用法：sudo bash install.sh --update-menu' >&2
        exit 1
    fi
    if ! command -v qrencode >/dev/null; then
        apt_run update
        apt_run install -y qrencode
    fi
    staging="$(mktemp /opt/sbnpm/.menu.XXXXXX)"
    trap 'rm -f -- "$staging"' EXIT
    install -m 0755 "$script_dir/sbnpm.py" "$staging"
    mv -Tf -- "$staging" "$app"
    echo '菜单已更新。输入 sb（或 sbnpm）进入最新设置菜单。'
    exit 0
fi
current_sb="$(type -P sb || true)"
if [[ -e $shortcut || -L $shortcut ]]; then
    current_sb=$shortcut
fi
if $claim_sb && [[ $current_sb == "$shortcut" && $(readlink -f -- "$shortcut") != "$app" ]] &&
   [[ -e $backup || -L $backup ]]; then
    echo "快捷命令已存在，且 $backup 已被占用。请先检查两个文件。" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
need_pkgs=false
for cmd in curl python3 openssl ss nft qrencode; do
    if ! command -v "$cmd" >/dev/null; then
        need_pkgs=true
        break
    fi
done
if [[ ! -f /etc/ssl/certs/ca-certificates.crt ]]; then
    need_pkgs=true
fi
if $need_pkgs; then
    echo '正在检查并安装依赖包（若后台 unattended-upgrades 正在运行，最多自动等待 120 秒）...'
    apt_run update
    apt_run install -y ca-certificates curl python3 openssl iproute2 nftables qrencode
fi

if [[ ! -x /opt/sbnpm/sing-box ]] && ! command -v sing-box >/dev/null; then
    install -m 0755 -d /etc/apt/keyrings
    key="$(mktemp)"
    trap 'rm -f -- "$key"' EXIT
    curl --fail --location --silent --show-error --proto '=https' --connect-timeout 15 --max-time 60 \
        https://sing-box.app/gpg.key -o "$key"
    install -m 0644 "$key" /etc/apt/keyrings/sagernet.asc
    cat > /etc/apt/sources.list.d/sagernet.sources <<'APT'
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
APT
    apt_run update
    apt_run install -y sing-box
fi

install -d -m 0755 /opt/sbnpm
install -m 0755 "$script_dir/sbnpm.py" "$app"
if [[ ! -x /opt/sbnpm/sing-box ]]; then
    ln -sfn "$(type -P sing-box)" /opt/sbnpm/sing-box
fi
for unit in sbnpm.service sbnpm-origin.service sbnpm-cert-sync.service sbnpm-cert-sync.timer; do
    install -m 0644 "$script_dir/systemd/$unit" "/etc/systemd/system/$unit"
done
ln -sfn "$app" /usr/local/bin/sbnpm
systemctl daemon-reload

if [[ -f /etc/sbnpm/state.json ]]; then
    /usr/local/bin/sbnpm install --upgrade "${install_args[@]}"
else
    /usr/local/bin/sbnpm install "${install_args[@]}"
fi

if [[ -z $current_sb || $(readlink -f -- "$current_sb") == "$app" ]] || $claim_sb; then
    if [[ $current_sb == "$shortcut" && $(readlink -f -- "$shortcut") != "$app" ]]; then
        mv -- "$shortcut" "$backup"
        if ! ln -s -- "$app" "$shortcut"; then
            mv -- "$backup" "$shortcut"
            exit 1
        fi
        echo "原 sb 已备份到 $backup。"
    else
        ln -sfn "$app" "$shortcut"
        if [[ -n $current_sb && $current_sb != "$shortcut" && $(readlink -f -- "$current_sb") != "$app" ]]; then
            echo "原 sb 仍可通过 $current_sb 调用。"
        fi
    fi
    echo '输入 sb 进入设置菜单。'
else
    echo "检测到已有 $current_sb。输入 sbnpm 进入设置菜单；如需接管 sb，重跑 sudo bash install.sh --claim-sb。"
fi
