#!/usr/bin/env bash
# Run as root on a disposable GitHub Actions VM with systemd and nftables.
set -Eeuo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
domain=node.sbnpm.test
ca=/usr/local/share/ca-certificates/sbnpm-smoke.crt
cert_dir="/etc/letsencrypt/live/$domain"
[[ ! -e /etc/sbnpm/state.json && ! -e $ca && ! -e $cert_dir ]]
scratch="$(mktemp -d)"
client_pid=
http_pid=

cleanup() {
    [[ -z $client_pid ]] || kill "$client_pid" 2>/dev/null || true
    [[ -z $http_pid ]] || kill "$http_pid" 2>/dev/null || true
    if [[ -f /etc/sbnpm/state.json ]]; then /usr/local/bin/sbnpm remove --yes || true; fi
    rm -f -- "$ca"
    rm -rf -- "$scratch" "$cert_dir"
    sed -i '/# sbnpm-smoke$/d' /etc/hosts
    update-ca-certificates >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'journalctl -u sbnpm -u sbnpm-origin -n 80 --no-pager || true' ERR

mkdir -p -- "$cert_dir"
printf '127.0.0.1 %s # sbnpm-smoke\n' "$domain" >> /etc/hosts
openssl req -new -x509 -newkey rsa:2048 -nodes -days 7 \
    -subj '/CN=sbnpm disposable test CA' -addext 'basicConstraints=critical,CA:TRUE' \
    -keyout "$scratch/ca.key" -out "$ca"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$domain" \
    -keyout "$cert_dir/privkey.pem" -out "$scratch/leaf.csr"
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$domain" > "$scratch/leaf.ext"
openssl x509 -req -in "$scratch/leaf.csr" -CA "$ca" -CAkey "$scratch/ca.key" -CAcreateserial \
    -days 7 -extfile "$scratch/leaf.ext" -out "$cert_dir/fullchain.pem"
update-ca-certificates

bash install.sh --domain "$domain" --listen 0.0.0.0 \
    --local-origin-address ::1 --reality-extra '31000' --hy2-extra '31000-31001' --tuic-extra '31002' --claim-sb
script -qec 'sb' /dev/null <<< '0' | grep 'sbnpm 设置'
[[ "$(stat -c '%a' /etc/sbnpm/hysteria2-hop-outbound.json)" == 600 ]]
/usr/local/bin/sbnpm hop-profile --format json | cmp - /etc/sbnpm/hysteria2-hop-outbound.json
/usr/local/bin/sbnpm ports reality --port 19443
for port in 19443 31000; do
    curl --fail --silent --show-error --noproxy '*' --max-time 8 \
        --resolve "$domain:$port:127.0.0.1" "https://$domain:$port/" | grep Welcome
done

python3 - "$scratch/client.json" <<'PY'
import json
import sys

with open('/etc/sbnpm/state.json') as src:
    state = json.load(src)
tls = {'enabled': True, 'server_name': state['domain']}
outbounds = [
    {'type': 'vless', 'tag': 'reality', 'server': '127.0.0.1', 'server_port': 31000,
     'uuid': state['uuid'], 'flow': 'xtls-rprx-vision', 'tls': {
         **tls, 'utls': {'enabled': True, 'fingerprint': 'chrome'},
         'reality': {'enabled': True, 'public_key': state['reality_public'], 'short_id': state['short_id']}}},
    {'type': 'hysteria2', 'tag': 'hy2', 'server': '127.0.0.1', 'server_ports': ['31000:31001'],
     'hop_interval': '5s', 'password': state['hy2_password'], 'tls': tls},
    {'type': 'tuic', 'tag': 'tuic', 'server': '127.0.0.1', 'server_port': 31002,
     'uuid': state['tuic_uuid'], 'password': state['tuic_password'], 'congestion_control': 'bbr', 'tls': tls},
]
config = {
    'inbounds': [{'type': 'mixed', 'tag': item['tag'] + '-in',
                  'listen': '127.0.0.1', 'listen_port': 19281 + i}
                 for i, item in enumerate(outbounds)],
    'outbounds': outbounds,
    'dns': {'servers': [{'type': 'local', 'tag': 'system'}]},
    'route': {'default_domain_resolver': 'system',
              'rules': [{'inbound': [item['tag'] + '-in'], 'action': 'route', 'outbound': item['tag']}
                        for item in outbounds]},
}
with open(sys.argv[1], 'w') as dst:
    json.dump(config, dst)
PY
printf 'sbnpm-smoke-ok\n' > "$scratch/probe"
python3 -m http.server 19500 --bind 127.0.0.1 --directory "$scratch" >"$scratch/http.log" 2>&1 &
http_pid=$!
/opt/sbnpm/sing-box run -c "$scratch/client.json" >"$scratch/client.log" 2>&1 &
client_pid=$!
for port in 19281 19282 19283; do
    curl --fail --silent --show-error --retry 3 --retry-all-errors --max-time 10 \
        --noproxy '' --proxy "socks5h://127.0.0.1:$port" http://127.0.0.1:19500/probe |
        grep -x 'sbnpm-smoke-ok' || { cat "$scratch/client.log"; exit 1; }
done
pid="$(systemctl show -p MainPID --value sbnpm.service)"
version="$("/proc/$pid/exe" version | awk 'NR==1 {print $3}')"
printf '0\n' | script -qec 'sb' /dev/null | grep -F "运行中的 sing-box 版本：$version"
/usr/local/bin/sbnpm nodes --qr > "$scratch/qr.txt"
for scheme in vless hysteria2 tuic; do
    grep "^$scheme://" "$scratch/qr.txt" >/dev/null
done
grep -F $'\033[' "$scratch/qr.txt" >/dev/null
checksums="$(sha256sum /etc/sbnpm/config.json /etc/sbnpm/state.json)"
bash install.sh --update-menu
/usr/local/bin/sbnpm update-core --yes
[[ "$(sha256sum /etc/sbnpm/config.json /etc/sbnpm/state.json)" == "$checksums" ]]
printf '10\nREMOVE\n' | script -qec 'sb' /dev/null | grep 'sbnpm 已卸载'
[[ ! -e /etc/sbnpm && ! -e /opt/sbnpm && ! -L /usr/local/bin/sbnpm ]]
! nft list table inet sbnpm_ports >/dev/null 2>&1
