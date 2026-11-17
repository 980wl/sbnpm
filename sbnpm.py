#!/usr/bin/env python3
"""sbnpm: sing-box Reality + Hysteria2 + TUIC, with NPM TLS reuse.

Standalone standard-library CLI for Debian/Ubuntu. All mutating commands require root.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import threading
import tempfile
import time
import urllib.parse
import uuid

SCRIPT_VERSION = 'v2.7'
BASE = Path('/etc/sbnpm')
CFG = BASE / 'config.json'
STATE = BASE / 'state.json'
CERT_DIR = BASE / 'tls'
SERVICE = 'sbnpm.service'
SYNC_TIMER = 'sbnpm-cert-sync.timer'
SYNC_SERVICE = 'sbnpm-cert-sync.service'
SYSTEMD_DIR = Path('/etc/systemd/system')
TIMER_STAMP = Path('/var/lib/systemd/timers') / f'stamp-{SYNC_TIMER}'
INSTALL_DIR = Path('/opt/sbnpm')
BIN_DIR = Path('/usr/local/bin')
ORIGIN_SERVICE = 'sbnpm-origin.service'
ORIGIN_FILE = BASE / 'origin.json'
HOP_PROFILE_NAME = 'hysteria2-hop-outbound.json'
SYSCTL_BBR_CONF = Path('/etc/sysctl.d/99-sbnpm-bbr.conf')
OS_RELEASE = Path('/etc/os-release')
PROC_AVAILABLE_CC = Path('/proc/sys/net/ipv4/tcp_available_congestion_control')
PROC_CURRENT_CC = Path('/proc/sys/net/ipv4/tcp_congestion_control')
PROC_CURRENT_QDISC = Path('/proc/sys/net/core/default_qdisc')
SYS_BBR_VERSION = Path('/sys/module/tcp_bbr/version')
DEFAULT_HOP_INTERVAL = 30
MIN_HOP_INTERVAL = 5
MAX_HOP_INTERVAL = 3600
DEFAULT_NODE_NAME = 'sbnpm'
DEFAULT_HY2_PORT = 55667
DEFAULT_TUIC_PORT = 55668
INSTALL_HY2_HOP_RANGE = (56000, 60000)
INSTALL_HOP_INTERVAL = 10
NFT_TABLE = 'sbnpm_ports'
CORE = '/opt/sbnpm/sing-box'
RELEASE_API = 'https://api.github.com/repos/SagerNet/sing-box/releases/latest'
RELEASE_URL = 'https://github.com/SagerNet/sing-box/releases/download'
CORE_LIMIT = 128 * 1024 * 1024
PROTOCOLS = {'reality': 'tcp', 'hy2': 'udp', 'tuic': 'udp'}
CERT_DAYS = 2
DOMAIN_RE = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.I)


class Error(Exception):
    pass


def run(args: list[str], *, check=True, input_data=None, timeout=300) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, input=input_data, capture_output=True, text=True, check=check, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise Error(f'命令超时：{args[0]}') from e
    except FileNotFoundError as e:
        raise Error(f'缺少命令：{args[0]}') from e
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or e.stdout or '').strip()
        raise Error(f'命令执行失败: {" ".join(args[:3])}\n{msg[-1200:]}') from e


def ensure_root():
    if os.geteuid() != 0:
        raise Error('请使用 sudo 或 root 执行此命令。')


def norm_domain(name: str) -> str:
    name = name.strip().rstrip('.').lower()
    try:
        name = name.encode('idna').decode('ascii')
    except UnicodeError as e:
        raise Error('无效域名') from e
    if not DOMAIN_RE.fullmatch(name) or name.startswith('*.'):
        raise Error(f'无效的独立域名: {name!r}（不支持 IP 或通配符作为节点地址）')
    return name


def covers(cert_name: str, target: str) -> bool:
    cert_name = cert_name.lower().rstrip('.')
    target = target.lower().rstrip('.')
    if cert_name == target:
        return True
    if cert_name.startswith('*.'):
        suffix = cert_name[2:]
        return target.endswith('.' + suffix) and target.count('.') == suffix.count('.') + 1
    return False


def parse_version_tuple(text: str, length: int = 2) -> tuple[int, ...]:
    nums = [int(x) for x in re.findall(r'\d+', text or '')[:length]]
    while len(nums) < length:
        nums.append(0)
    return tuple(nums)


def detect_os_info() -> dict:
    info = {'id': 'linux', 'version_id': '', 'pretty_name': 'Linux'}
    if OS_RELEASE.is_file():
        try:
            for line in OS_RELEASE.read_text(errors='replace').splitlines():
                if '=' not in line or line.lstrip().startswith('#'):
                    continue
                k, v = line.split('=', 1)
                v = v.strip().strip('"').strip("'")
                if k == 'ID':
                    info['id'] = v.lower()
                elif k == 'VERSION_ID':
                    info['version_id'] = v
                elif k == 'PRETTY_NAME':
                    info['pretty_name'] = v
        except OSError:
            pass
    kernel_release = os.uname().release
    info['kernel'] = kernel_release
    info['kernel_tuple'] = list(parse_version_tuple(kernel_release, 2))
    return info


def detect_bbr_info(os_info: dict | None = None) -> dict:
    if os_info is None:
        os_info = detect_os_info()
    if shutil.which('modprobe') and os.geteuid() == 0:
        for mod in ('tcp_bbr', 'sch_fq'):
            run(['modprobe', mod], check=False, timeout=5)
    avail = []
    if PROC_AVAILABLE_CC.is_file():
        try:
            avail = PROC_AVAILABLE_CC.read_text(errors='replace').split()
        except OSError:
            pass
    current_cc = ''
    if PROC_CURRENT_CC.is_file():
        try:
            current_cc = PROC_CURRENT_CC.read_text(errors='replace').strip()
        except OSError:
            pass
    current_qdisc = ''
    if PROC_CURRENT_QDISC.is_file():
        try:
            current_qdisc = PROC_CURRENT_QDISC.read_text(errors='replace').strip()
        except OSError:
            pass
    mod_version = ''
    if SYS_BBR_VERSION.is_file():
        try:
            mod_version = SYS_BBR_VERSION.read_text(errors='replace').strip()
        except OSError:
            pass
    if not mod_version and shutil.which('modinfo'):
        res = run(['modinfo', '-F', 'version', 'tcp_bbr'], check=False, timeout=5)
        if res.returncode == 0:
            mod_version = res.stdout.strip().splitlines()[0] if res.stdout.strip() else ''

    kernel_lower = os_info.get('kernel', '').lower()
    if 'bbr3' in avail or mod_version.startswith('3') or 'bbrv3' in kernel_lower or 'bbr3' in kernel_lower:
        gen = 'bbrv3'
        target_cc = 'bbr3' if 'bbr3' in avail else 'bbr'
    elif 'bbr2' in avail or mod_version.startswith('2') or 'bbrv2' in kernel_lower or 'bbr2' in kernel_lower:
        gen = 'bbrv2'
        target_cc = 'bbr2' if 'bbr2' in avail else 'bbr'
    elif 'bbr' in avail or current_cc == 'bbr' or tuple(os_info.get('kernel_tuple', [0, 0])) >= (4, 9):
        gen = 'bbrv1'
        target_cc = 'bbr'
    else:
        gen = 'none'
        target_cc = current_cc or 'cubic'

    return {
        'generation': gen,
        'module_version': mod_version or ('3' if gen == 'bbrv3' else '2' if gen == 'bbrv2' else '1' if gen == 'bbrv1' else ''),
        'available_cc': avail,
        'current_cc': current_cc,
        'current_qdisc': current_qdisc,
        'target_cc': target_cc,
        'target_qdisc': 'fq',
    }


def core_supports_bbr_profile() -> bool:
    try:
        return parse_version_tuple(core_version(CORE), 2) >= (1, 14)
    except (Error, OSError, AttributeError):
        return False


def build_transport_profile(os_info: dict, bbr_info: dict, *, bbr_profile_supported: bool | None = None) -> dict:
    gen = bbr_info['generation']
    kernel_tuple = tuple(os_info.get('kernel_tuple', [0, 0]))
    os_id = os_info.get('id', 'linux')
    os_ver = parse_version_tuple(os_info.get('version_id', ''), 2)
    if bbr_profile_supported is None:
        bbr_profile_supported = core_supports_bbr_profile()

    # Ubuntu 24.04+ (kernel >= 6.8) or Ubuntu 22.04 HWE / Debian 12+ (kernel >= 6.1) support mature MPTCP & TFO
    mptcp_capable = kernel_tuple >= (6, 1) or (os_id == 'ubuntu' and os_ver >= (24, 4))
    if gen == 'bbrv3':
        hy2_profile = 'standard'
        tuic_heartbeat = '8s'
        tfo = False
        mptcp = False
        udp_fragment = False
        ecn = 2
    elif gen == 'bbrv2':
        hy2_profile = 'standard'
        tuic_heartbeat = '10s'
        tfo = False
        mptcp = False
        udp_fragment = False
        ecn = 2
    elif gen == 'bbrv1':
        hy2_profile = 'standard'
        tuic_heartbeat = '10s'
        tfo = False
        mptcp = False
        udp_fragment = False
        ecn = 2
    else:
        hy2_profile = 'conservative'
        tuic_heartbeat = '15s'
        tfo = False
        mptcp = False
        udp_fragment = False
        ecn = 2

    return {
        'os_id': os_id,
        'os_version': os_info.get('version_id', ''),
        'os_pretty': os_info.get('pretty_name', 'Linux'),
        'kernel': os_info.get('kernel', ''),
        'generation': gen,
        'module_version': bbr_info.get('module_version', ''),
        'cc': bbr_info.get('current_cc') or bbr_info.get('target_cc', 'bbr'),
        'qdisc': bbr_info.get('current_qdisc') or bbr_info.get('target_qdisc', 'fq'),
        'sysctl_applied': False,
        'tcp_fast_open': tfo,
        'tcp_multi_path': mptcp,
        'hy2_bbr_profile': hy2_profile if bbr_profile_supported else None,
        'tuic_cc': 'bbr',
        'tuic_heartbeat': tuic_heartbeat,
        'udp_fragment': udp_fragment,
        'tcp_ecn': ecn,
        'quic_stream_window': 8388608,
        'quic_conn_window': 20971520,
        'quic_initial_packet_size': 1200,
    }


def enable_system_bbr() -> dict:
    os_info = detect_os_info()
    bbr_info = detect_bbr_info(os_info)
    profile = build_transport_profile(os_info, bbr_info)
    if bbr_info['generation'] != 'none':
        sysctl_lines = [
            '# Managed by sbnpm: BBR & QUIC/TCP evening-peak transport tuning',
            f'net.core.default_qdisc = {bbr_info["target_qdisc"]}',
            f'net.ipv4.tcp_congestion_control = {bbr_info["target_cc"]}',
            f'net.ipv4.tcp_ecn = {profile["tcp_ecn"]}',
            'net.ipv4.tcp_fastopen = 3',
            'net.ipv4.tcp_slow_start_after_idle = 0',
            'net.ipv4.tcp_mtu_probing = 1',
            'net.core.rmem_max = 33554432',
            'net.core.wmem_max = 33554432',
            'net.core.rmem_default = 262144',
            'net.core.wmem_default = 262144',
            'net.ipv4.tcp_rmem = 4096 87380 33554432',
            'net.ipv4.tcp_wmem = 4096 65536 33554432',
            'net.ipv4.tcp_notsent_lowat = 16384',
            'net.core.netdev_max_backlog = 16384',
            'net.core.netdev_budget = 600',
            'net.core.netdev_budget_usecs = 8000',
            'net.core.somaxconn = 4096',
            'net.ipv4.udp_rmem_min = 16384',
            'net.ipv4.udp_wmem_min = 16384',
        ]
        try:
            write_file(SYSCTL_BBR_CONF, ('\n'.join(sysctl_lines) + '\n').encode(), mode=0o644)
            res = run(['sysctl', '-p', str(SYSCTL_BBR_CONF)], check=False, timeout=10)
            if res.returncode == 0:
                profile['sysctl_applied'] = True
                refreshed = detect_bbr_info(os_info)
                profile['cc'] = refreshed['current_cc'] or bbr_info['target_cc']
                profile['qdisc'] = refreshed['current_qdisc'] or bbr_info['target_qdisc']
        except (Error, OSError):
            pass
    print_bbr_summary(profile)
    return profile


def print_bbr_summary(profile: dict):
    gen_label = {
        'bbrv3': 'BBRv3（第三代低丢包高吞吐拥塞控制）',
        'bbrv2': 'BBRv2（第二代 ECN/丢包感知拥塞控制）',
        'bbrv1': 'BBRv1（标准主线内核 BBR）',
        'none': '未检测到内核 BBR（仅启用用户态 QUIC BBR）',
    }.get(profile.get('generation', 'none'), profile.get('generation', '未知'))
    print(f"系统环境：{profile.get('os_pretty', 'Linux')}（内核 {profile.get('kernel', '未知')}）")
    print(f"BBR 状态：{gen_label}，当前算法 {profile.get('cc', '未知')} + 队列 {profile.get('qdisc', '未知')}")
    hy2_desc = f"bbr_profile={profile['hy2_bbr_profile']}" if profile.get('hy2_bbr_profile') else '标准 QUIC BBR'
    reality_opts = [name for name, flag in (('TFO', profile.get('tcp_fast_open')),
                                            ('MPTCP', profile.get('tcp_multi_path'))) if flag]
    reality_desc = '+'.join(reality_opts) if reality_opts else '标准 TCP'
    print(f"协议传输优化：Reality({reality_desc}) | Hysteria2({hy2_desc}) | "
          f"TUIC(cc={profile.get('tuic_cc', 'bbr')}, heartbeat={profile.get('tuic_heartbeat', '10s')})")


def docker_containers() -> list[dict]:
    if not shutil.which('docker'):
        return []
    ids = run(['docker', 'ps', '-aq'], timeout=15).stdout.split()
    return json.loads(run(['docker', 'inspect', *ids], timeout=15).stdout) if ids else []


def published_ports(container: dict) -> dict:
    return (container.get('NetworkSettings') or {}).get('Ports') or {}


def npm_endpoints(container: dict) -> list[tuple[str, int]]:
    endpoints = []
    if (container.get('HostConfig') or {}).get('NetworkMode') == 'host':
        endpoints.extend([('127.0.0.1', 443), ('::1', 443)])
    for binding in published_ports(container).get('443/tcp') or []:
        address = binding['HostIp']
        address = {'0.0.0.0': '127.0.0.1', '::': '::1', '': '127.0.0.1'}.get(address, address)
        endpoints.append((address, int(binding['HostPort'])))
    for net in ((container.get('NetworkSettings') or {}).get('Networks') or {}).values():
        endpoints.extend((net[k], 443) for k in ('IPAddress', 'GlobalIPv6Address') if net.get(k))
    return list(dict.fromkeys(endpoints))


def docker_npms(containers=None) -> list[dict]:
    if containers is None:
        containers = docker_containers()
    result = []
    for c in containers:
        img = str(c.get('Config', {}).get('Image', '')).lower()
        if 'nginx-proxy-manager' not in img:
            continue
        mounts = {m['Destination'].rstrip('/'): Path(m['Source']) for m in c.get('Mounts', [])
                  if m.get('Source') and m.get('Destination')}
        result.append({'id': c.get('Id', '')[:12], 'name': c.get('Name', '').lstrip('/'),
                       'running': bool(c.get('State', {}).get('Running', False)),
                       'letsencrypt': mounts.get('/etc/letsencrypt'), 'data': mounts.get('/data'),
                       'endpoints': npm_endpoints(c)})
    return result


def npm_cert_pairs(npm: dict) -> list[tuple[Path, Path]]:
    dirs = []
    if npm['letsencrypt']:
        dirs.extend(sorted((npm['letsencrypt'] / 'live').glob('npm-*')))
    if npm['data']:
        dirs.extend(sorted((npm['data'] / 'custom_ssl').glob('npm-*')))
    return [(d / 'fullchain.pem', d / 'privkey.pem') for d in dirs
            if (d / 'fullchain.pem').is_file() and (d / 'privkey.pem').is_file()]


def npm_hostnames(npm: dict) -> set[str]:
    names = set()
    if not npm['data']:
        return names
    base = npm['data'] / 'nginx'
    for folder in ('proxy_host', 'redirection_host', 'dead_host'):
        for path in (base / folder).glob('*.conf'):
            try:
                content = path.read_text(errors='replace')
            except OSError:
                continue
            # NPM generated server_name directives, not arbitrary DB files.
            for raw in re.findall(r'\bserver_name\s+([^;]+);', content):
                for part in raw.split():
                    try:
                        names.add(norm_domain(part))
                    except Error:
                        pass
    return names


def certificate_info(cert: Path, min_days: int) -> tuple[set[str], str]:
    result = run(['openssl', 'x509', '-in', str(cert), '-noout', '-ext', 'subjectAltName',
                  '-checkend', str(min_days * 86400), '-pubkey'], check=False)
    if result.returncode != 0:
        raise Error(f'证书无法读取、已过期或将在 {min_days} 天内过期：{cert}')
    names = {n.lower().rstrip('.') for n in re.findall(r'DNS:([^,\s]+)', result.stdout)}
    pem = re.search(r'-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----', result.stdout, re.S)
    if not pem:
        raise Error(f'无法读取证书公钥：{cert}')
    return names, pem[0]


def cert_valid(cert: Path, key: Path, domain: str, *, min_days: int = CERT_DAYS) -> None:
    if not (cert.is_file() and key.is_file()):
        raise Error(f'证书或私钥不存在：{cert} / {key}')
    names, public_key = certificate_info(cert, min_days)
    if not any(covers(name, domain) for name in names):
        raise Error(f'证书 SAN 不匹配 {domain}: {cert}')
    check_pair(cert, key, public_key)


def check_pair(cert: Path, key: Path, public_key: str):
    key_public = run(['openssl', 'pkey', '-in', str(key), '-pubout']).stdout.strip()
    if public_key != key_public:
        raise Error(f'证书与私钥不匹配：{cert} / {key}')


def npm_cert_records(npms: list[dict], domain=None):
    for npm in npms:
        for cert, key in npm_cert_pairs(npm):
            try:
                names, public_key = certificate_info(cert, CERT_DAYS)
                if not names or (domain and not any(covers(name, domain) for name in names)):
                    continue
                check_pair(cert, key, public_key)
                if cert_publicly_trusted(cert):
                    yield names, cert, key, npm['name']
            except (Error, OSError):
                continue


def discover_sources(npms: list[dict]) -> dict[str, Path]:
    hostnames = set().union(*(npm_hostnames(npm) for npm in npms))
    found = {}
    for names, cert, _, _ in npm_cert_records(npms):
        matched = {domain for domain in hostnames if any(covers(name, domain) for name in names)}
        for name in names:
            try:
                matched.add(norm_domain(name))
            except Error:
                continue
        for domain in matched:
            found.setdefault(domain, cert)
    return dict(sorted(found.items()))


def discover_domains(npms: list[dict]) -> list[str]:
    return list(discover_sources(npms))


def find_le(domain: str) -> tuple[Path, Path] | None:
    # certbot live directory can be suffixed -0001 after reissues.
    root = Path('/etc/letsencrypt/live')
    for d in [root / domain] + sorted(root.glob(f'{domain}-[0-9]*')):
        cert, key = d / 'fullchain.pem', d / 'privkey.pem'
        try:
            cert_valid(cert, key, domain)
            if cert_publicly_trusted(cert):
                return cert, key
        except (Error, OSError):
            pass
    return None


def port_available(port: int, udp: bool, listen: str = '0.0.0.0') -> bool:
    family = socket.AF_INET6 if ':' in listen else socket.AF_INET
    typ = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    try:
        with socket.socket(family, typ) as s:
            if family == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                s.bind((listen, port, 0, 0))
            else:
                s.bind((listen, port))
            return True
    except OSError:
        return False


def auto_listen() -> str:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.bind(('::', 0))
        return '::'
    except OSError:
        return '0.0.0.0'


def probe_tls(address: str, port: int, domain: str, *, context=None) -> str:
    ctx = context or ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    with socket.create_connection((address, port), timeout=3) as raw:
        with ctx.wrap_socket(raw, server_hostname=domain) as tls:
            return tls.selected_alpn_protocol() or '未协商 ALPN'


def select_origin(args, domain, npms, source) -> dict:
    if args.origin_port is not None and not 1 <= args.origin_port <= 65535:
        raise Error('HTTPS 握手目标端口必须在 1–65535。')
    local_address = args.local_origin_address
    if local_address or (not args.origin_address and not npms and source == 'letsencrypt'):
        port = args.origin_port or 18443
        if port < 1024:
            raise Error('内置 HTTPS 握手入口需使用 1024–65535 的端口。')
        return {'address': local_address or '127.0.0.1', 'port': port, 'local': True}
    if args.origin_address:
        endpoints = [(str(ipaddress.ip_address(args.origin_address)), args.origin_port or 443)]
    elif npms:
        endpoints = [(address, args.origin_port or port)
                     for npm in npms if npm['running']
                     for address, port in npm['endpoints']]
    else:
        endpoints = []
    failures = []
    for address, port in dict.fromkeys(endpoints):
        try:
            alpn = probe_tls(address, port, domain)
        except OSError as e:
            failures.append(f'{address}:{port} {e}')
            continue
        print(f'同域名 HTTPS 握手入口：{domain} → [{address}]:{port}（TLS 1.3，{alpn}）')
        return {'address': address, 'port': port, 'local': False}
    details = '\n'.join(failures)
    raise Error('找不到提供该域名可信 TLS 1.3 的 NPM HTTPS 入口。检查容器状态和站点证书，'
                '或用 --origin-address IP --origin-port 端口指定 HTTPS 入口。'
                + ('\n' + details if details else ''))


def validate_hop_interval(seconds: int) -> int:
    if isinstance(seconds, bool) or not isinstance(seconds, int) or not (MIN_HOP_INTERVAL <= seconds <= MAX_HOP_INTERVAL):
        raise Error(f'Hysteria2 端口跳跃间隔必须在 {MIN_HOP_INTERVAL}–{MAX_HOP_INTERVAL} 秒之间。')
    return seconds


def validate_node_name(name: str) -> str:
    name = name.strip()
    if not name:
        return DEFAULT_NODE_NAME
    if len(name) > 32:
        raise Error('节点名称最长 32 个字符。')
    if any(ch.isspace() for ch in name) or any(ch in '#?/:@&=+%\\' for ch in name):
        raise Error('节点名称不能包含空格及 # ? / : @ & = + % \\ 等字符。')
    return name


def resolve_node_name(args, old: dict | None = None) -> str:
    flag = getattr(args, 'node_name', None)
    if flag is not None:
        return validate_node_name(flag)
    if old and old.get('node_name'):
        return validate_node_name(old['node_name'])
    if sys.stdin.isatty():
        raw = input('请输入节点名称（回车默认 sbnpm）：').strip()
        if raw:
            return validate_node_name(raw)
    return DEFAULT_NODE_NAME


def validate_bandwidth_mbps(mbps: int, label: str = '带宽') -> int:
    if isinstance(mbps, bool) or not isinstance(mbps, int) or not (0 <= mbps <= 10000):
        raise Error(f'{label}必须在 0–10000 Mbps 之间（0 表示不限速并启用自适应 BBR）。')
    return mbps


def parse_ranges(text: str) -> list[tuple[int, int]]:
    if not text.strip():
        return []
    if len(text) > 1024:
        raise Error('端口列表过长。')
    ranges = []
    for token in text.split(','):
        m = re.fullmatch(r'(\d{1,5})(?:[-:](\d{1,5}))?', token.strip())
        if not m:
            raise Error('端口格式示例：30000,30100-30120。')
        start, end = int(m[1]), int(m[2] or m[1])
        if not 1024 <= start <= end <= 65535:
            raise Error('端口范围必须按从小到大填写，且在 1024–65535。')
        ranges.append((start, end))
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    if sum(b - a + 1 for a, b in merged) > 4096:
        raise Error('每个协议最多可配置 4096 个备用端口。')
    return merged


def port_plan(s: dict) -> dict[str, set[int]]:
    plan = {'tcp': set(), 'udp': set()}
    origin = s.get('origin')
    for proto, transport in PROTOCOLS.items():
        main = s['ports'][proto]
        if not 1024 <= main <= 65535:
            raise Error('节点主端口必须在 1024–65535。')
        extras = {port for start, end in s.get('extra_ports', {}).get(proto, [])
                  for port in range(start, end + 1)}
        if main in extras:
            raise Error(f'{proto} 主端口 {main} 已包括在备用端口内，请将它移出范围。')
        occupied = plan[transport] & (extras | {main})
        if occupied:
            raise Error(f'{transport.upper()} {min(occupied)} 同时分配给两个协议。')
        plan[transport].update(extras | {main})
    if origin and origin['port'] in plan['tcp']:
        raise Error(f"Reality 节点端口与 HTTPS 握手入口 TCP {origin['port']} 冲突。")
    return plan


def check_port_plan(s: dict, old=None, *, containers=None):
    plan = port_plan(s)
    previous = {'tcp': set(), 'udp': set()}
    if old and active(SERVICE):
        for proto, transport in PROTOCOLS.items():
            previous[transport].add(old['ports'][proto])
    if containers is None:
        containers = docker_containers()
    for container in containers:
        for entry, bindings in published_ports(container).items():
            transport = entry.split('/')[-1]
            for binding in bindings or []:
                port = int(binding['HostPort'])
                if port in plan.get(transport, set()):
                    raise Error(f'{transport.upper()} {port} 已由 Docker 容器发布。')
    for transport, ports in plan.items():
        for port in sorted(ports - previous[transport]):
            if not port_available(port, transport == 'udp', s['listen']):
                raise Error(f'{transport.upper()} {port} 已被占用，请更换端口。')
    origin = s.get('origin')
    if origin and origin['local']:
        old_origin = old.get('origin') if old else None
        port = origin['port']
        already_bound = origin == old_origin and active(ORIGIN_SERVICE)
        if not already_bound and not port_available(port, False, origin['address']):
            raise Error(f'本机 HTTPS 握手端口 TCP {port} 已被占用，请使用 --origin-port 指定其他端口。')


def format_ranges(ranges, separator='-') -> str:
    return ','.join(str(a) if a == b else f'{a}{separator}{b}' for a, b in ranges)


def nft_rules(s: dict) -> str:
    rules = []
    drop_v6 = []
    ipv4_only = s['listen'] == '0.0.0.0'
    family = 'meta nfproto ipv4 ' if ipv4_only else ''
    for proto, transport in PROTOCOLS.items():
        ranges = s.get('extra_ports', {}).get(proto, [])
        if ranges:
            matches = format_ranges(ranges).replace(',', ', ')
            rules.append(f'{family}{transport} dport {{ {matches} }} redirect to :{s["ports"][proto]}')
            if ipv4_only:
                drop_v6.append(f'meta nfproto ipv6 {transport} dport {{ {matches} }} drop')
    if not rules:
        return ''
    lines = [f'add table inet {NFT_TABLE}', f'delete table inet {NFT_TABLE}', f'table inet {NFT_TABLE} {{']
    for chain in ('prerouting', 'output'):
        lines.extend([f'  chain {chain} {{', f'    type nat hook {chain} priority -95; policy accept;'])
        lines.extend(f'    fib daddr type local {rule}' for rule in rules)
        if chain == 'prerouting' and drop_v6:
            lines.extend(f'    fib daddr type local {rule}' for rule in drop_v6)
        lines.append('  }')
    lines.append('}')
    return '\n'.join(lines) + '\n'


def apply_nft(s: dict, *, check=False):
    rules = nft_rules(s)
    if rules:
        run(['nft', *(['-c'] if check else []), '-f', '-'], input_data=rules, timeout=15)
    elif not check:
        clear_nft()


def clear_nft():
    if not shutil.which('nft'):
        return
    table = run(['nft', 'list', 'table', 'inet', NFT_TABLE], check=False, timeout=15)
    if table.returncode == 0:
        run(['nft', 'delete', 'table', 'inet', NFT_TABLE], timeout=15)


def dns_addresses(domain: str) -> list[str]:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(domain, None,
                                                                type=socket.SOCK_STREAM)})
    except socket.gaierror:
        return []


def select_domain(asked: str | None, npms: list[dict]) -> str:
    if asked:
        return norm_domain(asked)
    discovered = discover_domains(npms)
    if discovered:
        print('检测到可复用 NPM TLS 证书的域名：')
        for i, d in enumerate(discovered, 1):
            print(f'  {i}. {d}')
        if not sys.stdin.isatty():
            raise Error('非交互模式需要指定 --domain')
        picked = input('请输入编号或新域名 [1]: ').strip() or '1'
        if picked.isdigit() and 1 <= int(picked) <= len(discovered):
            return discovered[int(picked) - 1]
        return norm_domain(picked)
    if not sys.stdin.isatty():
        raise Error('未找到 NPM 可用域名，非交互模式必须指定 --domain')
    return norm_domain(input('请输入已解析到 VPS 的域名：'))


def choose_source(mode: str, domain: str, npms: list[dict], email: str | None,
                  allow_issue=True) -> tuple[Path, Path, str]:
    if mode in ('auto', 'npm'):
        match = next(npm_cert_records(npms, domain), None)
        if match:
            _, cert, key, _ = match
            return cert, key, 'npm'
    if mode == 'npm':
        raise Error(f'NPM 中找不到 {domain} 对应的有效证书。先在 NPM 管理界面签发该域名证书。')
    if mode == 'auto' and npms:
        raise Error(f'检测到 NPM，但找不到 {domain} 的有效证书。请先在 NPM 签发证书；'
                    '不会擅自占用 NPM 的 80 端口。')
    existing = find_le(domain)
    if existing:
        return existing[0], existing[1], 'letsencrypt'
    if not allow_issue:
        raise Error(f'本地没有找到 {domain} 的有效 Let\'s Encrypt 证书。')
    if not email or not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
        raise Error('无 NPM 时首次申请 Let\'s Encrypt 证书，必须提供 --email 收取续期通知。')
    if not port_available(80, False, '0.0.0.0'):
        raise Error('Certbot HTTP-01 需要 TCP 80 空闲；当前端口已占用。先通过 NPM 签发证书，'
                    '或手动配置 DNS-01 证书并导入；本工具不停止任何服务。')
    print('无可复用 NPM 证书：通过 certbot standalone 向 Let\'s Encrypt 申请。')
    if not shutil.which('certbot'):
        run(['apt-get', '-o', 'DPkg::Lock::Timeout=120', 'update'])
        run(['apt-get', '-o', 'DPkg::Lock::Timeout=120', 'install', '-y', 'certbot'])
    run(['certbot', 'certonly', '--standalone', '--non-interactive', '--agree-tos',
         '--preferred-challenges', 'http', '--email', email, '-d', domain])
    got = find_le(domain)
    if not got:
        raise Error('certbot 结束后仍无法找到匹配的有效证书。')
    return got[0], got[1], 'letsencrypt'


def generate_keys(binary='sing-box') -> dict:
    keys = run([binary, 'generate', 'reality-keypair']).stdout
    private = re.search(r'^PrivateKey:\s*(\S+)', keys, re.M | re.I)
    public = re.search(r'^PublicKey:\s*(\S+)', keys, re.M | re.I)
    if not private or not public:
        raise Error('sing-box 没有输出预期的 Reality 密钥对。')
    return {'private': private.group(1), 'public': public.group(1)}


def make_config(s: dict) -> dict:
    ports, domain = s['ports'], s['domain']
    tls_cert = str(CERT_DIR / 'fullchain.pem')
    tls_key = str(CERT_DIR / 'privkey.pem')
    handshake = {'server': s['reality_sni'], 'server_port': 443}
    dns_servers = [{'type': 'local', 'tag': 'system'}]
    if 'origin' in s:
        origin = s['origin']
        handshake.update(server_port=origin['port'], domain_resolver='reality-origin')
        dns_servers.append({'type': 'hosts', 'tag': 'reality-origin',
                            'predefined': {domain: origin['address']}})
    tls = {'enabled': True, 'server_name': domain, 'certificate_path': tls_cert,
           'key_path': tls_key, 'alpn': ['h3']}
    vless_in = {
        'type': 'vless', 'tag': 'vless-reality-vision', 'listen': s['listen'],
        'listen_port': ports['reality'],
        'users': [{'uuid': s['uuid'], 'flow': 'xtls-rprx-vision'}],
        'tls': {'enabled': True, 'server_name': s['reality_sni'],
                'reality': {'enabled': True,
                            'handshake': handshake,
                            'private_key': s['reality_private'], 'short_id': [s['short_id']]}}
    }
    hy2_in = {
        'type': 'hysteria2', 'tag': 'hysteria2', 'listen': s['listen'],
        'listen_port': ports['hy2'], 'users': [{'password': s['hy2_password']}],
        'tls': dict(tls)
    }
    tuic_in = {
        'type': 'tuic', 'tag': 'tuic-v5', 'listen': s['listen'],
        'listen_port': ports['tuic'],
        'users': [{'uuid': s['tuic_uuid'], 'password': s['tuic_password']}],
        'congestion_control': 'bbr', 'tls': dict(tls)
    }
    bbr = s.get('bbr')
    if isinstance(bbr, dict):
        if bbr.get('tcp_fast_open'):
            vless_in['tcp_fast_open'] = True
        if bbr.get('tcp_multi_path'):
            vless_in['tcp_multi_path'] = True
        if bbr.get('hy2_bbr_profile') and (bbr.get('force_bbr_profile') or core_supports_bbr_profile()):
            hy2_in['bbr_profile'] = bbr['hy2_bbr_profile']
        if bbr.get('tuic_cc'):
            tuic_in['congestion_control'] = bbr['tuic_cc']
        if bbr.get('tuic_heartbeat'):
            tuic_in['heartbeat'] = bbr['tuic_heartbeat']
        if bbr.get('udp_fragment'):
            hy2_in['udp_fragment'] = True
            tuic_in['udp_fragment'] = True
        if bbr.get('quic_stream_window'):
            hy2_in['stream_receive_window'] = int(bbr['quic_stream_window'])
            tuic_in['stream_receive_window'] = int(bbr['quic_stream_window'])
        if bbr.get('quic_conn_window'):
            hy2_in['connection_receive_window'] = int(bbr['quic_conn_window'])
            tuic_in['connection_receive_window'] = int(bbr['quic_conn_window'])
        if bbr.get('quic_initial_packet_size'):
            hy2_in['initial_packet_size'] = int(bbr['quic_initial_packet_size'])
            tuic_in['initial_packet_size'] = int(bbr['quic_initial_packet_size'])
    if s.get('hy2_obfs'):
        obfs_type = s.get('hy2_obfs_type', 'salamander')
        hy2_in['obfs'] = {'type': obfs_type, 'password': s['hy2_obfs']}
    if s.get('hy2_up_mbps') and s.get('hy2_down_mbps'):
        # Server inbound up_mbps is server send (client download), down_mbps is server recv (client upload)
        hy2_in['up_mbps'] = int(s['hy2_down_mbps'])
        hy2_in['down_mbps'] = int(s['hy2_up_mbps'])
    return {
        'dns': {'servers': dns_servers, 'final': 'system'},
        'log': {'level': 'warn', 'timestamp': True},
        'inbounds': [vless_in, hy2_in, tuic_in],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}, {'type': 'block', 'tag': 'block'}],
        'route': {
            'rules': [{'ip_is_private': True, 'outbound': 'block'}],
            'final': 'direct',
            'default_domain_resolver': 'system',
        },
    }


def make_links(s: dict, ports=None, *, hop_ports: str | None = None) -> list[str]:
    host = s['domain']
    ports = s['ports'] if ports is None else ports
    name = s.get('node_name') or DEFAULT_NODE_NAME
    tuic_cc = (s.get('bbr') or {}).get('tuic_cc', 'bbr') if isinstance(s.get('bbr'), dict) else 'bbr'

    def query(params: dict) -> str:
        return urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    v = (f'vless://{s["uuid"]}@{host}:{ports["reality"]}?'
         f'{query({"encryption": "none", "security": "reality", "type": "tcp", "sni": s["reality_sni"], "fp": "chrome", "pbk": s["reality_public"], "sid": s["short_id"], "flow": "xtls-rprx-vision"})}'
         f'#{name}-Reality-Vision')
    hy_params = {'sni': host, 'alpn': 'h3', 'insecure': '0'}
    if hop_ports:
        hy_params['mport'] = hop_ports
    if s.get('hy2_obfs'):
        hy_params['obfs'] = s.get('hy2_obfs_type', 'salamander')
        hy_params['obfs-password'] = s['hy2_obfs']
    hy = (f'hysteria2://{urllib.parse.quote(s["hy2_password"], safe="")}@{host}:{ports["hy2"]}/?'
          f'{query(hy_params)}'
          f'#{name}-Hysteria2')
    tu = (f'tuic://{s["tuic_uuid"]}:{urllib.parse.quote(s["tuic_password"], safe="")}@{host}:{ports["tuic"]}?'
          f'{query({"sni": host, "alpn": "h3", "congestion_control": tuic_cc})}'
          f'#{name}-TUIC-v5')
    return [v, hy, tu]


def write_file(path: Path, payload: bytes, mode=0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name + '.')
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def as_json(data: dict) -> bytes:
    return (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode()


def group_access(path: Path) -> None:
    import grp
    gid = grp.getgrnam('sbnpm').gr_gid
    os.chown(path, 0, gid)
    os.chmod(path, 0o640)


def ensure_user() -> None:
    import pwd
    BASE.mkdir(mode=0o750, parents=True, exist_ok=True)
    try:
        pwd.getpwnam('sbnpm')
    except KeyError:
        run(['useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'sbnpm'])
        account = pwd.getpwnam('sbnpm')
        write_file(BASE / 'account.json', as_json({'uid': account.pw_uid, 'gid': account.pw_gid}), mode=0o600)
    CERT_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    import grp
    gid = grp.getgrnam('sbnpm').gr_gid
    for p in (BASE, CERT_DIR):
        os.chown(p, 0, gid)
        os.chmod(p, 0o750)


def cert_publicly_trusted(cert: Path, ca_file='/etc/ssl/certs/ca-certificates.crt') -> bool:
    # The chain must be trusted by normal clients; Cloudflare Origin CA is not.
    if not Path(ca_file).is_file():
        raise Error('未找到 CA 信任链；先安装 ca-certificates。')
    check = run(['openssl', 'verify', '-purpose', 'sslserver', '-CAfile', str(ca_file),
                 '-untrusted', str(cert), str(cert)], check=False)
    return check.returncode == 0


def stage_certificate(cert: Path, key: Path, domain: str) -> tuple[bytes, bytes]:
    cert_valid(cert, key, domain)
    c, k = cert.read_bytes(), key.read_bytes()
    # Original NPM may rotate while reading. Verify staged snapshot before writing.
    with tempfile.TemporaryDirectory() as td:
        cp, kp = Path(td) / 'cert.pem', Path(td) / 'key.pem'
        cp.write_bytes(c)
        kp.write_bytes(k)
        cert_valid(cp, kp, domain)
        if not cert_publicly_trusted(cp):
            raise Error('证书不受系统 CA 信任，请使用公共 CA 签发且包含中间证书的完整证书链。')
    return c, k


def install_copies(cert_bytes: bytes, key_bytes: bytes):
    for name, payload in (('fullchain.pem', cert_bytes), ('privkey.pem', key_bytes)):
        path = CERT_DIR / name
        write_file(path, payload)
        group_access(path)


def systemctl(*args: str):
    run(['systemctl', *args])


def read_state() -> dict:
    if not STATE.is_file():
        raise Error('尚未安装 sbnpm，请先执行 sudo sbnpm install。')
    return json.loads(STATE.read_text())


def cmd_list(args):
    ensure_root()
    npms = docker_npms()
    if not npms:
        print('没有发现 Docker 版 Nginx Proxy Manager。')
    else:
        for npm in npms:
            print(f'NPM: {npm["name"]} ({npm["id"]})  状态: {"运行中" if npm["running"] else "已停止"}')
            print(f'  /etc/letsencrypt: {npm["letsencrypt"] or "未挂载"}')
            print(f'  /data: {npm["data"] or "未挂载"}')
        print('具有有效匹配证书的域名：')
        for domain, cert in discover_sources(npms).items():
            print(f'  {domain:42} {cert}')


def active(unit: str) -> bool:
    return run(['systemctl', 'is-active', '--quiet', unit], check=False, timeout=15).returncode == 0


def verify_running(s: dict):
    last_error = None
    wanted = {(transport, s['ports'][proto]) for proto, transport in PROTOCOLS.items()}
    deadline = time.monotonic() + 12
    origin = s.get('origin')
    interval = 0.05
    while time.monotonic() < deadline:
        pid = run(['systemctl', 'show', '-p', 'MainPID', '--value', SERVICE], timeout=10).stdout.strip()
        if pid.isdigit() and pid != '0' and active(SERVICE):
            listeners = set()
            for row in run(['ss', '-H', '-lntup'], timeout=10).stdout.splitlines():
                columns = row.split(maxsplit=6)
                if len(columns) >= 7 and f'pid={pid},' in columns[6]:
                    listeners.add((columns[0], int(columns[4].rsplit(':', 1)[-1])))
            if wanted <= listeners:
                if not origin:
                    return
                address = '::1' if s['listen'] == '::' else '127.0.0.1'
                try:
                    probe_tls(address, s['ports']['reality'], s['domain'])
                    return
                except OSError as e:
                    last_error = e
        time.sleep(interval)
        interval = min(interval * 2, 0.2)
    details = f'最后的 TLS 错误：{last_error}。' if last_error else ''
    raise Error('协议端口或 Reality 同域名 TLS 回落未通过启动检查。' + details
                + '请用 journalctl -u sbnpm -u sbnpm-origin 查看日志。')


def write_config(s: dict):
    write_file(CFG, as_json(make_config(s)))
    group_access(CFG)
    write_file(STATE, as_json(s), mode=0o600)
    write_hop_profile(s)
    origin = s.get('origin')
    if origin and origin['local']:
        write_file(ORIGIN_FILE, as_json(origin))
        group_access(ORIGIN_FILE)
    else:
        ORIGIN_FILE.unlink(missing_ok=True)


def check_config(s: dict):
    with tempfile.TemporaryDirectory(dir=BASE) as td:
        path = Path(td) / 'config.json'
        write_file(path, as_json(make_config(s)), mode=0o600)
        run([CORE, 'check', '-c', str(path)], timeout=20)
    apply_nft(s, check=True)


def stop_services():
    systemctl('stop', SERVICE, ORIGIN_SERVICE)


def start_services(s: dict):
    if (s.get('origin') or {}).get('local'):
        systemctl('start', ORIGIN_SERVICE)
    systemctl('start', SERVICE)
    verify_running(s)


def activate(s: dict, old: dict | None, cert_pair=None, *, install=False):
    ensure_user()
    hop_path = BASE / HOP_PROFILE_NAME
    paths = (CFG, STATE, ORIGIN_FILE, hop_path, CERT_DIR / 'fullchain.pem', CERT_DIR / 'privkey.pem')
    snapshots = {p: p.read_bytes() if p.is_file() else None for p in paths}
    old_running = bool(old and active(SERVICE))
    old_enabled = {unit: run(['systemctl', 'is-enabled', '--quiet', unit], check=False).returncode == 0
                   for unit in (SERVICE, SYNC_TIMER)}
    stopped = False
    try:
        if old:
            if cert_pair is None:
                check_config(s)
            stopped = True
            stop_services()
        if cert_pair:
            install_copies(*cert_pair)
        if cert_pair or not old:
            check_config(s)
        write_config(s)
        if old_running or not old or install:
            start_services(s)
        if not old or install:
            systemctl('enable', SERVICE)
            systemctl('enable', '--now', SYNC_TIMER)
    except (Error, OSError):
        if stopped or not old:
            try:
                stop_services()
                for path, data in snapshots.items():
                    if data is None:
                        path.unlink(missing_ok=True)
                    else:
                        private = path in (STATE, hop_path)
                        write_file(path, data, mode=0o600 if private else 0o640)
                        if not private:
                            group_access(path)
                if not old and SYSCTL_BBR_CONF.is_file():
                    SYSCTL_BBR_CONF.unlink(missing_ok=True)
                    run(['sysctl', '--system'], check=False, timeout=15)
                for unit, was_enabled in old_enabled.items():
                    if not was_enabled:
                        systemctl('disable', '--now', unit)
                if old_running:
                    start_services(old)
            except (Error, OSError) as rollback:
                print(f'回滚服务时出错：{rollback}', file=sys.stderr)
        raise


def core_version(binary: str) -> str:
    output = run([binary, 'version'], timeout=10).stdout
    match = re.search(r'^sing-box version v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)\s*$', output, re.M)
    if not match:
        raise Error('无法识别 sing-box 核心版本。')
    return match[1]


def running_core_version() -> str:
    try:
        pid = run(['systemctl', 'show', '-p', 'MainPID', '--value', SERVICE], timeout=5).stdout.strip()
        if pid == '0':
            return '未运行'
        if re.fullmatch(r'[1-9][0-9]*', pid):
            return core_version(f'/proc/{pid}/exe')
    except (Error, OSError):
        pass
    return '无法读取运行版本'


def require_core():
    if tuple(map(int, core_version(CORE).split('.')[:2])) < (1, 12):
        raise Error('同域名握手需要 sing-box 1.12 或更新版本。请升级现有核心后重试。')


def curl_release(*args, timeout: int, limit: int) -> str:
    headers: list[str] = []
    token = os.environ.get('GITHUB_TOKEN', '').strip()
    if token and any('api.github.com' in str(arg) for arg in args):
        headers = ['-H', f'Authorization: Bearer {token}']
    result = run(['curl', '-q', '--fail', '--silent', '--show-error', '--location',
                  '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', '10',
                  '--max-time', str(timeout), '--max-filesize', str(limit), *headers, *args], timeout=timeout + 5)
    return result.stdout


def latest_stable_core() -> tuple[str, str, str, str]:
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(os.uname().machine)
    if not arch:
        raise Error('核心在线更新目前支持 amd64 和 arm64 VPS。')
    release = json.loads(curl_release('-H', 'Accept: application/vnd.github+json', RELEASE_API,
                                      timeout=20, limit=8 * 1024 * 1024))
    tag = release.get('tag_name', '')
    if release.get('draft') is not False or release.get('prerelease') is not False or not re.fullmatch(r'v\d+\.\d+\.\d+', tag):
        raise Error('GitHub 未返回有效的 sing-box 稳定版。')
    version = tag[1:]
    folder = f'sing-box-{version}-linux-{arch}'
    filename = folder + '.tar.gz'
    expected_url = f'{RELEASE_URL}/{tag}/{filename}'
    for asset in release.get('assets', []):
        if asset.get('name') == filename and asset.get('browser_download_url') == expected_url:
            digest = re.fullmatch(r'sha256:([0-9a-f]{64})', asset.get('digest') or '')
            if digest:
                return version, expected_url, digest[1], folder
    raise Error(f'官方稳定版缺少 {filename} 或可验证的 SHA-256 摘要。')


def download_core(staging: Path, url: str, digest: str, folder: str) -> Path:
    archive = staging / 'core.tar.gz'
    curl_release('--output', str(archive), url, timeout=120, limit=CORE_LIMIT)
    sha = hashlib.sha256()
    with archive.open('rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            sha.update(chunk)
    if sha.hexdigest() != digest:
        raise Error('官方核心压缩包 SHA-256 校验失败。')
    candidate = staging / 'sing-box'
    try:
        with tarfile.open(archive, 'r:gz') as tar:
            member = tar.getmember(f'{folder}/sing-box')
            if not member.isfile() or not 0 < member.size <= CORE_LIMIT:
                raise Error('官方压缩包中的 sing-box 文件无效。')
            with tar.extractfile(member) as src, candidate.open('xb') as dst:
                shutil.copyfileobj(src, dst)
    except (KeyError, tarfile.TarError, EOFError) as e:
        raise Error('无法从官方压缩包读取 sing-box 核心。') from e
    candidate.chmod(0o755)
    return candidate


def switch_core(candidate: Path, state: dict):
    core = Path(CORE)
    previous = core.with_name('sing-box.previous')
    backup = candidate.with_name('old-core')
    running = active(SERVICE)
    shutil.copy2(core, backup, follow_symlinks=False)
    os.replace(backup, previous)
    os.replace(candidate, core)
    try:
        if running:
            systemctl('restart', SERVICE)
            verify_running(state)
    except (Error, OSError, KeyboardInterrupt) as e:
        os.replace(previous, core)
        try:
            systemctl('restart', SERVICE)
            verify_running(state)
        except (Error, OSError) as rollback:
            raise Error(f'已恢复旧核心，但服务重启检查失败：{rollback}') from e
        raise Error(f'新核心启动检查失败，已回滚到旧核心：{e}') from e


def cmd_update_core(args):
    state = read_state()
    current = core_version(CORE)
    version, url, digest, folder = latest_stable_core()
    print(f'当前核心：{current}  官方最新稳定版：{version}')
    if current == version:
        print('当前已是最新稳定版。')
        return
    if re.fullmatch(r'\d+\.\d+\.\d+', current) and tuple(map(int, current.split('.'))) > tuple(map(int, version.split('.'))):
        raise Error('本机稳定版高于上游当前标记的最新版本，已跳过降级。')
    if not args.yes and input('更新运行中的核心会短暂中断节点连接。输入 UPDATE 确认：').strip() != 'UPDATE':
        print('已取消。')
        return
    with tempfile.TemporaryDirectory(prefix='.core-', dir=Path(CORE).parent) as tmp:
        candidate = download_core(Path(tmp), url, digest, folder)
        if core_version(str(candidate)) != version:
            raise Error('下载的核心版本与官方稳定版标签不符。')
        run([str(candidate), 'check', '-c', str(CFG)], timeout=30)
        switch_core(candidate, state)
    print(f'sing-box 核心已更新为 {version}。')


def cmd_optimize_bbr(args):
    old = read_state()
    bbr_profile = enable_system_bbr()
    s = {**old, 'bbr': bbr_profile}
    if s == old and CFG.is_file() and json.loads(CFG.read_text()) == make_config(s):
        write_hop_profile(s)
        print('节点传输协议配置已是当前内核最优状态。')
        return
    activate(s, old)
    print('已根据当前系统与 BBR 内核版本更新节点传输协议配置。')


def cmd_udp_optimize(args):
    old = read_state()
    s = dict(old)
    preset = getattr(args, 'preset', None)
    obfs = getattr(args, 'obfs', None)
    obfs_type = getattr(args, 'obfs_type', None)
    obfs_password = getattr(args, 'obfs_password', None)
    up_mbps = getattr(args, 'up_mbps', None)
    down_mbps = getattr(args, 'down_mbps', None)
    hop_interval = getattr(args, 'hop_interval', None)
    hop_interval_max = getattr(args, 'hop_interval_max', None)

    if all(v is None for v in (preset, obfs, obfs_type, obfs_password, up_mbps, down_mbps, hop_interval, hop_interval_max)):
        raise Error('请指定 --preset、--obfs、--obfs-type、--obfs-password、--up-mbps/--down-mbps 或 --hop-interval。')

    if preset == 'peak':
        s['hy2_obfs'] = s.get('hy2_obfs') or secrets.token_urlsafe(18)
        s.setdefault('hy2_obfs_type', 'salamander')
        s['hop_interval'] = 30
        s['hop_interval_max'] = 60
        s['bbr'] = enable_system_bbr()
        if not s.get('extra_ports', {}).get('hy2'):
            print('提示：尚未配置 Hysteria2 备用跳跃端口，端口跳跃暂未生效（建议通过 sb 菜单 4 添加如 20000-40000）。')
    elif preset == 'reset':
        s.pop('hy2_obfs', None)
        s.pop('hy2_obfs_type', None)
        s.pop('hy2_up_mbps', None)
        s.pop('hy2_down_mbps', None)
        s.pop('hop_interval_max', None)
        s['hop_interval'] = DEFAULT_HOP_INTERVAL

    if obfs == 'disable':
        s.pop('hy2_obfs', None)
        s.pop('hy2_obfs_type', None)
    elif obfs == 'enable' or obfs_password or obfs_type:
        s['hy2_obfs'] = obfs_password or s.get('hy2_obfs') or secrets.token_urlsafe(18)
        if obfs_type:
            s['hy2_obfs_type'] = obfs_type
        else:
            s.setdefault('hy2_obfs_type', 'salamander')

    if up_mbps is not None or down_mbps is not None:
        u = validate_bandwidth_mbps(up_mbps if up_mbps is not None else s.get('hy2_up_mbps', 0), '上行带宽')
        d = validate_bandwidth_mbps(down_mbps if down_mbps is not None else s.get('hy2_down_mbps', 0), '下行带宽')
        if u == 0 or d == 0:
            if u != d:
                raise Error('启用 Brutal 带宽控制需同时设置非零的 --up-mbps 与 --down-mbps（同设为 0 则关闭）。')
            s.pop('hy2_up_mbps', None)
            s.pop('hy2_down_mbps', None)
        else:
            s['hy2_up_mbps'] = u
            s['hy2_down_mbps'] = d

    if hop_interval is not None:
        s['hop_interval'] = validate_hop_interval(hop_interval)
    if hop_interval_max is not None:
        if hop_interval_max == 0:
            s.pop('hop_interval_max', None)
        else:
            validate_hop_interval(hop_interval_max)
            base_hop = s.get('hop_interval', DEFAULT_HOP_INTERVAL)
            if hop_interval_max < base_hop:
                raise Error(f'最大跳跃间隔（{hop_interval_max}s）不能小于最小跳跃间隔（{base_hop}s）。')
            s['hop_interval_max'] = hop_interval_max
    elif s.get('hop_interval_max') and s['hop_interval_max'] < s.get('hop_interval', DEFAULT_HOP_INTERVAL):
        s['hop_interval_max'] = s['hop_interval']

    server_cfg_changed = (make_config(s) != make_config(old))
    if s == old:
        write_hop_profile(old)
        print('UDP 抗 QoS 配置无变化。')
        return
    if not server_cfg_changed:
        write_file(STATE, as_json(s), mode=0o600)
        write_hop_profile(s)
        show_udp_profile(s)
        return
    activate(s, old)
    show_udp_profile(s)
    print('提示：开启或更改 Salamander 混淆后，请用 sb 菜单 2 或 5 重新导出客户端节点配置。')


def show_udp_profile(s: dict):
    obfs_state = f"已开启 (salamander, 密码: {s['hy2_obfs']})" if s.get('hy2_obfs') else '未开启（标准 QUIC）'
    if s.get('hy2_up_mbps') and s.get('hy2_down_mbps'):
        bw_state = f"Brutal 恒定速率（客户端上行 {s['hy2_up_mbps']} Mbps / 下行 {s['hy2_down_mbps']} Mbps）"
    else:
        bw_state = '自适应 BBR（未限制固定带宽）'
    hop_min = s.get('hop_interval', DEFAULT_HOP_INTERVAL)
    hop_max = s.get('hop_interval_max')
    hop_desc = f'{hop_min}s–{hop_max}s 随机跳跃' if hop_max and hop_max > hop_min else f'{hop_min}s 固定间隔'
    print(f'Hysteria2 抗 QoS 状态：混淆={obfs_state} | 拥塞控制={bw_state} | 跳跃间隔={hop_desc}')


def resolve_listen_mode(mode: str) -> str:
    if mode in ('dual', '::'):
        if auto_listen() != '::':
            raise Error('当前系统内核未启用 IPv6 或不支持 :: 双栈监听。')
        return '::'
    if mode in ('ipv4', '0.0.0.0'):
        return '0.0.0.0'
    if mode == 'auto':
        return auto_listen()
    raise Error(f'不支持的监听模式：{mode}')


def listen_label(listen: str) -> str:
    return f'{listen}（{"IPv4 + IPv6 双栈" if listen == "::" else "仅 IPv4 单栈"}）'


def cmd_listen_mode(args):
    old = read_state()
    target = resolve_listen_mode(args.mode)
    s = {**old, 'listen': target}
    if s == old:
        print(f'当前已是 {listen_label(target)} 监听模式，无需切换。')
        return
    check_port_plan(s, old)
    activate(s, old)
    print(f'监听模式已切换为：{listen_label(target)}。')


def cmd_reinstall(args):
    ensure_root()
    require_core()
    old = read_state() if STATE.is_file() else None
    containers = docker_containers()
    npms = docker_npms(containers)
    if getattr(args, 'keep_domain', False):
        if not old:
            raise Error('尚未安装 sbnpm，请使用 --domain 指定域名。')
        domain = old['domain']
    elif getattr(args, 'domain', None):
        domain = norm_domain(args.domain)
    elif old and not getattr(args, 'select_domain', False) and not sys.stdin.isatty():
        domain = old['domain']
    else:
        domain = select_domain(None, npms)

    dns = dns_addresses(domain)
    if not dns:
        raise Error(f'域名 {domain} 没有可解析的 A/AAAA 记录；请先将其解析到 VPS。')
    print(f'域名 {domain} DNS 地址：{", ".join(dns)}')
    print('请确认这些地址能直接到达 VPS（Cloudflare DNS 记录需设为 DNS only）。')

    email = getattr(args, 'email', None) or (old.get('email') if old else None)
    if not email and not npms and not find_le(domain) and sys.stdin.isatty():
        email = input('请输入用于申请 Let\'s Encrypt 证书的邮箱：').strip()

    ports = {
        'reality': getattr(args, 'reality_port', None) or (old['ports']['reality'] if old else 8443),
        'hy2': getattr(args, 'hy2_port', None) or (old['ports']['hy2'] if old else DEFAULT_HY2_PORT),
        'tuic': getattr(args, 'tuic_port', None) or (old['ports']['tuic'] if old else DEFAULT_TUIC_PORT),
    }
    listen_arg = getattr(args, 'listen', 'auto')
    listen = listen_arg if listen_arg != 'auto' else (old['listen'] if old else auto_listen())
    has_extra_args = any(getattr(args, proto + '_extra', '') for proto in PROTOCOLS)
    if old and not has_extra_args:
        extra_ports = {k: [tuple(r) for r in v] for k, v in old.get('extra_ports', {}).items()}
    else:
        extra_ports = {proto: parse_ranges(getattr(args, proto + '_extra', '')) for proto in PROTOCOLS}

    hop_arg = getattr(args, 'hop_interval', None)
    hop_interval = validate_hop_interval(hop_arg) if hop_arg is not None else (
        old.get('hop_interval', DEFAULT_HOP_INTERVAL) if old else DEFAULT_HOP_INTERVAL
    )
    s = {
        'schema_version': 2,
        'domain': domain,
        'node_name': resolve_node_name(args, old),
        'ports': ports,
        'listen': listen,
        'extra_ports': extra_ports,
        'hop_interval': hop_interval,
        'reality_sni': domain,
    }
    if not getattr(args, 'no_bbr', False):
        s['bbr'] = enable_system_bbr()
    cert_mode = getattr(args, 'cert_mode', 'auto')
    cert, key, source = choose_source(cert_mode, domain, npms, email)
    s['origin'] = select_origin(args, domain, npms, source)
    check_port_plan(s, old, containers=containers)
    cert_pair = stage_certificate(cert, key, domain)
    r = generate_keys(CORE)
    s.update(
        cert_mode=source,
        email=email or '',
        reality_private=r['private'],
        reality_public=r['public'],
        uuid=str(uuid.uuid4()),
        short_id=secrets.token_hex(8),
        hy2_password=secrets.token_urlsafe(24),
        tuic_uuid=str(uuid.uuid4()),
        tuic_password=secrets.token_urlsafe(24),
        created_at=dt.datetime.now(dt.timezone.utc).isoformat(),
    )
    activate(s, old, cert_pair, install=True)
    print(f'重新安装完成。证书来源：{source}，域名及 Reality SNI：{domain}。')
    print('用 sudo sbnpm nodes 显示新节点。')
    show_ports(s)


def cmd_install(args):
    ensure_root()
    require_core()
    if getattr(args, 'reinstall', False):
        cmd_reinstall(args)
        return
    hop_arg = getattr(args, 'hop_interval', None)
    if hop_arg is not None:
        validate_hop_interval(hop_arg)
    if STATE.exists():
        if not args.upgrade:
            raise Error('已有 sbnpm 安装。用 sb 管理，或使用 sudo sbnpm reinstall 重新安装。')
        old = read_state()
        if args.domain and norm_domain(args.domain) != old['domain']:
            raise Error('升级沿用已安装的域名；如需更换域名请使用 sudo sbnpm reinstall --domain 新域名。')
        if old.get('schema_version') == 2 and not (args.origin_address or args.local_origin_address or args.origin_port or hop_arg is not None):
            legacy = make_config(old)
            legacy['route'].pop('default_domain_resolver')
            if CFG.is_file() and json.loads(CFG.read_text()) == legacy:
                activate(old, old, install=True)
                print('已补齐新版 sing-box 所需的默认 DNS 解析器，节点信息沿用现有配置。')
                return
            s = dict(old)
            if not getattr(args, 'no_bbr', False):
                s['bbr'] = enable_system_bbr()
            desired_cfg = make_config(s)
            current_cfg = json.loads(CFG.read_text()) if CFG.is_file() else None
            if current_cfg != desired_cfg or s != old:
                activate(s, old, install=True)
                print('已应用新版配置与传输优化参数，节点凭据与端口保持不变。')
            else:
                start_services(s)
                write_hop_profile(s)
                systemctl('enable', SERVICE)
                systemctl('enable', '--now', SYNC_TIMER)
                print('sbnpm 已是新版配置，服务检查通过。')
            return
        containers = docker_containers()
        origin = select_origin(args, old['domain'], docker_npms(containers), old['cert_mode'])
        s = {**old, 'schema_version': 2, 'reality_sni': old['domain'], 'origin': origin}
        if hop_arg is not None:
            s['hop_interval'] = hop_arg
        if not getattr(args, 'no_bbr', False):
            s['bbr'] = enable_system_bbr()
        check_port_plan(s, old, containers=containers)
        activate(s, old, install=True)
        print('已升级并保留原有 UUID、密钥和主端口。请用 sb 重新导出客户端节点。')
        return

    containers = docker_containers()
    npms = docker_npms(containers)
    domain = select_domain(args.domain, npms)
    dns = dns_addresses(domain)
    if not dns:
        raise Error(f'域名 {domain} 没有可解析的 A/AAAA 记录；请先将其解析到 VPS。')
    print(f'域名 {domain} DNS 地址：{", ".join(dns)}')
    print('请确认这些地址能直接到达 VPS（Cloudflare DNS 记录需设为 DNS only）。')
    node_name = resolve_node_name(args)
    ports = {'reality': args.reality_port, 'hy2': args.hy2_port, 'tuic': args.tuic_port}
    listen = args.listen if args.listen != 'auto' else auto_listen()
    extra_ports = {proto: parse_ranges(getattr(args, proto + '_extra', '')) for proto in PROTOCOLS}
    if not getattr(args, 'hy2_extra', ''):
        extra_ports['hy2'] = [INSTALL_HY2_HOP_RANGE]
    s = {'schema_version': 2, 'domain': domain, 'node_name': node_name, 'ports': ports, 'listen': listen,
         'extra_ports': extra_ports,
         'hop_interval': hop_arg if hop_arg is not None else INSTALL_HOP_INTERVAL,
         'reality_sni': domain}
    if not getattr(args, 'no_bbr', False):
        s['bbr'] = enable_system_bbr()
    cert, key, source = choose_source(args.cert_mode, domain, npms, args.email)
    s['origin'] = select_origin(args, domain, npms, source)
    check_port_plan(s, containers=containers)
    cert_pair = stage_certificate(cert, key, domain)
    r = generate_keys(CORE)
    s.update(cert_mode=source, email=args.email or '', reality_private=r['private'],
             reality_public=r['public'], uuid=str(uuid.uuid4()), short_id=secrets.token_hex(8),
             hy2_password=secrets.token_urlsafe(24), tuic_uuid=str(uuid.uuid4()),
             tuic_password=secrets.token_urlsafe(24),
             created_at=dt.datetime.now(dt.timezone.utc).isoformat())
    activate(s, None, cert_pair)
    print(f'安装完成。证书来源：{source}，域名及 Reality SNI：{domain}。')
    print('用 sudo sbnpm nodes 显示节点。')
    show_ports(s)


def cmd_configure(args):
    old = read_state()
    hop_interval = getattr(args, 'hop_interval', None)
    if args.port is None and args.extra is None and args.add is None and hop_interval is None:
        raise Error('请指定 --port、--extra、--add 或 --hop-interval。')
    if hop_interval is not None:
        if args.protocol != 'hy2':
            raise Error('--hop-interval 仅适用于 hy2 协议。')
        validate_hop_interval(hop_interval)
    ports = dict(old['ports'])
    extras = {k: [tuple(r) for r in v] for k, v in old.get('extra_ports', {}).items()}
    old_extras = dict(extras)
    if args.port is not None:
        ports[args.protocol] = args.port
    if args.extra is not None:
        extras[args.protocol] = parse_ranges(args.extra)
    if args.add is not None:
        added = format_ranges(extras.get(args.protocol, []))
        extras[args.protocol] = parse_ranges(','.join(filter(None, [added, args.add])))
    s = {**old, 'ports': ports, 'extra_ports': extras}
    if hop_interval is not None:
        s['hop_interval'] = hop_interval
        if s.get('hop_interval_max') and s['hop_interval_max'] < hop_interval:
            s['hop_interval_max'] = hop_interval
    ports_unchanged = (ports == old['ports'] and extras == old_extras)
    hop_unchanged = (s.get('hop_interval', DEFAULT_HOP_INTERVAL) == old.get('hop_interval', DEFAULT_HOP_INTERVAL)
                     and s.get('hop_interval_max') == old.get('hop_interval_max'))
    if ports_unchanged and hop_unchanged:
        write_hop_profile(old)
        print('端口配置无变化。')
        return
    if ports_unchanged and not hop_unchanged:
        write_file(STATE, as_json(s), mode=0o600)
        write_hop_profile(s)
        show_ports(s)
        return
    check_port_plan(s, old)
    activate(s, old)
    show_ports(s)


def cmd_origin_refresh(args):
    old = read_state()
    containers = docker_containers()
    origin = select_origin(args, old['domain'], docker_npms(containers), old['cert_mode'])
    s = {**old, 'schema_version': 2, 'reality_sni': old['domain'], 'origin': origin}
    check_port_plan(s, old, containers=containers)
    activate(s, old)
    print('Reality 同域名握手设置已更新。')


def cmd_origin_serve(args):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            body = b'<!doctype html><title>Welcome</title><h1>Welcome</h1>\n'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)

        do_HEAD = do_GET

        def log_message(self, *args):
            pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['http/1.1'])
    context.load_cert_chain(str(CERT_DIR / 'fullchain.pem'), str(CERT_DIR / 'privkey.pem'))

    origin = json.loads(ORIGIN_FILE.read_text())
    address = origin['address']
    if address not in ('127.0.0.1', '::1'):
        raise Error('内置 HTTPS 握手入口只允许绑定回环地址。')

    conn_sem = threading.BoundedSemaphore(64)

    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if address == '::1' else socket.AF_INET
        request_queue_size = 128
        daemon_threads = True

        def finish_request(self, request, address):
            if not conn_sem.acquire(blocking=False):
                request.close()
                return
            try:
                request.settimeout(5)
                try:
                    with context.wrap_socket(request, server_side=True) as tls:
                        super().finish_request(tls, address)
                except OSError:
                    pass
            finally:
                conn_sem.release()

    with Server((address, origin['port']), Handler) as server:
        server.serve_forever()


def cmd_sync(args):
    ensure_root()
    s = read_state()
    npms = docker_npms() if s['cert_mode'] == 'npm' else []
    cert, key, source = choose_source(s['cert_mode'], s['domain'], npms, s.get('email'),
                                       allow_issue=False)
    c, k = stage_certificate(cert, key, s['domain'])
    cp, kp = CERT_DIR / 'fullchain.pem', CERT_DIR / 'privkey.pem'
    if cp.exists() and kp.exists() and cp.read_bytes() == c and kp.read_bytes() == k:
        print('证书没有变化，无需重启。')
        return
    running = active(SERVICE)
    activate(s, s, (c, k))
    print(f'证书已从 {source} 同步。' + ('服务已重启。' if running else ''))


def show_ports(s):
    extra = s.get('extra_ports', {})
    for name, transport in PROTOCOLS.items():
        fallback = format_ranges(extra.get(name, [])) or '无'
        print(f'{name:7} {transport.upper()} 主端口 {s["ports"][name]}，备用端口 {fallback}')
    if extra.get('hy2'):
        interval = s.get('hop_interval', DEFAULT_HOP_INTERVAL)
        hop_max = s.get('hop_interval_max')
        hop_str = f'{interval}s–{hop_max}s' if hop_max and hop_max > interval else f'{interval}s'
        print(f'Hysteria2 跳跃间隔：{hop_str}，客户端配置：{BASE / HOP_PROFILE_NAME}')
    if s.get('hy2_obfs') or (s.get('hy2_up_mbps') and s.get('hy2_down_mbps')):
        show_udp_profile(s)


def print_qr(qrencode: str, link: str, label: str):
    try:
        qr = run([qrencode, '-t', 'ANSIUTF8', '-l', 'M', '-m', '4', '-o', '-'],
                 input_data=link, timeout=5)
        print(qr.stdout, end='')
    except (Error, OSError):
        print(f'{label} 二维码生成失败，可复制上方链接。', file=sys.stderr)


def cmd_nodes(args):
    ensure_root()
    s = read_state()
    ports = dict(s['ports'])
    if args.port is not None:
        if not args.protocol:
            raise Error('--port 需要与 --protocol 一起指定。')
        extra = s.get('extra_ports', {}).get(args.protocol, [])
        if args.port != ports[args.protocol] and not any(a <= args.port <= b for a, b in extra):
            raise Error('该端口未分配给此协议。')
        ports[args.protocol] = args.port
    links = dict(zip(PROTOCOLS, make_links(s, ports)))
    qrencode = shutil.which('qrencode') if args.qr else None
    if args.qr and qrencode is None:
        print('缺少 qrencode，暂时只显示链接。安装命令：apt-get install -y qrencode', file=sys.stderr)
    for name in (args.protocol,) if args.protocol else PROTOCOLS:
        link = links[name]
        print(link)
        if qrencode:
            print_qr(qrencode, link, name)


def hopping_ports(s: dict):
    ranges = s.get('extra_ports', {}).get('hy2', [])
    if not ranges:
        return []
    port = s['ports']['hy2']
    return sorted([(port, port), *map(tuple, ranges)])


def make_hop_profile(s: dict, ports: list, hop_interval: int | None = None) -> dict:
    interval = validate_hop_interval(
        s.get('hop_interval', DEFAULT_HOP_INTERVAL) if hop_interval is None else hop_interval
    )
    profile = {
        'type': 'hysteria2', 'tag': f'{s.get("node_name") or DEFAULT_NODE_NAME}-hy2-hop', 'server': s['domain'],
        'server_ports': [f'{a}:{b}' for a, b in ports], 'hop_interval': f'{interval}s',
        'password': s['hy2_password'],
        'tls': {'enabled': True, 'server_name': s['domain'], 'alpn': ['h3']}
    }
    bbr = s.get('bbr')
    supports_114 = (isinstance(bbr, dict) and bbr.get('force_bbr_profile')) or core_supports_bbr_profile()
    if hop_interval is None and s.get('hop_interval_max') and s['hop_interval_max'] > interval and supports_114:
        profile['hop_interval_max'] = f"{int(s['hop_interval_max'])}s"
    if isinstance(bbr, dict) and bbr.get('hy2_bbr_profile') and supports_114:
        profile['bbr_profile'] = bbr['hy2_bbr_profile']
    if isinstance(bbr, dict):
        if bbr.get('quic_stream_window'):
            profile['stream_receive_window'] = int(bbr['quic_stream_window'])
        if bbr.get('quic_conn_window'):
            profile['connection_receive_window'] = int(bbr['quic_conn_window'])
        if bbr.get('quic_initial_packet_size'):
            profile['initial_packet_size'] = int(bbr['quic_initial_packet_size'])
    if s.get('hy2_obfs'):
        profile['obfs'] = {'type': s.get('hy2_obfs_type', 'salamander'), 'password': s['hy2_obfs']}
    if s.get('hy2_up_mbps') and s.get('hy2_down_mbps'):
        profile['up_mbps'] = int(s['hy2_up_mbps'])
        profile['down_mbps'] = int(s['hy2_down_mbps'])
    return profile


def write_hop_profile(s: dict):
    path = BASE / HOP_PROFILE_NAME
    ports = hopping_ports(s)
    if ports:
        write_file(path, as_json(make_hop_profile(s, ports)), mode=0o600)
    else:
        path.unlink(missing_ok=True)


def cmd_hop_profile(args):
    s = read_state()
    ports = hopping_ports(s)
    if not ports:
        raise Error('请先为 Hysteria2 添加 UDP 跳跃端口。')
    hop_interval = getattr(args, 'hop_interval', None)
    if hop_interval is not None:
        validate_hop_interval(hop_interval)
    if args.format == 'uri':
        link = make_links(s, hop_ports=format_ranges(ports))[1]
        name = s.get('node_name') or DEFAULT_NODE_NAME
        hop_link = link.replace(f'#{name}-Hysteria2', f'#{name}-Hysteria2-Hop')
        print(hop_link)
        if getattr(args, 'qr', False):
            qrencode = shutil.which('qrencode')
            if qrencode is None:
                print('缺少 qrencode，暂时只显示链接。安装命令：apt-get install -y qrencode', file=sys.stderr)
            else:
                print_qr(qrencode, hop_link, 'hy2-hop')
    else:
        print(json.dumps(make_hop_profile(s, ports, hop_interval=hop_interval), ensure_ascii=False, indent=2))


def current_hop_interval() -> int:
    try:
        return int(read_state().get('hop_interval', DEFAULT_HOP_INTERVAL))
    except (Error, OSError, ValueError, TypeError):
        return DEFAULT_HOP_INTERVAL


def current_domain() -> str:
    try:
        return str(read_state().get('domain', ''))
    except (Error, OSError, ValueError, TypeError):
        return ''


def current_listen() -> str:
    try:
        return str(read_state().get('listen', '::'))
    except (Error, OSError, ValueError, TypeError):
        return '::'


def cmd_menu():
    if not sys.stdin.isatty():
        raise Error('管理菜单需要交互终端。用 sbnpm --help 查看命令行用法。')
    if os.geteuid() != 0:
        os.execvp('sudo', ['sudo', '/usr/local/bin/sbnpm'])
    menu = {
        '1': ('服务、证书与端口状态', ['status']),
        '2': ('显示三协议主端口节点（链接和二维码）', ['nodes', '--qr']),
        '3': ('更改协议主端口', None),
        '4': ('多端口复用 / Hysteria2 跳跃端口及间隔设置', None),
        '5': ('导出 Hysteria2 跳跃节点及 sing-box 出站配置', None),
        '6': ('查看指定端口的节点', None),
        '7': ('重新识别同域名 HTTPS 握手入口', ['refresh-origin']),
        '8': ('同步证书', ['sync-cert']),
        '9': ('检测 NPM 域名与证书', ['list-domains']),
        '10': ('彻底卸载 sbnpm', ['remove']),
        '11': ('更新 sing-box 到官方最新稳定版', ['update-core']),
        '12': ('检测 Ubuntu/内核版本，开启 BBR 并优化节点传输协议', ['optimize-bbr']),
        '13': ('晚高峰 UDP 抗 QoS 优化（Salamander 混淆 / Brutal 带宽 / 随机高频跳跃）', None),
        '14': ('重新安装（可选沿用原域名或更换新域名）', None),
        '15': ('切换监听模式（IPv4+IPv6 双栈 :: / 仅 IPv4 单栈 0.0.0.0）', None),
    }
    while True:
        print(f'\n=== sbnpm 设置 {SCRIPT_VERSION} ===')
        print(f'运行中的 sing-box 版本：{running_core_version()}')
        for k, (label, _) in menu.items():
            print(f' {k}. {label}')
        print(' 0. 退出')
        try:
            picked = input('请选择：').strip()
            if picked in ('', '0'):
                return
            if picked not in menu:
                print('请输入菜单编号。')
                continue
            if picked == '5':
                main(['hop-profile', '--format', 'uri'])
                main(['hop-profile'])
                continue
            if picked == '13':
                sub_op = input(
                    '[1] 一键晚高峰抗限速预设（开启 Salamander 混淆 + 30–60s 随机跳跃 + 内核队列调优）\n'
                    '[2] 单独开关 Hysteria2 Salamander 混淆\n'
                    '[3] 设置 Hysteria2 Brutal 真实上下行带宽（抗晚高峰高丢包）\n'
                    '[4] 恢复默认标准 QUIC 模式\n'
                    '请选择：'
                ).strip()
                if sub_op == '1':
                    main(['udp-optimize', '--preset', 'peak'])
                elif sub_op == '2':
                    toggle = input('[1] 开启 Salamander 混淆  [2] 关闭混淆：').strip()
                    if toggle == '1':
                        pwd_in = input('自定义混淆密码（回车自动生成随机高强度密码）：').strip()
                        cmd = ['udp-optimize', '--obfs', 'enable']
                        if pwd_in:
                            cmd.extend(['--obfs-password', pwd_in])
                        main(cmd)
                    elif toggle == '2':
                        main(['udp-optimize', '--obfs', 'disable'])
                elif sub_op == '3':
                    up_in = input('客户端晚高峰实际上行带宽 Mbps（输入 0 关闭固定带宽并恢复 BBR）：').strip()
                    down_in = input('客户端晚高峰实际下行带宽 Mbps（输入 0 关闭固定带宽并恢复 BBR）：').strip()
                    if not (up_in.isdecimal() and down_in.isdecimal()):
                        print('请输入整数 Mbps 数值。')
                        continue
                    main(['udp-optimize', '--up-mbps', up_in, '--down-mbps', down_in])
                elif sub_op == '4':
                    main(['udp-optimize', '--preset', 'reset'])
                continue
            if picked == '14':
                existing_dom = current_domain()
                if existing_dom:
                    dom_op = input(f'[1] 使用原域名重新安装 ({existing_dom})  [2] 更换新域名重新安装：').strip()
                else:
                    dom_op = '2'
                if dom_op not in ('1', '2'):
                    continue
                if dom_op == '1':
                    reinstall_args = ['reinstall', '--keep-domain']
                else:
                    new_dom = input('请输入新域名（直接回车自动扫描并选择 NPM 域名）：').strip()
                    reinstall_args = ['reinstall', '--domain', new_dom] if new_dom else ['reinstall', '--select-domain']
                if input('重新安装会重置节点 UUID、Reality 密钥及密码。输入 REINSTALL 确认：').strip() != 'REINSTALL':
                    print('已取消。')
                    continue
                main(reinstall_args)
                continue
            if picked == '15':
                cur = current_listen()
                mode_op = input(
                    f'当前监听模式：{listen_label(cur)}\n'
                    '[1] IPv4 + IPv6 双栈监听 (::)\n'
                    '[2] 仅 IPv4 单栈监听 (0.0.0.0)\n'
                    '[3] 自动检测 (auto)\n'
                    '请选择：'
                ).strip()
                mode_map = {'1': '::', '2': '0.0.0.0', '3': 'auto'}
                if mode_op in mode_map:
                    main(['listen-mode', mode_map[mode_op]])
                continue
            args = menu[picked][1]
            if args == ['remove']:
                if confirm_remove() and main(['remove', '--yes']) == 0:
                    return
                continue
            if args is None:
                protocol = input('协议 [1] Reality  [2] Hysteria2  [3] TUIC：').strip()
                if protocol not in ('1', '2', '3'):
                    print('请输入协议编号 1–3。')
                    continue
                proto = tuple(PROTOCOLS)[int(protocol) - 1]
                if picked == '4':
                    if proto == 'hy2':
                        op = input('[1] 添加  [2] 替换  [3] 清空  [4] 修改跳跃间隔：').strip()
                        if op not in ('1', '2', '3', '4'):
                            continue
                        if op == '4':
                            default_hop = current_hop_interval()
                            interval = input(
                                f'端口跳跃间隔（秒，{MIN_HOP_INTERVAL}–{MAX_HOP_INTERVAL}）[{default_hop}]：'
                            ).strip() or str(default_hop)
                            if not interval.isdecimal():
                                print('请输入数字秒数。')
                                continue
                            args = ['ports', proto, '--hop-interval', interval]
                        else:
                            ranges = '' if op == '3' else input('端口示例 30000,30100-30120：').strip()
                            if op != '3' and not ranges:
                                continue
                            args = ['ports', proto, '--add' if op == '1' else '--extra', ranges]
                            if op in ('1', '2'):
                                default_hop = current_hop_interval()
                                interval = input(
                                    f'端口跳跃间隔（秒，{MIN_HOP_INTERVAL}–{MAX_HOP_INTERVAL}，回车默认 {default_hop}）：'
                                ).strip()
                                if interval:
                                    if not interval.isdecimal():
                                        print('请输入数字秒数。')
                                        continue
                                    args.extend(['--hop-interval', interval])
                    else:
                        op = input('[1] 添加  [2] 替换  [3] 清空：').strip()
                        if op not in ('1', '2', '3'):
                            continue
                        ranges = '' if op == '3' else input('端口示例 30000,30100-30120：').strip()
                        if op != '3' and not ranges:
                            continue
                        args = ['ports', proto, '--add' if op == '1' else '--extra', ranges]
                else:
                    port = input('端口：').strip()
                    if not port.isdecimal():
                        print('请输入数字端口。')
                        continue
                    args = ['ports', proto, '--port', port] if picked == '3' else [
                        'nodes', '--protocol', proto, '--port', port]
            main(args)
        except (EOFError, KeyboardInterrupt):
            print()
            return


def cmd_status(args):
    ensure_root()
    s = read_state()
    print('域名:', s['domain'], '\n证书模式:', s['cert_mode'],
          '\nReality 握手 SNI:', s['reality_sni'], '\n监听地址:', listen_label(s['listen']))
    show_ports(s)
    if isinstance(s.get('bbr'), dict):
        print_bbr_summary(s['bbr'])
    else:
        os_info = detect_os_info()
        print_bbr_summary(build_transport_profile(os_info, detect_bbr_info(os_info)))
    print('DNS:', ', '.join(dns_addresses(s['domain'])) or '无法解析')
    if nft_rules(s):
        ready = run(['nft', 'list', 'table', 'inet', NFT_TABLE], check=False, timeout=15).returncode == 0
        print('备用端口转发规则：' + ('已加载' if ready else '未加载，请检查服务或重启 sbnpm'))
    for unit in (SERVICE, SYNC_TIMER):
        proc = run(['systemctl', 'is-active', unit], check=False)
        print(unit, ':', proc.stdout.strip() or proc.stderr.strip())
    try:
        cert_valid(CERT_DIR / 'fullchain.pem', CERT_DIR / 'privkey.pem', s['domain'])
        print('当前本地 TLS 证书: SAN 匹配，证书与密钥匹配，有效期大于 2 天')
    except Error as e:
        print('证书检查失败:', e)
    origin = s.get('origin')
    if origin:
        address, port = origin['address'], origin['port']
        print(f"Reality 握手目标：{s['domain']} → [{address}]:{port}")
        try:
            print('HTTPS 握手检测：TLS 1.3，' + probe_tls(address, port, s['domain']))
        except OSError as e:
            print(f'HTTPS 握手入口异常：{e}。可用 sbnpm refresh-origin 重新识别。')
    else:
        print('当前是旧版握手配置，可用新版 install.sh 升级。')


def confirm_remove() -> bool:
    print('卸载会停用本项目的节点，并删除其配置、密钥、证书副本及端口转发规则。')
    print('会保留 NPM、Certbot、原始证书及共享的 sing-box 核心。')
    if input('确认卸载请输入 REMOVE：').strip() == 'REMOVE':
        return True
    print('已取消。')
    return False


def remove_owned_account():
    import grp
    import pwd

    marker = BASE / 'account.json'
    if not marker.is_file():
        return
    owner = json.loads(marker.read_text())
    try:
        account = pwd.getpwnam('sbnpm')
    except KeyError:
        pass
    else:
        if (account.pw_uid, account.pw_gid) != (owner['uid'], owner['gid']):
            print('系统账户 sbnpm 的 UID/GID 已变更，已保留。')
            return
        run(['userdel', 'sbnpm'])
    try:
        group = grp.getgrnam('sbnpm')
    except KeyError:
        return
    if (group.gr_gid == owner['gid'] and not group.gr_mem
            and not any(user.pw_gid == group.gr_gid for user in pwd.getpwall())):
        run(['groupdel', 'sbnpm'])


def cmd_remove(args):
    ensure_root()
    if not args.yes and not confirm_remove():
        return

    units = [unit for unit in (SYNC_TIMER, SYNC_SERVICE, SERVICE, ORIGIN_SERVICE)
             if (SYSTEMD_DIR / unit).is_file()]
    if SYNC_TIMER in units:
        systemctl('disable', '--now', SYNC_TIMER)
    services = [unit for unit in units if unit != SYNC_TIMER]
    if services:
        systemctl('stop', *services)
    if SERVICE in units:
        systemctl('disable', SERVICE)
    clear_nft()
    SYSCTL_BBR_CONF.unlink(missing_ok=True)

    remove_owned_account()
    TIMER_STAMP.unlink(missing_ok=True)
    for unit in units:
        (SYSTEMD_DIR / unit).unlink(missing_ok=True)
    systemctl('daemon-reload')
    if BASE.is_dir():
        shutil.rmtree(BASE)

    app = INSTALL_DIR / 'sbnpm.py'
    for name in ('sbnpm', 'sb'):
        launcher = BIN_DIR / name
        if launcher.is_symlink() and launcher.resolve() == app:
            backup = launcher.with_name('sb.pre-sbnpm')
            if name == 'sb' and (backup.exists() or backup.is_symlink()):
                backup.replace(launcher)
            else:
                launcher.unlink()
    if INSTALL_DIR.is_dir():
        shutil.rmtree(INSTALL_DIR)
    print('sbnpm 已卸载。')


def origin_args(parser):
    address = parser.add_mutually_exclusive_group()
    address.add_argument('--origin-address', help='已运行的同域名 HTTPS 入口 IP')
    address.add_argument('--local-origin-address', choices=['127.0.0.1', '::1'], help='启用内置 HTTPS 源站并绑定指定回环 IP')
    parser.add_argument('--origin-port', type=int, help='HTTPS 握手目标端口')


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(prog='sbnpm', description='sing-box 三协议及 NPM 同域名握手')
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('list-domains', help='识别 NPM 域名和可信证书').set_defaults(func=cmd_list)
    install = sub.add_parser('install', help='安装 Reality Vision、Hysteria2、TUIC v5')
    install.add_argument('--domain', help='客户端连接域名及 Reality SNI')
    install.add_argument('--node-name', help='节点名称，用于订阅链接后缀（回车默认 sbnpm）')
    install.add_argument('--email', help='无 NPM 时 ACME 申请邮箱')
    install.add_argument('--cert-mode', choices=['auto', 'npm', 'letsencrypt'], default='auto')
    install.add_argument('--reality-port', type=int, default=8443)
    install.add_argument('--hy2-port', type=int, default=DEFAULT_HY2_PORT, help='Hysteria2 主端口（默认 55667）')
    install.add_argument('--tuic-port', type=int, default=DEFAULT_TUIC_PORT, help='TUIC 主端口（默认 55668）')
    for proto in PROTOCOLS:
        install.add_argument(f'--{proto}-extra', default='', help='备用端口，例如 30000,30100-30120')
    install.add_argument('--hop-interval', type=int, help='Hysteria2 端口跳跃间隔（秒，5–3600，默认 10）')
    install.add_argument('--no-bbr', action='store_true', help='跳过自动开启 BBR 及内核传输参数调优')
    install.add_argument('--listen', choices=['auto', '0.0.0.0', '::'], default='auto')
    install.add_argument('--upgrade', action='store_true', help=argparse.SUPPRESS)
    install.add_argument('--reinstall', action='store_true', help='重新安装并重置节点密钥（可选原域名或新域名）')
    origin_args(install)
    install.set_defaults(func=cmd_install, write=True)
    reinstall = sub.add_parser('reinstall', help='重新安装并重置节点密钥（支持沿用原域名或更换新域名）')
    dom_group = reinstall.add_mutually_exclusive_group()
    dom_group.add_argument('--domain', help='更换为指定新域名（或指定原域名）')
    dom_group.add_argument('--keep-domain', action='store_true', help='沿用当前已安装的域名重新安装')
    dom_group.add_argument('--select-domain', action='store_true', help='交互式扫描并选择域名')
    reinstall.add_argument('--email', help='无 NPM 时 ACME 申请邮箱')
    reinstall.add_argument('--node-name', help='节点名称，用于订阅链接后缀（默认沿用现有）')
    reinstall.add_argument('--cert-mode', choices=['auto', 'npm', 'letsencrypt'], default='auto')
    reinstall.add_argument('--reality-port', type=int, help='Reality 主端口（默认沿用现有或 8443）')
    reinstall.add_argument('--hy2-port', type=int, help='Hysteria2 主端口（默认沿用现有或 55667）')
    reinstall.add_argument('--tuic-port', type=int, help='TUIC 主端口（默认沿用现有或 55668）')
    for proto in PROTOCOLS:
        reinstall.add_argument(f'--{proto}-extra', default='', help='备用端口，例如 30000,30100-30120')
    reinstall.add_argument('--hop-interval', type=int, help='Hysteria2 端口跳跃间隔（秒，5–3600）')
    reinstall.add_argument('--no-bbr', action='store_true', help='跳过自动开启 BBR 及内核传输参数调优')
    reinstall.add_argument('--listen', choices=['auto', '0.0.0.0', '::'], default='auto')
    origin_args(reinstall)
    reinstall.set_defaults(func=cmd_reinstall, write=True)
    listen_cmd = sub.add_parser('listen-mode', help='切换节点监听模式（双栈 :: / 仅 IPv4 单栈 0.0.0.0）')
    listen_cmd.add_argument('mode', choices=['auto', '::', '0.0.0.0', 'dual', 'ipv4'],
                            help='::/dual: IPv4+IPv6 双栈；0.0.0.0/ipv4: 仅 IPv4 单栈；auto: 自动检测')
    listen_cmd.set_defaults(func=cmd_listen_mode, write=True)
    ports = sub.add_parser('ports', help='更改主端口或添加、替换备用端口及跳跃间隔')
    ports.add_argument('protocol', choices=PROTOCOLS)
    ports.add_argument('--port', type=int, help='新主端口')
    extras = ports.add_mutually_exclusive_group()
    extras.add_argument('--extra', help='替换备用端口列表，空字符串表示清空')
    extras.add_argument('--add', help='添加备用端口')
    ports.add_argument('--hop-interval', type=int, help='Hysteria2 端口跳跃间隔（秒，5–3600）')
    ports.set_defaults(func=cmd_configure, write=True)
    refresh = sub.add_parser('refresh-origin', help='更新 Reality 同域名 HTTPS 握手入口')
    origin_args(refresh)
    refresh.set_defaults(func=cmd_origin_refresh, write=True)
    sub.add_parser('sync-cert', help='同步证书并按需重启服务').set_defaults(func=cmd_sync, write=True)
    nodes = sub.add_parser('nodes', help='显示含认证信息的客户端节点')
    nodes.add_argument('--protocol', choices=PROTOCOLS)
    nodes.add_argument('--port', type=int)
    nodes.add_argument('--qr', action='store_true', help='在终端显示节点二维码')
    nodes.set_defaults(func=cmd_nodes)
    hop = sub.add_parser('hop-profile', help='导出 Hysteria2 跳跃客户端配置')
    hop.add_argument('--format', choices=['json', 'uri'], default='json')
    hop.add_argument('--hop-interval', type=int, help='覆盖导出的端口跳跃间隔（秒，5–3600）')
    hop.add_argument('--qr', action='store_true', help='当格式为 uri 时显示二维码')
    hop.set_defaults(func=cmd_hop_profile, write=True)
    sub.add_parser('status', help='检查运行状态及证书').set_defaults(func=cmd_status)
    sub.add_parser('optimize-bbr', help='检测 Ubuntu/内核版本，开启 BBR 并根据 BBR 版本优化节点传输协议').set_defaults(
        func=cmd_optimize_bbr, write=True)
    udp_opt = sub.add_parser('udp-optimize', help='晚高峰 UDP 抗 QoS 优化（Salamander 混淆、Brutal 带宽、随机跳跃）')
    udp_opt.add_argument('--preset', choices=['peak', 'reset'], help='peak: 一键开启晚高峰抗限速预设；reset: 恢复默认标准 QUIC')
    udp_opt.add_argument('--obfs', choices=['enable', 'disable'], help='开启或关闭 Hysteria2 混淆')
    udp_opt.add_argument('--obfs-type', choices=['salamander', 'gecko'], help='Hysteria2 混淆类型（gecko 需 sing-box 1.14+）')
    udp_opt.add_argument('--obfs-password', help='指定 Salamander 混淆密码')
    udp_opt.add_argument('--up-mbps', type=int, help='客户端上行带宽 Mbps（0 表示恢复自适应 BBR）')
    udp_opt.add_argument('--down-mbps', type=int, help='客户端下行带宽 Mbps（0 表示恢复自适应 BBR）')
    udp_opt.add_argument('--hop-interval', type=int, help='Hysteria2 最小端口跳跃间隔（秒，5–3600）')
    udp_opt.add_argument('--hop-interval-max', type=int, help='Hysteria2 最大随机端口跳跃间隔（秒，0 表示固定间隔）')
    udp_opt.set_defaults(func=cmd_udp_optimize, write=True)
    update = sub.add_parser('update-core', help='原地更新本项目的 sing-box 核心至官方最新稳定版')
    update.add_argument('--yes', action='store_true', help='跳过更新确认')
    update.set_defaults(func=cmd_update_core, write=True)
    remove = sub.add_parser('remove', help='卸载本项目')
    remove.set_defaults(func=cmd_remove, write=True)
    remove.add_argument('--yes', action='store_true', help='不提示确认')
    try:
        if not argv:
            cmd_menu()
        elif argv == ['_serve-origin']:
            cmd_origin_serve(None)
        elif argv in (['_apply-ports'], ['_clear-ports']):
            ensure_root()
            if argv == ['_apply-ports']:
                apply_nft(read_state())
            else:
                clear_nft()
        else:
            args = parser.parse_args(argv)
            if getattr(args, 'write', False):
                ensure_root()
                lock = os.open('/run/lock/sbnpm.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    args.func(args)
                finally:
                    os.close(lock)
            else:
                if getattr(args, 'root', False):
                    ensure_root()
                args.func(args)
    except (Error, OSError, ValueError) as e:
        print(f'错误：{e}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
