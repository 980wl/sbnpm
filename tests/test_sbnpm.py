import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sbnpm


def mkcert(folder: Path, sans: str = 'DNS:node.example.com,DNS:*.example.org'):
    folder.mkdir(parents=True, exist_ok=True)
    key = folder / 'privkey.pem'
    cert = folder / 'fullchain.pem'
    p = subprocess.run(['openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048',
                        '-nodes', '-keyout', str(key), '-out', str(cert),
                        '-days', '30', '-subj', '/CN=node.example.com',
                        '-addext', f'subjectAltName={sans}'],
                       capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(p.stderr)
    return cert, key


class DomainTests(unittest.TestCase):
    def test_normalize_and_bad_domains(self):
        self.assertEqual(sbnpm.norm_domain(' NODE.EXAMPLE.COM. '), 'node.example.com')
        self.assertEqual(sbnpm.norm_domain('例子.测试'), 'xn--fsqu00a.xn--0zwm56d')
        for v in ('127.0.0.1', 'localhost', '*.example.com', 'evil@domain.com',
                  '-a.example.com', 'example..com'):
            with self.subTest(v=v), self.assertRaises(sbnpm.Error):
                sbnpm.norm_domain(v)

    def test_wildcard_only_one_level(self):
        self.assertTrue(sbnpm.covers('*.example.org', 'a.example.org'))
        self.assertFalse(sbnpm.covers('*.example.org', 'example.org'))
        self.assertFalse(sbnpm.covers('*.example.org', 'a.b.example.org'))
        self.assertTrue(sbnpm.covers('node.example.com', 'node.example.com'))


class CertificateTests(unittest.TestCase):
    def test_san_match_expiry_key(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            c, k = mkcert(folder)
            sbnpm.cert_valid(c, k, 'node.example.com')
            sbnpm.cert_valid(c, k, 'a.example.org')
            with self.assertRaises(sbnpm.Error):
                sbnpm.cert_valid(c, k, 'example.org')
            with self.assertRaises(sbnpm.Error):
                sbnpm.cert_valid(c, k, 'node.example.com', min_days=40)
            c2, k2 = mkcert(folder / 'another')
            with self.assertRaises(sbnpm.Error):
                sbnpm.cert_valid(c, k2, 'node.example.com')

    def test_npm_scan_hostnames_cert(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            live = root / 'letsencrypt' / 'live' / 'npm-2'
            mkcert(live)
            hosts = root / 'data' / 'nginx' / 'proxy_host'
            hosts.mkdir(parents=True)
            (hosts / '1.conf').write_text('server_name node.example.com api.example.org;\n')
            npm = {'name': 'npm', 'id': '12345', 'letsencrypt': root / 'letsencrypt',
                   'data': root / 'data'}
            self.assertEqual(sbnpm.discover_domains([npm]), [])
            rejected, _ = mkcert(root / 'letsencrypt' / 'live' / 'npm-1')
            with mock.patch.object(sbnpm, 'cert_publicly_trusted', side_effect=lambda cert: cert != rejected):
                self.assertEqual(sbnpm.discover_domains([npm]), ['api.example.org', 'node.example.com'])
                found = sbnpm.choose_source('npm', 'api.example.org', [npm], None)
            self.assertEqual(found[0], live / 'fullchain.pem')
            self.assertEqual(sbnpm.npm_hostnames(npm), {'node.example.com', 'api.example.org'})

    def test_npm_docker_detect_named_volume(self):
        sample = [{'Id': '1234567890123456', 'Name': '/app',
                   'Config': {'Image': 'jc21/nginx-proxy-manager:latest'},
                   'NetworkSettings': {'Ports': {'443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '10443'}]},
                                       'Networks': {'default': {'IPAddress': '172.30.0.7'}}},
                   'Mounts': [{'Destination': '/etc/letsencrypt', 'Source': '/var/lib/docker/volumes/a/_data'},
                              {'Destination': '/data', 'Source': '/opt/npm/data'}]},
                  {'Config': {'Image': 'nginx:latest'}, 'Mounts': []}]
        def fake_run(args, **kwargs):
            if args[:2] == ['docker', 'ps']:
                return subprocess.CompletedProcess(args, 0, '1234567890123456\n2\n', '')
            return subprocess.CompletedProcess(args, 0, json.dumps(sample), '')
        with mock.patch.object(sbnpm.shutil, 'which', return_value='/usr/bin/docker'), \
             mock.patch.object(sbnpm, 'run', side_effect=fake_run):
            got = sbnpm.docker_npms()
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]['name'], 'app')
        self.assertEqual(got[0]['letsencrypt'], Path('/var/lib/docker/volumes/a/_data'))
        self.assertEqual(got[0]['endpoints'], [('127.0.0.1', 10443), ('172.30.0.7', 443)])

    def test_fail_safe_on_running_npm_without_cert(self):
        npms = [{'name': 'npm', 'letsencrypt': None, 'data': None}]
        with self.assertRaisesRegex(sbnpm.Error, '请先在 NPM 签发证书'):
            sbnpm.choose_source('auto', 'node.example.com', npms, None)
        with self.assertRaisesRegex(sbnpm.Error, 'NPM 中找不到'):
            sbnpm.choose_source('npm', 'node.example.com', npms, None)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.s = {
            'domain': 'node.example.com', 'cert_mode': 'npm', 'listen': '::',
            'ports': {'reality': 8443, 'hy2': 24443, 'tuic': 24444},
            'uuid': '12345678-1234-1234-1234-123456789abc',
            'tuic_uuid': '87654321-4321-4321-4321-cba987654321',
            'reality_private': 'private', 'reality_public': 'public',
            'reality_sni': 'www.microsoft.com', 'short_id': '0123456789abcdef',
            'hy2_password': 'hy-secret', 'tuic_password': 'tuic-secret'}

    def test_three_protocols_and_separate_reality_sni(self):
        conf = sbnpm.make_config(self.s)
        inb = conf['inbounds']
        self.assertEqual([x['type'] for x in inb], ['vless', 'hysteria2', 'tuic'])
        self.assertEqual(inb[0]['users'][0]['flow'], 'xtls-rprx-vision')
        self.assertEqual(inb[0]['tls']['server_name'], 'www.microsoft.com')
        self.assertEqual(inb[1]['tls']['server_name'], 'node.example.com')
        self.assertNotIn('certificate_path', inb[0]['tls'])
        self.assertEqual(inb[2]['congestion_control'], 'bbr')
        self.assertNotIn('vmess', json.dumps(conf).lower())
        self.assertNotIn('anytls', json.dumps(conf).lower())

    def test_uris(self):
        links = sbnpm.make_links(self.s)
        self.assertEqual(len(links), 3)
        self.assertIn('node.example.com:8443', links[0])
        self.assertIn('sni=www.microsoft.com', links[0])
        self.assertIn('pbk=public', links[0])
        self.assertIn('node.example.com:24443', links[1])
        self.assertIn('node.example.com:24444', links[2])
        self.assertTrue(links[2].startswith('tuic://'))

    def test_ports_conflict_mock(self):
        with mock.patch.object(sbnpm, 'docker_containers', return_value=[]), \
             mock.patch.object(sbnpm, 'port_available', return_value=False):
            with self.assertRaisesRegex(sbnpm.Error, '8443'):
                sbnpm.check_port_plan(self.s)

    def test_cli_help(self):
        proc = subprocess.run([sys.executable, str(Path(sbnpm.__file__)), '--help'],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('list-domains', proc.stdout)
        self.assertIn('reinstall', proc.stdout)
        self.assertIn('listen-mode', proc.stdout)

    def test_node_link_no_private_key(self):
        links = '\n'.join(sbnpm.make_links(self.s))
        self.assertNotIn('private', links)
        self.assertIn('tuic-secret@', links)  # 链接包含客户端密码，必须保密

    def test_primary_nodes_send_each_link_to_local_qrencode(self):
        links = sbnpm.make_links(self.s)
        with mock.patch.object(sbnpm, 'ensure_root'), \
             mock.patch.object(sbnpm, 'read_state', return_value=self.s), \
             mock.patch.object(sbnpm.shutil, 'which', return_value='/usr/bin/qrencode'), \
             mock.patch.object(sbnpm, 'run', side_effect=[
                 SimpleNamespace(stdout=f'QR-{i}\n') for i in range(3)
             ]) as run, contextlib.redirect_stdout(io.StringIO()) as out:
            sbnpm.cmd_nodes(SimpleNamespace(port=None, protocol=None, qr=True))
        self.assertEqual([c.kwargs['input_data'] for c in run.call_args_list], links)
        self.assertTrue(all(c.args[0][0] == '/usr/bin/qrencode' for c in run.call_args_list))
        self.assertEqual(out.getvalue().splitlines(),
                         [value for i, link in enumerate(links) for value in (link, f'QR-{i}')])

    def test_nodes_without_qr_keeps_plain_links(self):
        with mock.patch.object(sbnpm, 'ensure_root'), \
             mock.patch.object(sbnpm, 'read_state', return_value=self.s), \
             mock.patch.object(sbnpm.shutil, 'which') as which, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            sbnpm.cmd_nodes(SimpleNamespace(port=None, protocol=None, qr=False))
        which.assert_not_called()
        self.assertEqual(out.getvalue().splitlines(), sbnpm.make_links(self.s))

    def test_same_domain_handshake_with_private_resolution(self):
        s = {**self.s, 'reality_sni': self.s['domain'],
             'origin': {'address': '127.0.0.1', 'port': 10443, 'local': False}}
        conf = sbnpm.make_config(s)
        tls = conf['inbounds'][0]['tls']
        self.assertEqual(tls['server_name'], s['domain'])
        self.assertEqual(tls['reality']['handshake'],
                         {'server': s['domain'], 'server_port': 10443, 'domain_resolver': 'reality-origin'})
        self.assertEqual(conf['dns']['servers'][1]['predefined'], {s['domain']: '127.0.0.1'})
        self.assertEqual(conf['dns']['servers'][0], {'type': 'local', 'tag': 'system'})
        self.assertEqual(conf['dns']['final'], 'system')
        self.assertEqual(conf['route']['default_domain_resolver'], 'system')
        self.assertIn('sni=node.example.com', sbnpm.make_links(s)[0])

    def test_legacy_managed_config_is_migrated_with_existing_credentials(self):
        old = {**self.s, 'schema_version': 2, 'reality_sni': self.s['domain'],
               'origin': {'address': '127.0.0.1', 'port': 443, 'local': False}}
        legacy = sbnpm.make_config(old)
        legacy['route'].pop('default_domain_resolver')
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / 'config.json'
            cfg.write_bytes(sbnpm.as_json(legacy))
            with mock.patch.multiple(sbnpm, CFG=cfg, STATE=cfg), \
                 mock.patch.object(sbnpm, 'ensure_root'), mock.patch.object(sbnpm, 'require_core'), \
                 mock.patch.object(sbnpm, 'read_state', return_value=old), \
                 mock.patch.object(sbnpm, 'activate') as activate, \
                 contextlib.redirect_stdout(io.StringIO()):
                sbnpm.cmd_install(SimpleNamespace(upgrade=True, domain=None,
                                                  origin_address=None, local_origin_address=None, origin_port=None))
            activate.assert_called_once_with(old, old, install=True)

    def test_reinstall_keeps_or_changes_domain_and_regenerates_credentials(self):
        old = {**self.s, 'schema_version': 2, 'reality_sni': self.s['domain'],
               'extra_ports': {'hy2': [[30000, 30005]]}, 'hop_interval': 15}
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / 'state.json'
            state_file.write_bytes(sbnpm.as_json(old))
            for keep, new_dom, expected_dom in ((True, None, 'node.example.com'),
                                                (False, 'new.example.org', 'new.example.org')):
                with mock.patch.multiple(sbnpm, STATE=state_file), \
                     mock.patch.object(sbnpm, 'ensure_root'), mock.patch.object(sbnpm, 'require_core'), \
                     mock.patch.object(sbnpm, 'read_state', return_value=old), \
                     mock.patch.object(sbnpm, 'docker_containers', return_value=[]), \
                     mock.patch.object(sbnpm, 'docker_npms', return_value=[]), \
                     mock.patch.object(sbnpm, 'dns_addresses', return_value=['203.0.113.10']), \
                     mock.patch.object(sbnpm, 'enable_system_bbr', return_value={'generation': 'bbrv1'}), \
                     mock.patch.object(sbnpm, 'choose_source', return_value=(Path('/c'), Path('/k'), 'npm')), \
                     mock.patch.object(sbnpm, 'select_origin', return_value={'address': '127.0.0.1', 'port': 443, 'local': False}), \
                     mock.patch.object(sbnpm, 'check_port_plan') as check_ports, \
                     mock.patch.object(sbnpm, 'stage_certificate', return_value=(b'cert', b'key')), \
                     mock.patch.object(sbnpm, 'generate_keys', return_value={'private': 'new-priv', 'public': 'new-pub'}), \
                     mock.patch.object(sbnpm, 'activate') as activate, \
                     contextlib.redirect_stdout(io.StringIO()):
                    sbnpm.cmd_reinstall(SimpleNamespace(
                        keep_domain=keep, domain=new_dom, select_domain=False,
                        email='a@b.com', cert_mode='auto',
                        reality_port=None, hy2_port=None, tuic_port=None,
                        reality_extra='', hy2_extra='', tuic_extra='',
                        hop_interval=None, no_bbr=False, listen='auto',
                        origin_address=None, local_origin_address=None, origin_port=None))
                new_state = activate.call_args[0][0]
                self.assertEqual(new_state['domain'], expected_dom)
                self.assertEqual(new_state['reality_sni'], expected_dom)
                self.assertNotEqual(new_state['uuid'], old['uuid'])
                self.assertEqual(new_state['reality_public'], 'new-pub')
                self.assertEqual(new_state['hop_interval'], 15)
                check_ports.assert_called_once()

    def test_listen_mode_switching_between_dual_and_single_stack(self):
        old_ipv4 = {**self.s, 'listen': '0.0.0.0'}
        with mock.patch.object(sbnpm, 'read_state', return_value=old_ipv4), \
             mock.patch.object(sbnpm, 'auto_listen', return_value='::'), \
             mock.patch.object(sbnpm, 'check_port_plan') as check_ports, \
             mock.patch.object(sbnpm, 'activate') as activate, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            sbnpm.cmd_listen_mode(SimpleNamespace(mode='0.0.0.0'))
            self.assertIn('无需切换', out.getvalue())
            activate.assert_not_called()

            sbnpm.cmd_listen_mode(SimpleNamespace(mode='dual'))
            check_ports.assert_called_once()
            activate.assert_called_once_with({**old_ipv4, 'listen': '::'}, old_ipv4)

        with mock.patch.object(sbnpm, 'auto_listen', return_value='0.0.0.0'):
            with self.assertRaisesRegex(sbnpm.Error, '未启用 IPv6'):
                sbnpm.resolve_listen_mode('::')

    def test_port_ranges_and_tcp_udp_reuse(self):
        self.assertEqual(sbnpm.parse_ranges('30004,30000-30002, 30001:30005'), [(30000, 30005)])
        for invalid in ('30002-30001', '22', '1024-65535', '2048,', '65536'):
            with self.subTest(invalid=invalid), self.assertRaises(sbnpm.Error):
                sbnpm.parse_ranges(invalid)
        s = {**self.s, 'extra_ports': {'reality': [(30000, 30004)], 'hy2': [(30000, 30004)],
                                       'tuic': [(40000, 40000)]}}
        self.assertIn(30001, sbnpm.port_plan(s)['tcp'] & sbnpm.port_plan(s)['udp'])
        rules = sbnpm.nft_rules(s)
        self.assertIn('tcp dport { 30000-30004 } redirect to :8443', rules)
        self.assertIn('udp dport { 30000-30004 } redirect to :24443', rules)
        self.assertIn('udp dport { 40000 } redirect to :24444', rules)
        self.assertNotIn('flush ruleset', rules)
        v4_rules = sbnpm.nft_rules({**s, 'listen': '0.0.0.0'})
        self.assertIn('meta nfproto ipv6 tcp dport { 30000-30004 } drop', v4_rules)
        with self.assertRaisesRegex(sbnpm.Error, '与 HTTPS 握手入口'):
            sbnpm.port_plan({**s, 'origin': {'port': 30001}})
        s['extra_ports']['tuic'] = [(30004, 30004)]
        with self.assertRaisesRegex(sbnpm.Error, 'UDP 30004'):
            sbnpm.port_plan(s)

    def test_docker_published_port_conflict_without_local_listener(self):
        published = {'NetworkSettings': {'Ports': {'8443/tcp': [{'HostPort': '8443'}]}}}
        with mock.patch.object(sbnpm, 'docker_containers', return_value=[published]), \
             mock.patch.object(sbnpm, 'port_available', return_value=True):
            with self.assertRaisesRegex(sbnpm.Error, 'Docker'):
                sbnpm.check_port_plan(self.s)

    def test_hopping_profile_exports_main_and_aliases(self):
        s = {**self.s, 'extra_ports': {'hy2': [(30000, 30005)]}}
        for fmt in ('json', 'uri'):
            with mock.patch.object(sbnpm, 'read_state', return_value=s), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                sbnpm.cmd_hop_profile(SimpleNamespace(format=fmt))
                result = out.getvalue()
            if fmt == 'json':
                parsed = json.loads(result)
                self.assertEqual(parsed['server_ports'], ['24443:24443', '30000:30005'])
                self.assertEqual(parsed['hop_interval'], '30s')
            else:
                self.assertIn('node.example.com:24443/?', result)
                self.assertIn('mport=24443%2C30000-30005', result)

    def test_custom_hop_interval_validation_and_zero_downtime_update(self):
        for invalid in (0, 4, 3601, -10, True):
            with self.subTest(invalid=invalid), self.assertRaises(sbnpm.Error):
                sbnpm.validate_hop_interval(invalid)
        self.assertEqual(sbnpm.validate_hop_interval(5), 5)
        self.assertEqual(sbnpm.validate_hop_interval(45), 45)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state_file = base / 'state.json'
            old = {**self.s, 'extra_ports': {'hy2': [[30000, 30005]]}, 'hop_interval': 30}
            with mock.patch.multiple(sbnpm, BASE=base, STATE=state_file), \
                 mock.patch.object(sbnpm, 'read_state', return_value=old), \
                 mock.patch.object(sbnpm, 'activate') as activate, \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                with self.assertRaisesRegex(sbnpm.Error, '仅适用于 hy2'):
                    sbnpm.cmd_configure(SimpleNamespace(
                        protocol='reality', port=None, extra=None, add=None, hop_interval=15))
                # No-op when JSON list ranges match parsed tuple ranges
                sbnpm.cmd_configure(SimpleNamespace(
                    protocol='hy2', port=None, extra='30000-30005', add=None, hop_interval=None))
                self.assertIn('端口配置无变化', out.getvalue())
                activate.assert_not_called()
                # Updating only hop_interval writes state & hop profile without restarting service
                sbnpm.cmd_configure(SimpleNamespace(
                    protocol='hy2', port=None, extra=None, add=None, hop_interval=15))
                activate.assert_not_called()
                saved_state = json.loads(state_file.read_text())
                self.assertEqual(saved_state['hop_interval'], 15)
                hop_json = json.loads((base / sbnpm.HOP_PROFILE_NAME).read_text())
                self.assertEqual(hop_json['hop_interval'], '15s')

    def test_ubuntu_and_bbr_kernel_version_protocol_optimization(self):
        ubuntu_24 = {'id': 'ubuntu', 'version_id': '24.04', 'pretty_name': 'Ubuntu 24.04.1 LTS',
                     'kernel': '6.8.0-45-generic', 'kernel_tuple': [6, 8]}
        ubuntu_20 = {'id': 'ubuntu', 'version_id': '20.04', 'pretty_name': 'Ubuntu 20.04 LTS',
                     'kernel': '5.4.0-190-generic', 'kernel_tuple': [5, 4]}

        bbr3 = {'generation': 'bbrv3', 'module_version': '3', 'current_cc': 'bbr',
                'current_qdisc': 'fq', 'target_cc': 'bbr', 'target_qdisc': 'fq'}
        bbr1 = {'generation': 'bbrv1', 'module_version': '1', 'current_cc': 'bbr',
                'current_qdisc': 'fq', 'target_cc': 'bbr', 'target_qdisc': 'fq'}

        prof_v3 = sbnpm.build_transport_profile(ubuntu_24, bbr3, bbr_profile_supported=True)
        self.assertEqual(prof_v3['hy2_bbr_profile'], 'standard')
        self.assertFalse(prof_v3['tcp_fast_open'])
        self.assertFalse(prof_v3['tcp_multi_path'])
        self.assertFalse(prof_v3['udp_fragment'])
        self.assertEqual(prof_v3['tuic_heartbeat'], '8s')
        self.assertEqual(prof_v3['tcp_ecn'], 2)
        self.assertEqual(prof_v3['quic_stream_window'], 8388608)

        prof_v1_old = sbnpm.build_transport_profile(ubuntu_20, bbr1, bbr_profile_supported=True)
        self.assertEqual(prof_v1_old['hy2_bbr_profile'], 'standard')
        self.assertFalse(prof_v1_old['tcp_fast_open'])
        self.assertFalse(prof_v1_old['tcp_multi_path'])
        self.assertEqual(prof_v1_old['tuic_heartbeat'], '10s')
        self.assertEqual(prof_v1_old['tcp_ecn'], 2)

        with mock.patch.object(sbnpm, 'core_supports_bbr_profile', return_value=True):
            conf = sbnpm.make_config({**self.s, 'bbr': prof_v3})
            self.assertNotIn('tcp_fast_open', conf['inbounds'][0])
            self.assertNotIn('tcp_multi_path', conf['inbounds'][0])
            self.assertEqual(conf['inbounds'][1]['bbr_profile'], 'standard')
            self.assertNotIn('udp_fragment', conf['inbounds'][1])
            self.assertEqual(conf['inbounds'][1]['stream_receive_window'], 8388608)
            self.assertEqual(conf['inbounds'][1]['connection_receive_window'], 20971520)
            self.assertEqual(conf['inbounds'][1]['initial_packet_size'], 1200)
            self.assertEqual(conf['inbounds'][2]['heartbeat'], '8s')
            self.assertIn({'ip_is_private': True, 'outbound': 'block'}, conf['route']['rules'])
            hop = sbnpm.make_hop_profile({**self.s, 'bbr': prof_v3, 'hop_interval': 20}, [(24443, 24443)])
            self.assertEqual(hop['bbr_profile'], 'standard')
            self.assertEqual(hop['stream_receive_window'], 8388608)
            self.assertEqual(hop['hop_interval'], '20s')

    def test_evening_peak_udp_anti_qos_optimization(self):
        old = {**self.s, 'extra_ports': {'hy2': [[30000, 30005]]}, 'hop_interval': 30}
        with mock.patch.object(sbnpm, 'read_state', return_value=old), \
             mock.patch.object(sbnpm, 'enable_system_bbr', return_value={'generation': 'bbrv1', 'hy2_bbr_profile': 'standard'}), \
             mock.patch.object(sbnpm, 'core_supports_bbr_profile', return_value=True), \
             mock.patch.object(sbnpm, 'activate') as activate, \
             contextlib.redirect_stdout(io.StringIO()):
            sbnpm.cmd_udp_optimize(SimpleNamespace(
                preset='peak', obfs=None, obfs_password='my-salamander-key',
                up_mbps=50, down_mbps=300, hop_interval=None, hop_interval_max=None))
            updated = activate.call_args[0][0]
            self.assertEqual(updated['hy2_obfs'], 'my-salamander-key')
            self.assertEqual(updated['hy2_up_mbps'], 50)
            self.assertEqual(updated['hy2_down_mbps'], 300)
            self.assertEqual(updated['hop_interval'], 30)
            self.assertEqual(updated['hop_interval_max'], 60)

            conf = sbnpm.make_config(updated)
            hy2_in = conf['inbounds'][1]
            self.assertEqual(hy2_in['obfs'], {'type': 'salamander', 'password': 'my-salamander-key'})
            self.assertEqual(hy2_in['up_mbps'], 300)
            self.assertEqual(hy2_in['down_mbps'], 50)

            hy2_link = sbnpm.make_links(updated)[1]
            self.assertIn('obfs=salamander', hy2_link)
            self.assertIn('obfs-password=my-salamander-key', hy2_link)

            hop = sbnpm.make_hop_profile(updated, [(24443, 24443), (30000, 30005)])
            self.assertEqual(hop['hop_interval'], '30s')
            self.assertEqual(hop['hop_interval_max'], '60s')
            self.assertEqual(hop['obfs'], {'type': 'salamander', 'password': 'my-salamander-key'})
            self.assertEqual(hop['up_mbps'], 50)
            self.assertEqual(hop['down_mbps'], 300)

    def test_select_origin_tries_docker_https_and_uses_local_when_no_npm(self):
        args = SimpleNamespace(origin_address=None, local_origin_address=None, origin_port=None)
        domain = self.s['domain']
        npms = [{'running': True, 'endpoints': [('127.0.0.1', 443), ('172.30.0.8', 443)]}]
        with mock.patch.object(sbnpm, 'probe_tls', side_effect=[OSError('bad origin'), 'h2']) as probe, \
             contextlib.redirect_stdout(io.StringIO()):
            chosen = sbnpm.select_origin(args, domain, npms, 'npm')
        self.assertEqual(chosen, {'address': '172.30.0.8', 'port': 443, 'local': False})
        probe.assert_called_with('172.30.0.8', 443, domain)
        self.assertEqual(sbnpm.select_origin(args, domain, [], 'letsencrypt'),
                         {'address': '127.0.0.1', 'port': 18443, 'local': True})

    def test_explicit_ipv6_local_origin_does_not_probe_before_start(self):
        args = SimpleNamespace(origin_address=None, local_origin_address='::1', origin_port=18444)
        with mock.patch.object(sbnpm, 'probe_tls') as probe:
            origin = sbnpm.select_origin(args, self.s['domain'], [], 'letsencrypt')
        probe.assert_not_called()
        self.assertEqual(origin, {'address': '::1', 'port': 18444, 'local': True})

    def test_hop_profile_saved_updated_and_removed(self):
        s = {**self.s, 'extra_ports': {'hy2': [[30000, 30005]]}, 'hop_interval': 25}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sbnpm, 'BASE', Path(tmp)):
            profile = Path(tmp) / sbnpm.HOP_PROFILE_NAME
            sbnpm.write_hop_profile(s)
            self.assertEqual(profile.stat().st_mode & 0o777, 0o600)
            data = json.loads(profile.read_text())
            self.assertEqual(data['server_ports'], ['24443:24443', '30000:30005'])
            self.assertEqual(data['hop_interval'], '25s')
            s['ports'] = {**s['ports'], 'hy2': 24445}
            sbnpm.write_hop_profile(s)
            self.assertEqual(json.loads(profile.read_text())['server_ports'],
                             ['24445:24445', '30000:30005'])
            s['extra_ports'] = {}
            sbnpm.write_hop_profile(s)
            self.assertFalse(profile.exists())

    def test_failed_update_restores_credentials_ports_and_config(self):
        self.check_rollback(self.s)

    def test_failed_first_install_leaves_no_install_record(self):
        self.check_rollback(None)

    def check_rollback(self, old):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            cert_dir = base / 'tls'
            state = base / 'state.json'
            cfg = base / 'config.json'
            desired = {**self.s, 'ports': {**self.s['ports'], 'reality': 18443},
                       'extra_ports': {'hy2': [[30000, 30005]]}}
            with mock.patch.multiple(sbnpm, BASE=base, CERT_DIR=cert_dir, STATE=state,
                                     CFG=cfg, ORIGIN_FILE=base / 'origin.json'), \
                 mock.patch.object(sbnpm, 'group_access'), mock.patch.object(sbnpm, 'ensure_user'), \
                 mock.patch.object(sbnpm, 'check_config'), mock.patch.object(sbnpm, 'stop_services'), \
                 mock.patch.object(sbnpm, 'systemctl'), mock.patch.object(sbnpm, 'active', return_value=True), \
                 mock.patch.object(sbnpm, 'run', return_value=SimpleNamespace(returncode=0)), \
                 mock.patch.object(sbnpm, 'start_services', side_effect=[sbnpm.Error('startup'), None]) as start:
                if old:
                    sbnpm.write_config(old)
                    old_config = cfg.read_bytes()
                with self.assertRaisesRegex(sbnpm.Error, 'startup'):
                    sbnpm.activate(desired, old, None if old else (b'cert', b'key'))
                self.assertFalse((base / sbnpm.HOP_PROFILE_NAME).exists())
                if old:
                    self.assertEqual(sbnpm.read_state(), old)
                    self.assertEqual(cfg.read_bytes(), old_config)
                    start.assert_called_with(old)
                else:
                    self.assertFalse(state.exists())
                    self.assertFalse(cfg.exists())
                    self.assertFalse((cert_dir / 'privkey.pem').exists())


class MenuTests(unittest.TestCase):
    def test_running_core_version_uses_proc_executable(self):
        with mock.patch.object(sbnpm, 'run', side_effect=[
            SimpleNamespace(stdout='1234\n'),
            SimpleNamespace(stdout='sing-box version 1.14.4\n'),
            SimpleNamespace(stdout='0\n'),
        ]) as run:
            self.assertEqual(sbnpm.running_core_version(), '1.14.4')
            self.assertEqual(sbnpm.running_core_version(), '未运行')
        self.assertEqual(run.call_args_list[1].args[0], ['/proc/1234/exe', 'version'])

    def test_menu_displays_running_version_and_enables_qr_for_option_two(self):
        with mock.patch.object(sbnpm.sys.stdin, 'isatty', return_value=True), \
             mock.patch.object(sbnpm.os, 'geteuid', return_value=0), \
             mock.patch.object(sbnpm, 'running_core_version', return_value='1.14.4'), \
             mock.patch('builtins.input', side_effect=['2', '0']), \
             mock.patch.object(sbnpm, 'main', return_value=0) as run, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            sbnpm.cmd_menu()
        run.assert_called_once_with(['nodes', '--qr'])
        self.assertIn(f'sbnpm 设置 {sbnpm.SCRIPT_VERSION}', out.getvalue())
        self.assertIn('运行中的 sing-box 版本：1.14.4', out.getvalue())
        self.assertIn('2. 显示三协议主端口节点（链接和二维码）', out.getvalue())

    def test_menu_options_hop_interval_udp_peak_reinstall_and_listen_mode(self):
        with mock.patch.object(sbnpm.sys.stdin, 'isatty', return_value=True), \
             mock.patch.object(sbnpm.os, 'geteuid', return_value=0), \
             mock.patch.object(sbnpm, 'running_core_version', return_value='1.14.4'), \
             mock.patch.object(sbnpm, 'current_hop_interval', return_value=30), \
             mock.patch.object(sbnpm, 'current_domain', return_value='node.example.com'), \
             mock.patch.object(sbnpm, 'current_listen', return_value='0.0.0.0'), \
             mock.patch('builtins.input', side_effect=[
                 '4', '2', '1', '30000-30010', '15',
                 '4', '2', '4', '20',
                 '12',
                 '13', '1',
                 '14', '1', 'REINSTALL',
                 '14', '2', 'new.example.org', 'REINSTALL',
                 '15', '1',
                 '15', '2',
                 '0',
             ]), \
             mock.patch.object(sbnpm, 'main', return_value=0) as run, \
             contextlib.redirect_stdout(io.StringIO()):
            sbnpm.cmd_menu()
        self.assertEqual(run.call_args_list, [
            mock.call(['ports', 'hy2', '--add', '30000-30010', '--hop-interval', '15']),
            mock.call(['ports', 'hy2', '--hop-interval', '20']),
            mock.call(['optimize-bbr']),
            mock.call(['udp-optimize', '--preset', 'peak']),
            mock.call(['reinstall', '--keep-domain']),
            mock.call(['reinstall', '--domain', 'new.example.org']),
            mock.call(['listen-mode', '::']),
            mock.call(['listen-mode', '0.0.0.0']),
        ])


class RemoveTests(unittest.TestCase):
    def test_menu_confirmation_and_exit(self):
        with mock.patch.object(sbnpm.sys.stdin, 'isatty', return_value=True), \
             mock.patch.object(sbnpm.os, 'geteuid', return_value=0), \
             mock.patch('builtins.input', side_effect=['10', 'cancel', '10', 'REMOVE']), \
             mock.patch.object(sbnpm, 'main', return_value=0) as run, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            sbnpm.cmd_menu()
        run.assert_called_once_with(['remove', '--yes'])
        self.assertIn('10. 彻底卸载 sbnpm', out.getvalue())
        self.assertIn('已取消', out.getvalue())

    def test_remove_cleans_managed_files_without_state_and_restores_original_sb(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, app, units, bin_dir = [root / name for name in ('config', 'app', 'units', 'bin')]
            for path in (base, app, units, bin_dir):
                path.mkdir()
            (base / 'privkey.pem').touch()
            (app / 'sbnpm.py').touch()
            stamp = root / 'timer-stamp'
            stamp.touch()
            sysctl_conf = root / '99-sbnpm-bbr.conf'
            sysctl_conf.touch()
            for unit in (sbnpm.SERVICE, sbnpm.ORIGIN_SERVICE, sbnpm.SYNC_SERVICE, sbnpm.SYNC_TIMER):
                (units / unit).touch()
            (units / 'sing-box.service').touch()
            (bin_dir / 'sbnpm').symlink_to(app / 'sbnpm.py')
            (bin_dir / 'sb').symlink_to(app / 'sbnpm.py')
            (bin_dir / 'sb.pre-sbnpm').write_text('original')
            with mock.patch.multiple(sbnpm, BASE=base, INSTALL_DIR=app, SYSTEMD_DIR=units,
                                     BIN_DIR=bin_dir, TIMER_STAMP=stamp, SYSCTL_BBR_CONF=sysctl_conf), \
                 mock.patch.object(sbnpm, 'ensure_root'), \
                 mock.patch.object(sbnpm, 'systemctl') as systemctl, \
                 mock.patch.object(sbnpm, 'clear_nft') as clear, \
                 contextlib.redirect_stdout(io.StringIO()):
                sbnpm.cmd_remove(SimpleNamespace(yes=True))
            systemctl.assert_has_calls([
                mock.call('disable', '--now', sbnpm.SYNC_TIMER),
                mock.call('stop', sbnpm.SYNC_SERVICE, sbnpm.SERVICE, sbnpm.ORIGIN_SERVICE),
                mock.call('disable', sbnpm.SERVICE),
                mock.call('daemon-reload'),
            ])
            clear.assert_called_once()
            self.assertFalse(base.exists())
            self.assertFalse(app.exists())
            self.assertFalse(stamp.exists())
            self.assertFalse(sysctl_conf.exists())
            self.assertFalse((bin_dir / 'sbnpm').is_symlink())
            self.assertEqual((bin_dir / 'sb').read_text(), 'original')
            self.assertEqual(list(units.iterdir()), [units / 'sing-box.service'])


class CoreUpdateTests(unittest.TestCase):
    def test_official_stable_asset_for_arm64(self):
        folder = 'sing-box-1.14.4-linux-arm64'
        filename = folder + '.tar.gz'
        url = f'{sbnpm.RELEASE_URL}/v1.14.4/{filename}'
        asset = {'name': filename, 'browser_download_url': url, 'digest': 'sha256:' + 'a' * 64}
        release = {'draft': False, 'prerelease': False, 'tag_name': 'v1.14.4', 'assets': [asset]}
        with mock.patch.object(sbnpm.os, 'uname', return_value=SimpleNamespace(machine='aarch64')), \
             mock.patch.object(sbnpm, 'curl_release', side_effect=lambda *a, **k: json.dumps(release)):
            self.assertEqual(sbnpm.latest_stable_core(), ('1.14.4', url, 'a' * 64, folder))
            release['prerelease'] = True
            with self.assertRaisesRegex(sbnpm.Error, '稳定版'):
                sbnpm.latest_stable_core()
            release['prerelease'] = False
            asset['digest'] = None
            with self.assertRaisesRegex(sbnpm.Error, 'SHA-256'):
                sbnpm.latest_stable_core()

    def test_download_verifies_checksum_and_extracts_binary_only(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            root = Path(tmp)
            src = root / 'fixture.tar.gz'
            payload = b'#!/bin/sh\necho sing-box version 1.14.4\n'
            folder = 'sing-box-1.14.4-linux-amd64'
            with tarfile.open(src, 'w:gz') as tar:
                member = tarfile.TarInfo(f'{folder}/sing-box')
                member.size = len(payload)
                tar.addfile(member, io.BytesIO(payload))
                tar.addfile(tarfile.TarInfo('../escape'))
            def fake_download(flag, output, url, **kwargs):
                self.assertEqual(flag, '--output')
                Path(output).write_bytes(src.read_bytes())
            with mock.patch.object(sbnpm, 'curl_release', side_effect=fake_download):
                with self.assertRaisesRegex(sbnpm.Error, 'SHA-256'):
                    sbnpm.download_core(root, 'unused', '0' * 64, folder)
                binary = sbnpm.download_core(root, 'unused', hashlib.sha256(src.read_bytes()).hexdigest(), folder)
            self.assertEqual(sbnpm.core_version(str(binary)), '1.14.4')
            self.assertFalse((root.parent / 'escape').exists())

    def test_switch_preserves_system_binary_and_rolls_back_service_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                system, core, candidate = [root / name for name in ('system', 'sing-box', 'candidate')]
                system.write_bytes(b'old')
                core.symlink_to(system)
                candidate.write_bytes(b'new')
                state = {'domain': 'node.example.com'}
                health = [sbnpm.Error('failed TLS probe'), None] if fail else [None]
                with mock.patch.object(sbnpm, 'CORE', str(core)), \
                     mock.patch.object(sbnpm, 'active', return_value=True), \
                     mock.patch.object(sbnpm, 'systemctl') as systemctl, \
                     mock.patch.object(sbnpm, 'verify_running', side_effect=health):
                    if fail:
                        with self.assertRaisesRegex(sbnpm.Error, '已回滚'):
                            sbnpm.switch_core(candidate, state)
                        self.assertEqual(core.resolve(), system)
                        self.assertEqual(systemctl.call_count, 2)
                    else:
                        sbnpm.switch_core(candidate, state)
                        self.assertFalse(core.is_symlink())
                        self.assertEqual(core.read_bytes(), b'new')
                        self.assertEqual((root / 'sing-box.previous').resolve(), system)
                        systemctl.assert_called_once_with('restart', sbnpm.SERVICE)
                self.assertEqual(system.read_bytes(), b'old')

    def test_incompatible_candidate_keeps_running_core(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = Path(tmp) / 'sing-box'
            with mock.patch.object(sbnpm, 'CORE', str(core)), \
                 mock.patch.object(sbnpm, 'read_state', return_value={}), \
                 mock.patch.object(sbnpm, 'core_version', side_effect=['1.13.0', '1.14.4']), \
                 mock.patch.object(sbnpm, 'latest_stable_core', return_value=('1.14.4', 'url', 'hash', 'folder')), \
                 mock.patch.object(sbnpm, 'download_core', return_value=Path(tmp) / 'new'), \
                 mock.patch.object(sbnpm, 'run', side_effect=sbnpm.Error('configuration rejected')), \
                 mock.patch.object(sbnpm, 'switch_core') as switch, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(sbnpm.Error, 'configuration rejected'):
                    sbnpm.cmd_update_core(SimpleNamespace(yes=True))
                switch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
