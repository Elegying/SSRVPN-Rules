import unittest
from publish import read_payload, encode, bump, version_tuple
from review import review_changes, review_routes


class RuleValidationTests(unittest.TestCase):
    def test_route_review_preserves_exact_suffix_and_wildcard_matching(self):
        payloads = {name: [] for name in ['gfw.yaml', 'foreign_services.yaml',
                    'ai_services.yaml', 'streaming_services.yaml',
                    'user_feedback_rules.yaml', 'cn.yaml', 'china_domains.yaml']}
        payloads['cn.yaml'] = ['+.example.cn', 'exact.cn', '+.cdn?.wild.cn']
        payloads['gfw.yaml'] = ['+.blocked.example', 'api*.foreign.example']
        cases = {'direct': ['example.cn', 'a.example.cn', 'exact.cn', 'cdn1.wild.cn', 'a.cdn2.wild.cn'],
                 'proxy': ['blocked.example', 'a.blocked.example', 'api.foreign.example', 'api123.foreign.example'],
                 'unknown': ['child.exact.cn', 'example.cn.evil.test', 'cdn12.wild.cn']}
        self.assertEqual(review_routes(payloads, cases), 12)

    def test_rejects_injected_configuration_and_catchalls(self):
        for text, behavior in [
            ('payload:\n - example.com\nrules:\n - MATCH,DIRECT', 'domain'),
            ('payload:\n - "*"', 'domain'),
            ('payload:\n - "*.*"', 'domain'),
            ('payload:\n - "+.com"', 'domain'),
            ('payload:\n - 0.0.0.0/0', 'ipcidr'),
            ('payload:\n - 192.168.1.1/8', 'ipcidr'),
            ('payload:\n - com.android.chrome', 'packages'),
            ('payload:\n - "com.test,PROXY"', 'packages'),
            ('payload: []', 'domain'),
        ]:
            with self.subTest(text=text), self.assertRaises((ValueError, SyntaxError)):
                read_payload(text, behavior)

    def test_equal_count_mass_replacement_is_blocked(self):
        old = {'cn.yaml': [f'old{i}.example' for i in range(100)]}
        candidate = {'cn.yaml': [f'new{i}.example' for i in range(100)]}
        with self.assertRaisesRegex(ValueError, 'excessive content replacement'):
            review_changes(candidate, old, {'cn.yaml'})
        candidate['cn.yaml'] = old['cn.yaml'][:-1] + ['reviewed.example']
        self.assertIn('| 1 | 1 |', review_changes(candidate, old, {'cn.yaml'}))

    def test_roundtrip_and_version_order(self):
        self.assertEqual(read_payload(encode([]), 'packages'), [])
        for values, behavior in [(['+.example.com', '+.youtube'], 'domain'),
                                 (['1.1.1.0/24'], 'ipcidr'),
                                 (['com.tencent.mm', 'org.telegram.messenger'], 'packages')]:
            self.assertEqual(read_payload(encode(values), behavior), sorted(values))
        self.assertEqual(bump('2.0.9'), '2.0.10')
        self.assertGreater(version_tuple('2.0.10'), version_tuple('2.0.9'))
        for version in ['01.0.0', '1.0.' + '9' * 100, '1.0.-1']:
            with self.assertRaises(ValueError):
                version_tuple(version)


class CoreReadinessTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        self.mocks = {}
        for name in ['subprocess.run', 'subprocess.Popen', 'socket.socket',
                     'urllib.request.build_opener', 'time.sleep']:
            patcher = patch('review.' + name)
            self.mocks[name] = patcher.start()
            self.addCleanup(patcher.stop)
        self.process = self.mocks['subprocess.Popen'].return_value
        self.process.poll.return_value = None
        self.mocks['socket.socket'].return_value.__enter__.return_value.getsockname.return_value = (
            '127.0.0.1', 12345)
        self.opener = self.mocks['urllib.request.build_opener'].return_value
        self.sleep = self.mocks['time.sleep']
        self.contents = {'domains.yaml': encode(['+.example.com']),
                         'networks.yaml': encode(['1.1.1.0/24', '8.8.8.0/24']),
                         'direct_apps.yaml': encode(['com.tencent.mm'])}
        self.entries = [
            {'name': 'domains.yaml', 'behavior': 'domain', 'count': 1},
            {'name': 'networks.yaml', 'behavior': 'ipcidr', 'count': 2},
            {'name': 'direct_apps.yaml', 'behavior': 'packages', 'count': 1},
        ]
        self.ready = {'providers': {'domains.yaml': {'ruleCount': 1},
                                    'networks.yaml': {'ruleCount': 2}}}

    def set_responses(self, responses):
        import io
        import json
        self.opener.open.side_effect = [
            response if isinstance(response, Exception) else io.StringIO(json.dumps(response))
            for response in responses]

    def review(self):
        from review import review_core
        return review_core('/unused/core', self.contents, self.entries)

    def assert_attempts(self, attempts, sleeps):
        from unittest.mock import call
        self.assertEqual(self.opener.open.call_count, attempts)
        self.assertEqual(self.sleep.call_args_list, [call(.1)] * sleeps)
        self.assertEqual(self.process.poll.call_count, attempts)
        for call_args in self.opener.open.call_args_list:
            self.assertEqual(call_args.kwargs['timeout'], .5)
            request = call_args.args[0]
            self.assertEqual(request.full_url, 'http://127.0.0.1:12345/providers/rules')
            self.assertEqual(request.get_header('Authorization'), 'Bearer isolated-rule-review')
        self.process.terminate.assert_called_once_with()
        self.process.wait.assert_called_once_with(timeout=5)
        self.process.kill.assert_not_called()

    def test_null_providers_are_retried_until_ready(self):
        self.set_responses([{'providers': None}, self.ready])
        self.assertIsNone(self.review())
        self.assert_attempts(2, 1)

    def test_empty_providers_are_not_ready(self):
        self.set_responses([{'providers': {}}, self.ready])
        self.review()
        self.assert_attempts(2, 1)

    def test_partial_providers_require_matching_counts_in_same_response(self):
        self.set_responses([
            {'providers': {'domains.yaml': {'ruleCount': 1}}},
            {'providers': {'networks.yaml': {'ruleCount': 2}}},
            {'providers': {'domains.yaml': {'ruleCount': 1}, 'networks.yaml': {'ruleCount': 1}}},
            self.ready,
        ])
        self.review()
        self.assert_attempts(4, 3)

    def test_complete_providers_pass_immediately(self):
        self.set_responses([self.ready])
        self.review()
        self.assert_attempts(1, 0)
        self.mocks['subprocess.run'].assert_called_once()
        self.assertEqual(self.mocks['subprocess.run'].call_args.args[0][-1], '-t')

    def test_malformed_response_shapes_are_retried(self):
        invalid = [None, [], 'loading', 0, {},
                   *({'providers': value} for value in [[], 'loading', 0, False]),
                   *({'providers': {'domains.yaml': value}} for value in [None, [], 'loading', 0]),
                   *({'providers': {'domains.yaml': {'ruleCount': value},
                                    'networks.yaml': {'ruleCount': 2}}}
                     for value in [None, '1', True, 1.0])]
        for response in invalid:
            with self.subTest(response=response):
                self.opener.open.reset_mock()
                self.sleep.reset_mock()
                self.process.reset_mock()
                self.set_responses([response, self.ready])
                self.review()
                self.assert_attempts(2, 1)

    def test_unready_providers_exhaust_retry_limit_and_fail_closed(self):
        invalid = [None, {'providers': None}, {'providers': {}},
                   {'providers': {'domains.yaml': {'ruleCount': 1}}},
                   {'providers': {'domains.yaml': None}},
                   {'providers': {'domains.yaml': {'ruleCount': 1},
                                  'networks.yaml': {'ruleCount': 3}}}]
        for response in invalid:
            with self.subTest(response=response):
                self.opener.open.reset_mock()
                self.sleep.reset_mock()
                self.process.reset_mock()
                self.set_responses([response] * 100)
                with self.assertRaisesRegex(ValueError, 'core provider load/count mismatch'):
                    self.review()
                self.assert_attempts(100, 100)

    def test_transient_request_and_json_errors_are_retried(self):
        import json
        self.set_responses([OSError('not listening yet'),
                            json.JSONDecodeError('incomplete response', '', 0), self.ready])
        self.review()
        self.assert_attempts(3, 2)

    def test_core_exit_stops_polling_and_cleans_up(self):
        self.process.poll.return_value = 1
        with self.assertRaisesRegex(ValueError, 'core exited before providers became ready'):
            self.review()
        self.opener.open.assert_not_called()
        self.sleep.assert_not_called()
        self.process.terminate.assert_called_once_with()
        self.process.wait.assert_called_once_with(timeout=5)

    def test_timeout_kills_core_if_termination_does_not_finish(self):
        import subprocess
        from unittest.mock import call
        self.set_responses([{'providers': None}] * 100)
        self.process.wait.side_effect = [subprocess.TimeoutExpired('core', 5), None]
        with self.assertRaisesRegex(ValueError, 'core provider load/count mismatch'):
            self.review()
        self.assertEqual(self.opener.open.call_count, 100)
        self.process.terminate.assert_called_once_with()
        self.process.kill.assert_called_once_with()
        self.assertEqual(self.process.wait.call_args_list, [call(timeout=5), call()])


class PublisherTransactionTests(unittest.TestCase):
    def test_core_review_cannot_be_omitted(self):
        import publish
        with self.assertRaises(TypeError):
            publish.build(None, 'a' * 40)

    def test_core_configuration_includes_application_rules(self):
        import json
        from pathlib import Path
        from unittest.mock import patch
        from review import review_core
        contents = {'direct_apps.yaml': encode(['com.tencent.mm']),
                    'proxy_apps.yaml': encode(['org.telegram.messenger'])}
        entries = [{'name': name, 'behavior': 'packages', 'count': 1} for name in contents]
        def inspect(command, **kwargs):
            config = json.loads(Path(command[command.index('-f') + 1]).read_text())
            self.assertIn('PROCESS-NAME,com.tencent.mm,REJECT', config['rules'])
            self.assertIn('PROCESS-NAME,org.telegram.messenger,REJECT', config['rules'])
            raise RuntimeError('checked configuration before process start')
        with patch('review.subprocess.run', side_effect=inspect):
            with self.assertRaisesRegex(RuntimeError, 'checked configuration'):
                review_core(Path('/unused/core'), contents, entries)

    def test_versions_conflicts_and_failure_preserve_previous_publication(self):
        import json
        from pathlib import Path
        import shutil
        import subprocess
        import tempfile
        from unittest.mock import patch
        import publish
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'lists').mkdir()
            shutil.copytree(publish.ROOT / 'baseline', root / 'baseline')
            shutil.copy(publish.ROOT / 'review-cases.json', root / 'review-cases.json')
            key = root / 'private.pem'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)], check=True, capture_output=True)
            subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(root / 'public-key.pem')], check=True, capture_output=True)
            for name, package in [('direct-apps', 'com.tencent.mm'), ('proxy-apps', 'org.telegram.messenger')]:
                (root / 'lists' / (name + '.json')).write_text(json.dumps({'version': '1.0.0', 'packages': [package]}))
            sources = {'direct.txt': ['+.baidu.com', '+.qq.com', '+.taobao.com'],
                       'proxy.txt': ['+.google.com', '+.youtube.com', '+.facebook.com'],
                       'gfw.txt': ['+.google.com', '+.youtube.com', '+.facebook.com'],
                       'cncidr.txt': ['1.1.1.0/24']}
            cases = json.loads((root / 'review-cases.json').read_text())
            sources['direct.txt'] = ['+.' + domain for domain in cases['direct']]
            sources['proxy.txt'] = ['+.' + domain for domain in cases['proxy']]
            sources['gfw.txt'] = list(sources['proxy.txt'])
            original_proxy = list(sources['proxy.txt'])
            with patch.object(publish, 'ROOT', root), patch.object(publish, 'fetch', side_effect=lambda url: encode(sources[url.rsplit('/', 1)[-1]])), patch.object(publish, 'review_core') as core_review:
                publish.build(key, 'a' * 40, core=root / 'core')
                core_review.assert_called_once()
                first = (root / 'latest/version.json').read_bytes()
                with patch.object(publish, 'review_core', side_effect=ValueError('injected core rejection')):
                    with self.assertRaisesRegex(ValueError, 'injected core rejection'):
                        publish.build(key, 'a' * 40, core=root / 'core')
                self.assertEqual(first, (root / 'latest/version.json').read_bytes())
                publish.build(key, 'b' * 40, core=root / 'core')
                self.assertEqual(first, (root / 'latest/version.json').read_bytes())
                (root / 'lists/direct-apps.json').write_text(json.dumps({'version': '1.0.0', 'packages': ['com.tencent.mm', 'com.test.app']}))
                publish.build(key, 'b' * 40, core=root / 'core')
                manifest = json.loads((root / 'latest/manifest.json').read_text())
                self.assertEqual(manifest['componentVersions'], {'rules': '2.0.0', 'directApps': '1.0.1', 'proxyApps': '1.0.0'})
                good = (root / 'latest/version.json').read_bytes()
                sources['proxy.txt'] = original_proxy[:-1] + ['+.qq.com']
                with self.assertRaisesRegex(ValueError, 'route expectation mismatch'):
                    publish.build(key, 'b' * 40, core=root / 'core')
                self.assertEqual(good, (root / 'latest/version.json').read_bytes())
                sources['proxy.txt'] = original_proxy
                (root / 'lists/direct-apps.json').write_text(json.dumps({'version': '1.0.0', 'packages': ['com.tencent.mm', 'com.test.app', 'com.test.second']}))
                real_write = Path.write_text
                def fail_candidate_write(path, *args, **kwargs):
                    if path.parent.name == 'complete' and path.name == 'gfw.yaml':
                        raise OSError('injected disk failure')
                    return real_write(path, *args, **kwargs)
                with patch.object(Path, 'write_text', fail_candidate_write), self.assertRaises(OSError):
                    publish.build(key, 'b' * 40, core=root / 'core')
                self.assertFalse((root / 'snapshots/2.0.2').exists())
                self.assertEqual(good, (root / 'latest/version.json').read_bytes())
                publish.build(key, 'b' * 40, core=root / 'core')
                (root / 'lists/direct-apps.json').write_text(json.dumps({'version': '1.0.0', 'packages': []}))
                publish.build(key, 'b' * 40, core=root / 'core')
                self.assertEqual((root / 'latest/direct_apps.yaml').read_text(), 'payload: []\n')
                good = (root / 'latest/version.json').read_bytes()
                (root / 'lists/direct-apps.json').write_text(json.dumps({'version': '1.0.0', 'packages': ['com.tencent.mm']}))
                (root / 'lists/proxy-apps.json').write_text(json.dumps({'version': '1.0.1', 'packages': ['com.tencent.mm']}))
                with self.assertRaises(ValueError):
                    publish.build(key, 'b' * 40, core=root / 'core')
                self.assertEqual(good, (root / 'latest/version.json').read_bytes())

if __name__ == '__main__':
    unittest.main()
