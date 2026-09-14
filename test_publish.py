import unittest
from publish import read_payload, encode, bump, version_tuple


class RuleValidationTests(unittest.TestCase):
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


class PublisherTransactionTests(unittest.TestCase):
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
            key = root / 'private.pem'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)], check=True, capture_output=True)
            subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(root / 'public-key.pem')], check=True, capture_output=True)
            for name, package in [('direct-apps', 'com.tencent.mm'), ('proxy-apps', 'org.telegram.messenger')]:
                (root / 'lists' / (name + '.json')).write_text(json.dumps({'version': '1.0.0', 'packages': [package]}))
            sources = {'direct.txt': ['+.baidu.com', '+.qq.com', '+.taobao.com'],
                       'proxy.txt': ['+.google.com', '+.youtube.com', '+.facebook.com'],
                       'gfw.txt': ['+.google.com', '+.youtube.com', '+.facebook.com'],
                       'cncidr.txt': ['1.1.1.0/24']}
            with patch.object(publish, 'ROOT', root), patch.object(publish, 'fetch', side_effect=lambda url: encode(sources[url.rsplit('/', 1)[-1]])):
                publish.build(key, 'a' * 40)
                first = (root / 'latest/version.json').read_bytes()
                publish.build(key, 'b' * 40)
                self.assertEqual(first, (root / 'latest/version.json').read_bytes())
                (root / 'lists/direct-apps.json').write_text(json.dumps({'version': '1.0.0', 'packages': ['com.tencent.mm', 'com.test.app']}))
                publish.build(key, 'b' * 40)
                manifest = json.loads((root / 'latest/manifest.json').read_text())
                self.assertEqual(manifest['componentVersions'], {'rules': '2.0.0', 'directApps': '1.0.1', 'proxyApps': '1.0.0'})
                good = (root / 'latest/version.json').read_bytes()
                sources['proxy.txt'] = ['+.google.com', '+.youtube.com', '+.qq.com']
                with self.assertRaisesRegex(ValueError, 'direct canary unexpectedly proxied'):
                    publish.build(key, 'b' * 40)
                self.assertEqual(good, (root / 'latest/version.json').read_bytes())
                sources['proxy.txt'] = ['+.google.com', '+.youtube.com', '+.facebook.com']
                (root / 'lists/direct-apps.json').write_text(json.dumps({'version': '1.0.0', 'packages': ['com.tencent.mm', 'com.test.app', 'com.test.second']}))
                real_write = Path.write_text
                def fail_candidate_write(path, *args, **kwargs):
                    if path.parent.name == 'complete' and path.name == 'gfw.yaml':
                        raise OSError('injected disk failure')
                    return real_write(path, *args, **kwargs)
                with patch.object(Path, 'write_text', fail_candidate_write), self.assertRaises(OSError):
                    publish.build(key, 'b' * 40)
                self.assertFalse((root / 'snapshots/2.0.2').exists())
                self.assertEqual(good, (root / 'latest/version.json').read_bytes())
                publish.build(key, 'b' * 40)
                (root / 'lists/direct-apps.json').write_text(json.dumps({'version': '1.0.0', 'packages': []}))
                publish.build(key, 'b' * 40)
                self.assertEqual((root / 'latest/direct_apps.yaml').read_text(), 'payload: []\n')
                good = (root / 'latest/version.json').read_bytes()
                (root / 'lists/direct-apps.json').write_text(json.dumps({'version': '1.0.0', 'packages': ['com.tencent.mm']}))
                (root / 'lists/proxy-apps.json').write_text(json.dumps({'version': '1.0.1', 'packages': ['com.tencent.mm']}))
                with self.assertRaises(ValueError):
                    publish.build(key, 'b' * 40)
                self.assertEqual(good, (root / 'latest/version.json').read_bytes())

if __name__ == '__main__':
    unittest.main()
