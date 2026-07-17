# -*- coding: utf-8 -*-

import tempfile
import unittest
from pathlib import Path

import XiaohaCleanerAuto as auto
import xiaoha_cleaner as core


class AutoMysqlConfigTest(unittest.TestCase):
    def test_exec_chain_and_property_password_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_text:
            server = Path(temp_text) / 'server-data'
            (server / 'config').mkdir(parents=True)
            (server / 'resources').mkdir()
            (server / 'server.cfg').write_text('exec config/database.cfg\n', encoding='utf-8')
            (server / 'config' / 'database.cfg').write_text(
                'set mysql_connection_string "server=127.0.0.1;port=3307;uid=cleaner;password=p@ss#word;database=fivem"\n',
                encoding='utf-8',
            )
            discovered = auto.discover_mysql_connection(server / 'resources')
            connection = core.parse_mysql_uri(discovered['uri'])
            self.assertEqual(connection['host'], '127.0.0.1')
            self.assertEqual(connection['port'], 3307)
            self.assertEqual(connection['user'], 'cleaner')
            self.assertEqual(connection['password'], 'p@ss#word')
            self.assertEqual(connection['database'], 'fivem')
            self.assertTrue(discovered['assignment_cfg'].endswith('database.cfg'))

    def test_multiple_profiles_require_explicit_cfg(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text) / 'txData'
            for name, database in (('alpha', 'db_alpha'), ('beta', 'db_beta')):
                profile = root / name
                profile.mkdir(parents=True)
                (profile / 'server.cfg').write_text(
                    'set mysql_connection_string "mysql://root:secret@localhost/{}"\n'.format(database),
                    encoding='utf-8',
                )
            with self.assertRaises(auto.ConfigError):
                auto.discover_mysql_connection(root)
            selected = auto.discover_mysql_connection(
                root, explicit_cfg=root / 'alpha' / 'server.cfg'
            )
            self.assertEqual(core.parse_mysql_uri(selected['uri'])['database'], 'db_alpha')

    def test_manual_uri_override_never_reads_cfg(self):
        arguments, discovered = auto.prepare_arguments([
            'clean', 'missing', '--yes', '--apply-sql', '--yes-drop-tables',
            '--mysql-uri', 'mysql://manual:secret@localhost/manual',
        ])
        self.assertIsNone(discovered)
        self.assertIn('mysql://manual:secret@localhost/manual', arguments)


if __name__ == '__main__':
    unittest.main()
