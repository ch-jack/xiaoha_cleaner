# -*- coding: utf-8 -*-

import json
import re
import tempfile
import unittest
from pathlib import Path

import XiaohaCleanerAuto  # configures the release core
import xiaoha_cleaner as core


class CleanerIntegrationTest(unittest.TestCase):
    def test_scan_clean_restore_and_sql(self):
        with tempfile.TemporaryDirectory() as temp_text:
            temp = Path(temp_text)
            target = temp / 'server-data'
            local = target / 'resources' / '[local]'
            local.mkdir(parents=True)

            owned = local / 'hgadmin'
            owned.mkdir()
            (owned / 'fxmanifest.lua').write_text(
                "fx_version 'cerulean'\nauthor 'XIAOHA'\n", encoding='utf-8'
            )

            normal = local / 'normal'
            normal.mkdir()
            (normal / 'fxmanifest.lua').write_text(
                "client_script 'hgadmin_guard.lua' -- [[HGADMIN-GUARD]]\n"
                "client_script 'client.lua'\n",
                encoding='utf-8',
            )
            (normal / 'hgadmin_guard.lua').write_text(
                '-- [[HGADMIN-GUARD]] HGAdmin 反作弊保护守卫\n', encoding='utf-8'
            )
            (normal / 'client.lua').write_text("print('keep')\n", encoding='utf-8')
            (target / 'server.cfg').write_text('ensure hgadmin\nensure normal\n', encoding='utf-8')

            plan = core.build_plan(str(target))
            self.assertEqual(plan['summary']['owned_resources'], 1)
            self.assertEqual(plan['summary']['injection_files'], 1)
            self.assertEqual(len(plan['sql']['safe_tables']), 14)
            self.assertEqual(len(plan['sql']['added_columns']), 3)

            sql = core.database_cleanup_sql(plan)
            self.assertIn('DROP TABLE IF EXISTS `bans`;', sql)
            self.assertIn("CONCAT('DROP TABLE IF EXISTS ', @XIAOHA_BRANDED_TABLES)", sql)
            self.assertNotIn("SEPARATOR '; '", sql)
            self.assertEqual(len(re.findall(r'(?m)^PREPARE XIAOHA_BRANDED_STMT', sql)), 1)

            run_dir, operations, reports = core.clean_target(plan, temp / 'quarantine')
            self.assertTrue(run_dir.exists())
            self.assertGreater(len(operations), 0)
            self.assertFalse(owned.exists())
            self.assertFalse((normal / 'hgadmin_guard.lua').exists())
            payload = json.loads(Path(reports[0]).read_text(encoding='utf-8'))
            self.assertEqual(payload['status'], 'cleaned')

            restore_path, result = core.restore_report(str(reports[0]))
            self.assertTrue(restore_path.exists())
            self.assertFalse(result['errors'])
            self.assertTrue(owned.exists())
            self.assertTrue((normal / 'hgadmin_guard.lua').exists())


if __name__ == '__main__':
    unittest.main()
