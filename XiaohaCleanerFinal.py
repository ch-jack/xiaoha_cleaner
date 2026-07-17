#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Release entry point with MySQL-safe dynamic branded-table deletion."""

from __future__ import print_function

import sys

import XiaohaCleaner  # installs strict detection and decrypted sample catalog
import xiaoha_cleaner as core

_catalog_cleanup_sql = core.database_cleanup_sql


DYNAMIC_START = "-- Catch branded tables created by encrypted server-only code."
DYNAMIC_END = "SET FOREIGN_KEY_CHECKS = @XIAOHA_OLD_FOREIGN_KEY_CHECKS;"
DYNAMIC_SQL = """-- Catch branded tables created by encrypted server-only code.
-- MySQL does not retain creator provenance, so generic names must come from
-- decrypted CREATE TABLE evidence; xiaoha/hgadmin-branded names are found live.
SET SESSION group_concat_max_len = 1048576;
SELECT GROUP_CONCAT(
  CONCAT('`', REPLACE(TABLE_NAME, '`', '``'), '`')
  SEPARATOR ', '
) INTO @XIAOHA_BRANDED_TABLES
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_TYPE = 'BASE TABLE'
  AND (LOWER(TABLE_NAME) LIKE '%xiaoha%' OR LOWER(TABLE_NAME) LIKE '%hgadmin%');
SET @XIAOHA_BRANDED_DROPS = IF(
  @XIAOHA_BRANDED_TABLES IS NULL,
  'SELECT 1',
  CONCAT('DROP TABLE IF EXISTS ', @XIAOHA_BRANDED_TABLES)
);
PREPARE XIAOHA_BRANDED_STMT FROM @XIAOHA_BRANDED_DROPS;
EXECUTE XIAOHA_BRANDED_STMT;
DEALLOCATE PREPARE XIAOHA_BRANDED_STMT;

"""


def database_cleanup_sql(plan):
    sql = _catalog_cleanup_sql(plan)
    start = sql.find(DYNAMIC_START)
    end = sql.find(DYNAMIC_END, start if start >= 0 else 0)
    if start < 0 or end < 0:
        raise RuntimeError("Generated SQL did not contain the dynamic cleanup block")
    return sql[:start] + DYNAMIC_SQL + sql[end:]


core.database_cleanup_sql = database_cleanup_sql


if __name__ == "__main__":
    sys.exit(core.main())
