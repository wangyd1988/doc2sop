"""对外接入页的「测一下」「试调」（app/mcp_probe.py）和审计里的「页面试调」标记（access.py 的 via 列）。

测一下、试调在进程内转给 /mcp 的 TokenGate：令牌、来源（MCP_CLIENTS）、总开关、Host 白名单、范围、限流照真实检查走；
每次结束都关掉开的会话。令牌明文不进日志、不进回复。
"""
import sqlite3
import unittest

import tests.support  # noqa: F401

from app import access
from tests.test_mcp_export import make_client, reset_access

OLD_CALLS = """CREATE TABLE mcp_calls (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, token_id TEXT NOT NULL, client TEXT NOT NULL,
  kind TEXT NOT NULL, name TEXT NOT NULL, args TEXT NOT NULL DEFAULT '{}', result_chars INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0, ok INTEGER NOT NULL DEFAULT 1, error TEXT NOT NULL DEFAULT '',
  execution_id TEXT, session TEXT NOT NULL DEFAULT '')"""
OLD_INSERT = ("INSERT INTO mcp_calls (at, token_id, client, kind, name, args, result_chars, duration_ms, ok,"
              " error, execution_id, session) VALUES ('2026-11-01T00:00:00+00:00', 't', 'c', 'tool', 'kb_search',"
              " '{}', 1, 1, 1, '', NULL, '')")


class AuditViaTests(unittest.TestCase):
    def setUp(self):
        reset_access()
        self.addCleanup(reset_access)

    def test_old_database_gets_the_column_and_old_rows_read_as_external(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(OLD_CALLS)
        conn.execute(OLD_INSERT)
        access._migrate(conn)
        access._migrate(conn)     # 再跑一遍不报错
        self.assertEqual(dict(conn.execute("SELECT via FROM mcp_calls").fetchone()), {"via": ""})

    def test_rollback_old_code_still_writes_and_reads_the_migrated_table(self):
        """回滚到老镜像：老代码的 INSERT 写明了列名（不含 via），SELECT * 多一列。"""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(OLD_CALLS)
        access._migrate(conn)
        conn.execute(OLD_INSERT)
        row = dict(conn.execute("SELECT * FROM mcp_calls").fetchone())
        self.assertEqual((row["name"], row["via"]), ("kb_search", ""))

    def test_record_call_keeps_page_and_drops_unknown_marks(self):
        client = make_client()
        access.record_call(client, "tool", "kb_catalog", {}, 1, 1, True, via="page")
        access.record_call(client, "tool", "kb_catalog", {}, 1, 1, True, via="evil")
        access.record_call(client, "tool", "kb_catalog", {}, 1, 1, True)
        self.assertEqual([c["via"] for c in access.recent_calls()], ["", "", "page"])

    def test_describe_tells_revoked_and_expired_apart_without_touching(self):
        token, secret = access.issue("测试", ["knowledge"])
        self.assertEqual(access.describe(secret)["status"], "active")
        self.assertIsNone(access.get(token["id"])["last_used_at"])
        access.revoke(token["id"])
        self.assertEqual(access.describe(secret)["status"], "revoked")
        self.assertIsNone(access.describe("d2s_nope"))
        self.assertIsNone(access.describe("not-a-token"))
        _, old = access.issue("过期的", ["knowledge"], expires_days=1)
        with access.lock:
            access.db.execute("UPDATE mcp_tokens SET expires_at = '2000-01-01T00:00:00+00:00' WHERE name = '过期的'")
            access.db.commit()
        self.assertEqual(access.describe(old)["status"], "expired")


if __name__ == "__main__":
    unittest.main()
