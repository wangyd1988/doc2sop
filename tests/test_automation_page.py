"""自动执行的设置在页面上填（app/automation_page.py、POST /api/automation/settings）。

真起一个工具服务（tests.test_page_approval_app._WithOps）核对审批口令：扩大能力的要口令、缩小能力的不要；和批准工具共用
输错计数、锁定；字段不对、版本号过时都在核对之前拒绝，不消耗次数；核对时出任何意外都不算通过、不写。授权码只写不读，
去向一变就作废；告警令牌只显示一次；手写的 automation.yaml 优先；旁路文件坏了照常运行；版本号不用密钥算；整个写操作在一把锁里。
"""
import http.server
import json
import os
import re
import socket
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.support import clear_graph
from tests.test_page_approval_app import PASS, POSIX, WRONG, _WithOps, ops
from tests.test_release import BASH

from app import alerts, automation_api, automation_config, automation_page, mailer, notify, playbooks, runs, schedules
from app.agent import ops_client
from app.config import AUTOMATION_FILE

REPO = Path(__file__).resolve().parent.parent
AUTH_CODE = "AUTH-code-qwerty-123456"
MAIL = {"host": "smtp.qq.com", "port": 465, "security": "ssl", "user": "bot@qq.com", "from": "doc2sop 巡检 <bot@qq.com>"}
HAND_TOKEN = "h" * 20 + "-hand-written-token"
STEPS = [{"tool": "host_disk", "args": {"target": ""}, "checkpoint": "根分区超过 80% 告警"}]


def clean_files():
    for path in (AUTOMATION_FILE, automation_page.PAGE_FILE, automation_page.SECRETS_FILE):
        path.unlink(missing_ok=True)
    automation_config.reset()


def write_hand(text):
    AUTOMATION_FILE.write_text(text, encoding="utf-8")
    automation_config.reset()


def write_page(data):
    text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
    automation_page.PAGE_FILE.write_text(text, encoding="utf-8")
    automation_config.reset()


def file_text(path):
    return path.read_text(encoding="utf-8") if path.exists() else ""


class SettingsCase(_WithOps):
    def setUp(self):
        super().setUp()
        clear_graph()
        clean_files()
        self.addCleanup(clean_files)
        self.set_passphrase()
        for patcher in (patch.object(automation_api, "SETTINGS_PER_MINUTE", 1000),
                        patch.dict(automation_api._settings_hits, clear=True),
                        patch.dict(alerts._failures, clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def view(self):
        response = self.client.get("/api/automation", auth=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("cache-control"), "no-store")
        return response.json()["settings"]

    def send(self, change, passphrase=None, version=None):
        body = {"version": self.view()["version"] if version is None else version, "change": change}
        if passphrase is not None:
            body["passphrase"] = passphrase
        return self.post("/api/automation/settings", body)

    def change(self, change, passphrase=None, expect=200, version=None):
        response = self.send(change, passphrase, version)
        self.assertEqual(response.status_code, expect, response.text)
        return response.json()

    def mail(self, **fields):
        return self.change({"kind": "mail", **MAIL, "password": AUTH_CODE, **fields}, passphrase=PASS)

    def hook(self, token):
        headers = {"Authorization": "Bearer " + token} if token else {}
        return self.client.post(alerts.PATH, content=json.dumps({"title": "磁盘使用率高"}), headers=headers)

    def failures(self):
        return ops._approval["failures"]


class ExpandShrinkTests(SettingsCase):
    """扩大能力的改动要审批口令，缩小能力的不要（服务端判断，页面上的口令框只是提示）。"""

    def test_sender_settings_need_the_passphrase_and_clearing_does_not(self):
        answer = self.change({"kind": "mail", **MAIL, "password": AUTH_CODE}, expect=400)
        self.assertEqual((answer["detail"], answer["passphrase"]), ("这项改动扩大了能力，要输审批口令", True))
        answer = self.change({"kind": "mail", **MAIL, "password": AUTH_CODE}, passphrase=WRONG, expect=403)
        self.assertEqual(answer["detail"], "审批口令不对，还能再试 4 次")
        self.assertFalse(automation_page.PAGE_FILE.exists())
        mail = self.mail()["settings"]["mail"]
        self.assertEqual((mail["source"], mail["configured"], mail["host"], mail["user"], mail["password"]["state"]),
                         ("page", True, "smtp.qq.com", "bot@qq.com", "set"))
        loaded = automation_config.load().mail
        self.assertEqual((loaded.password, loaded.sender_addr, loaded.port, loaded.ca_file), (AUTH_CODE, "bot@qq.com", 465, ""))
        # 只重输授权码也算改：要口令
        self.change({"kind": "mail", **MAIL, "password": "another-code-998877"}, expect=400)
        self.change({"kind": "mail", **MAIL, "from": "巡检 <bot@qq.com>"}, expect=400)
        self.assertEqual(self.change({"kind": "mail", **MAIL}, passphrase=PASS, expect=400)["detail"], "没有改动")
        # 清除：不要口令，存着的授权码一起删掉
        cleared = self.change({"kind": "mail-clear"})["settings"]["mail"]
        self.assertEqual((cleared["source"], cleared["configured"]), ("", False))
        self.assertIsNone(automation_config.load().mail)
        self.assertFalse(automation_page.SECRETS_FILE.exists())
        self.assertNotIn("mail", json.loads(file_text(automation_page.PAGE_FILE) or "{}"))
        self.assertEqual(self.change({"kind": "mail-clear"}, expect=400)["detail"], "页面上没有存发件设置")

    def test_new_addresses_need_the_passphrase_and_subsets_do_not(self):
        group = {"kind": "group", "name": "运维值班", "addresses": ["a@x.com", "b@x.com"]}
        self.change({**group, "create": True}, expect=400)
        self.change({**group, "create": True}, passphrase=PASS)
        self.assertEqual(automation_config.load().groups, {"运维值班": ("a@x.com", "b@x.com")})
        self.assertIn("已经有叫", self.change({**group, "create": True}, passphrase=PASS, expect=400)["detail"])
        self.change({**group, "addresses": ["b@x.com"]})                                  # 删地址：子集，不要口令
        self.change({**group, "addresses": ["b@x.com", "A@X.com"]}, expect=400)           # 加回来：要口令
        self.change({**group, "addresses": ["b@x.com", "a@x.com"]}, passphrase=PASS)
        self.change({**group, "addresses": ["a@x.com", "b@x.com"]})                       # 只调顺序：不要口令
        self.assertEqual(self.change({**group, "addresses": ["a@x.com", "b@x.com"]}, expect=400)["detail"], "没有改动")
        self.assertEqual(self.change({**group, "name": "没有这个组"}, passphrase=PASS, expect=409)["stale"], True)
        self.change({"kind": "group-delete", "name": "运维值班"})                          # 删整组：不要口令
        self.assertEqual(automation_config.load().groups, {})
        self.assertFalse(automation_page.PAGE_FILE.exists())                               # 什么都没存了：文件删掉

    def test_report_link_and_alert_sources(self):
        self.change({"kind": "site-url", "value": "http://127.0.0.1:8765"}, expect=400)
        site = self.change({"kind": "site-url", "value": "http://127.0.0.1:8765/"}, passphrase=PASS)["settings"]["site_url"]
        self.assertEqual(site, {"source": "page", "value": "http://127.0.0.1:8765", "plain": True})
        self.change({"kind": "site-url-clear"})
        self.assertEqual(automation_config.load().site_url, "")
        clients = {"kind": "alert-clients"}
        self.change({**clients, "clients": ["10.0.0.0/8"]})                               # 原来不限来源：加限制是缩小
        self.change({**clients, "clients": ["10.0.0.0/8", "192.168.1.0/24"]}, expect=400)  # 新网段：扩大
        self.change({**clients, "clients": ["10.0.0.0/8", "192.168.1.0/24"]}, passphrase=PASS)
        self.change({**clients, "clients": ["10.1.0.0/16"]})                              # 还在原来的范围里：缩小
        self.change({**clients, "clients": ["10.1.2.3"]})
        self.assertEqual(self.change({**clients, "clients": []}, expect=400)["passphrase"], True)   # 删光 = 不限来源
        self.change({**clients, "clients": []}, passphrase=PASS)
        self.assertEqual(automation_config.load().alert_clients, ())

    def test_the_alert_token_is_shown_once_rotated_and_deleted(self):
        self.assertEqual(self.hook("x" * 64).status_code, 404)
        self.change({"kind": "alert-token"}, expect=400)
        answer = self.change({"kind": "alert-token"}, passphrase=PASS)
        token = answer["token"]
        self.assertRegex(token, r"^[0-9a-f]{64}$")
        self.assertEqual(answer["settings"]["alerts"]["token"]["state"], "set")
        status = self.client.get("/api/automation", auth=self.auth).text
        self.assertNotIn(token, status)
        self.assertNotIn(token, json.dumps(answer["settings"]))
        self.assertTrue(self.view()["alerts"]["token"]["set_at"])
        self.assertEqual(self.hook(token).json(), {"received": 1, "triggered": 0})
        self.assertEqual(self.hook("y" * 64).status_code, 401)
        rotated = self.change({"kind": "alert-token"}, passphrase=PASS)["token"]
        self.assertNotEqual(rotated, token)
        self.assertEqual(self.hook(token).status_code, 401)                                 # 旧的立即失效
        self.assertEqual(self.hook(rotated).status_code, 200)
        self.change({"kind": "alert-token-delete"})                                         # 不要口令
        self.assertEqual(self.hook(rotated).status_code, 404)                               # 立刻回到 404
        self.assertFalse(automation_page.SECRETS_FILE.exists())


class LockoutTests(SettingsCase):
    def test_wrong_passphrases_share_the_lockout_with_approvals(self):
        site = {"kind": "site-url", "value": "http://kb.example.com:8765"}
        for left in (4, 3, 2):
            self.assertEqual(self.change(site, passphrase=WRONG, expect=403)["detail"], f"审批口令不对，还能再试 {left} 次")
        item = self.propose()
        self.assertEqual(self.post(f"/api/tools/pending/{item['id']}/approve", {"passphrase": WRONG}).status_code, 403)
        self.change(site, passphrase=WRONG, expect=423)                                     # 第 5 次：锁定
        self.change(site, passphrase=PASS, expect=423)                                      # 锁定中，对的也不核对
        self.assertEqual(self.post(f"/api/tools/pending/{item['id']}/approve", {"passphrase": PASS}).status_code, 423)
        self.assertFalse(automation_page.PAGE_FILE.exists())
        self.assertTrue(self.view()["approval"]["locked"])
        self.change({"kind": "alert-clients", "clients": ["10.0.0.0/8"]})                    # 缩小能力的照常能做
        self.assertNoPassphrase(self.client.get("/api/automation", auth=self.auth).text)


class FieldErrorTests(SettingsCase):
    def test_bad_fields_and_stale_versions_are_refused_before_the_passphrase_is_checked(self):
        bad = [{"kind": "mail", **MAIL, "host": "smtp.qq.com:465"},
               {"kind": "mail", **MAIL, "security": "none"},
               {"kind": "mail", **MAIL, "security": "tls"},
               {"kind": "mail", **MAIL, "port": 70000},
               {"kind": "mail", **MAIL, "from": "不是地址"},
               {"kind": "mail", **MAIL, "user": "", "password": AUTH_CODE},
               {"kind": "mail", **MAIL, "password": "AUTH\ncode-123456"},
               {"kind": "mail", **MAIL, "password": "x" * 201},
               {"kind": "group", "create": True, "name": "值班", "addresses": ["a@x.com", "not-an-address"]},
               {"kind": "group", "create": True, "name": "值" * 31, "addresses": ["a@x.com"]},
               {"kind": "group", "create": True, "name": "值班", "addresses": []},
               {"kind": "group", "create": True, "name": "值班", "addresses": [f"u{i}@x.com" for i in range(51)]},
               {"kind": "site-url", "value": "ftp://kb.example.com"},
               {"kind": "site-url", "value": "http://user:pass@kb.example.com"},
               {"kind": "site-url", "value": "http://kb.example.com/?x=1"},
               {"kind": "site-url", "value": "javascript:alert(1)"},
               {"kind": "alert-clients", "clients": ["10.0.0.0/8", "not-an-ip"]},
               {"kind": "nope"}]
        for change in bad:
            with self.subTest(change=change):
                answer = self.change(change, passphrase=WRONG, expect=400)
                self.assertNotIn(AUTH_CODE, answer["detail"])
        stale = self.change({"kind": "site-url", "value": "http://kb.example.com"}, passphrase=WRONG, expect=409,
                            version="0" * 16)
        self.assertTrue(stale["stale"])
        self.assertEqual(self.failures(), 0)                                                # 都没算一次尝试
        self.assertEqual(self.change({"kind": "site-url", "value": "http://kb.example.com"}, passphrase=WRONG,
                                     expect=403)["detail"], "审批口令不对，还能再试 4 次")
        approvals = [line for line in self.printed.getvalue().splitlines() if line.startswith("[approval]")]
        self.assertEqual(len(approvals), 1, approvals)                                     # 只有最后那一次核对了
        self.assertIn("口令错误（连续第 1 次）", approvals[0])

    def test_bodies_are_parsed_by_hand_and_never_echoed(self):
        url = "/api/automation/settings"
        broken = self.post(url, content=b'{"passphrase": "' + PASS.encode() + b'", oops', headers={"Content-Type": "application/json"})
        self.assertEqual(broken.status_code, 400)
        self.assertEqual(self.post(url, [1, 2]).status_code, 400)
        self.assertEqual(self.post(url, content=b"{" + b" " * (65 * 1024) + b"}").status_code, 413)
        for response in (broken,):
            self.assertNotIn(PASS, response.text)
        self.assertEqual(self.client.post(url, json={"change": {"kind": "mail-clear"}}).status_code, 401)   # 没登录
        cross = self.post(url, {"change": {"kind": "mail-clear"}}, headers={"Origin": "https://evil.example"})
        self.assertEqual(cross.status_code, 403)
        self.assertIn("跨站请求被拒绝", cross.json()["detail"])

    def test_requests_are_rate_limited_per_address(self):
        with patch.object(automation_api, "SETTINGS_PER_MINUTE", 2):
            self.change({"kind": "mail-clear"}, expect=400)
            self.change({"kind": "mail-clear"}, expect=400)
            self.assertIn("操作太频繁了", self.change({"kind": "mail-clear"}, expect=429)["detail"])


class SecretTests(SettingsCase):
    def test_the_password_never_comes_back(self):
        with self.assertLogs("kb", level="INFO") as logs:
            answers = [self.mail(), self.change({"kind": "mail", **MAIL, "host": "a b", "password": AUTH_CODE},
                                                passphrase=PASS, expect=400),
                       self.change({"kind": "mail", **MAIL, "password": AUTH_CODE}, passphrase=WRONG, expect=403),
                       self.client.get("/api/automation", auth=self.auth).json()]
        texts = [json.dumps(answer, ensure_ascii=False) for answer in answers] + [
            "\n".join(logs.output), self.printed.getvalue(), file_text(automation_page.PAGE_FILE),
            json.dumps(automation_page.changes(), ensure_ascii=False)]
        for text in texts:
            self.assertNotIn(AUTH_CODE, text)
        self.assertNoPassphrase(*texts)
        self.assertIn(AUTH_CODE, file_text(automation_page.SECRETS_FILE))                   # 只在这里
        self.assertIn("automation settings changed (user=", "\n".join(logs.output))
        self.assertIn("[approval] 邮件设置 发件服务器 smtp.qq.com:465：口令正确", self.printed.getvalue())
        if POSIX:
            for path in (automation_page.PAGE_FILE, automation_page.SECRETS_FILE):
                self.assertEqual(path.stat().st_mode & 0o777, 0o600, path)

    def test_a_changed_destination_voids_the_password(self):
        for field, value in (("host", "smtp.exmail.qq.com"), ("port", 2465), ("security", "starttls"), ("user", "ops@qq.com")):
            with self.subTest(field=field):
                self.mail()
                changed = self.change({"kind": "mail", **MAIL, field: value}, passphrase=PASS)
                self.assertEqual(changed["settings"]["mail"]["password"]["state"], "missing")
                self.assertNotIn("mail_password", json.loads(file_text(automation_page.SECRETS_FILE) or "{}"))
                self.assertIn("原来的授权码作废了", changed["detail"])
                settings = automation_config.load()
                self.assertIsNone(settings.mail)
                with self.assertRaises(mailer.MailError) as caught:
                    mailer.send("值班", "s", "t", settings=settings)
                self.assertIn("要输入授权码", str(caught.exception))
                self.change({"kind": "mail-clear"})
        # 只改发件人：授权码沿用
        self.mail()
        kept = self.change({"kind": "mail", **MAIL, "from": "巡检 <bot@qq.com>"}, passphrase=PASS)
        self.assertEqual((kept["settings"]["mail"]["password"]["state"], automation_config.load().mail.password),
                         ("set", AUTH_CODE))
        # 两个文件写到一半（或手改了 page.json 的服务器）：去向对不上，授权码不用到新的服务器上
        write_page({"mail": {**MAIL, "host": "smtp.evil.example"}})
        settings = automation_config.load()
        self.assertIsNone(settings.mail)
        self.assertIn("授权码要重新输入", settings.mail_problem)
        self.assertEqual(self.view()["mail"]["password"]["state"], "missing")

    def test_the_version_is_computed_without_any_secret(self):
        self.mail()
        token = self.change({"kind": "alert-token"}, passphrase=PASS)["token"]
        settings = automation_config.load()
        shown = json.dumps(automation_page.sections(settings), ensure_ascii=False)
        self.assertNotIn(AUTH_CODE, shown)
        self.assertNotIn(token, shown)
        before = automation_page.version_of(settings)
        stored = json.loads(file_text(automation_page.SECRETS_FILE))
        stored["mail_password"]["value"] = "a-different-code-0000"
        stored["alert_token"]["value"] = "f" * 64
        automation_page.SECRETS_FILE.write_text(json.dumps(stored), encoding="utf-8")
        automation_config.reset()
        settings = automation_config.load()
        self.assertEqual(settings.mail.password, "a-different-code-0000")
        self.assertEqual(automation_page.version_of(settings), before)        # 换了密钥的值、版本号不变：它不是密钥的函数


class HandWrittenTests(SettingsCase):
    def test_hand_written_keys_win_and_are_read_only_on_the_page(self):
        self.mail()
        self.change({"kind": "group", "create": True, "name": "运维值班", "addresses": ["page@x.com"]}, passphrase=PASS)
        self.change({"kind": "group", "create": True, "name": "页面组", "addresses": ["p2@x.com"]}, passphrase=PASS)
        page_token = self.change({"kind": "alert-token"}, passphrase=PASS)["token"]
        write_hand(f"mail:\n  host: smtp.hand.example\n  user: hand@x.com\n  password: hand-code-123\n"
                   f"groups:\n  运维值班: [hand@x.com]\nalerts:\n  token: {HAND_TOKEN}\n")
        settings = automation_config.load()
        self.assertEqual((settings.mail.host, settings.mail.password), ("smtp.hand.example", "hand-code-123"))
        self.assertEqual(settings.groups, {"运维值班": ("hand@x.com",), "页面组": ("p2@x.com",)})
        self.assertEqual(settings.alert_token, HAND_TOKEN)
        view = self.view()
        self.assertEqual((view["mail"]["source"], view["mail"]["password"]["state"]), ("server", "server"))
        self.assertEqual([(g["name"], g["source"]) for g in view["groups"]], [("运维值班", "server"), ("页面组", "page")])
        self.assertEqual(view["alerts"]["token"]["source"], "server")
        self.assertEqual(sorted(item["kind"] for item in view["skipped"]), ["alert_token", "group", "mail"])
        self.assertNotIn("hand-code-123", json.dumps(view, ensure_ascii=False))
        # 手写的部分在页面上不能改
        self.assertIn("以它为准", self.change({"kind": "mail", **MAIL, "host": "smtp.b.example", "password": "x" * 10},
                                             passphrase=PASS, expect=409)["detail"])
        self.change({"kind": "group", "name": "运维值班", "addresses": ["z@x.com"]}, passphrase=PASS, expect=409)
        self.change({"kind": "alert-token"}, passphrase=PASS, expect=409)
        self.assertEqual(self.hook(page_token).status_code, 401)
        self.assertEqual(self.hook(HAND_TOKEN).status_code, 200)
        # 页面上存着、没生效的那几条可以删掉，不要口令；手写的照常有效
        self.change({"kind": "group-delete", "name": "运维值班"})
        self.change({"kind": "mail-clear"})
        self.change({"kind": "alert-token-delete"})
        settings = automation_config.load()
        self.assertEqual((settings.groups["运维值班"], settings.mail.host, settings.alert_token),
                         (("hand@x.com",), "smtp.hand.example", HAND_TOKEN))
        self.assertEqual(self.view()["skipped"], [])
        self.assertEqual(self.failures(), 0)

    def test_a_broken_hand_written_file_turns_the_page_settings_off(self):
        self.change({"kind": "group", "create": True, "name": "页面组", "addresses": ["p@x.com"]}, passphrase=PASS)
        write_hand("groups: [oops\n")
        self.assertEqual(automation_config.load().groups, {})
        view = self.view()
        self.assertFalse(view["writable"]["ok"])
        self.assertIn("读不了或写坏了", view["writable"]["reason"])
        self.assertEqual(view["skipped"][0]["kind"], "all")
        self.change({"kind": "group-delete", "name": "页面组"}, expect=409)


class BrokenFileTests(SettingsCase):
    def test_a_broken_page_file_keeps_the_app_running(self):
        write_hand("groups:\n  运维值班: [a@x.com]\n")
        write_page('{"site_url": "http://kb.example.com",\n  "groups": oops}')
        self.assertEqual(automation_config.load().groups, {"运维值班": ("a@x.com",)})
        view = self.view()
        self.assertFalse(view["writable"]["ok"])
        self.assertIn("automation.page.json 读不了", view["writable"]["reason"])
        self.assertTrue(any("第 2 行" in problem for problem in view["problems"]))
        self.assertFalse(any("oops" in problem for problem in view["problems"]))
        self.change({"kind": "alert-clients", "clients": ["10.0.0.0/8"]}, expect=409)
        self.assertIn("oops", file_text(automation_page.PAGE_FILE))                          # 没有盖掉手改的内容

    def test_bad_entries_are_skipped_and_can_be_deleted(self):
        write_page({"groups": {"好的": ["a@x.com"], "坏的": ["not-an-address"], "长" * 31: ["b@x.com"]},
                    "mail": {"host": "a b", "user": "u@x.com"}, "alerts": {"clients": ["nope"]}, "what": 1})
        settings = automation_config.load()
        self.assertEqual(settings.groups, {"好的": ("a@x.com",)})
        self.assertIsNone(settings.mail)
        self.assertEqual((settings.alert_clients, settings.alert_networks), (("nope",), ()))
        self.assertFalse(automation_config.client_allowed(settings, "10.0.0.1"))            # 一项都不对：全拒
        view = self.view()
        self.assertEqual(sorted((item["kind"], item["name"]) for item in view["skipped"]),
                         sorted([("group", "坏的"), ("group", "长" * 30), ("mail", "发件设置"), ("alert_clients", "告警来源地址")]))
        self.assertTrue(any("不认识的键：what" in problem for problem in view["problems"]))
        self.assertTrue(view["writable"]["ok"])
        self.change({"kind": "group-delete", "name": "坏的"})
        self.assertNotIn("坏的", json.loads(file_text(automation_page.PAGE_FILE))["groups"])
        self.assertEqual(json.loads(file_text(automation_page.PAGE_FILE))["what"], 1)       # 不认识的键原样留着

    def test_a_broken_secrets_file_means_nothing_is_stored(self):
        self.mail()
        self.change({"kind": "alert-token"}, passphrase=PASS)
        automation_page.SECRETS_FILE.write_text('{"mail_password": ' + json.dumps(AUTH_CODE) + ', oops', encoding="utf-8")
        automation_config.reset()
        settings = automation_config.load()
        self.assertIsNone(settings.mail)
        self.assertIn("读不了", settings.mail_problem)
        self.assertEqual(settings.alert_token, "")
        self.assertEqual(self.hook("x" * 64).status_code, 404)
        view = self.view()
        self.assertEqual(view["mail"]["password"]["state"], "missing")
        self.assertTrue(any("automation.page-secrets.json" in problem for problem in view["problems"]))
        self.assertNotIn(AUTH_CODE, json.dumps(view, ensure_ascii=False))
        token = self.change({"kind": "alert-token"}, passphrase=PASS)["token"]             # 整个重写
        self.assertEqual(self.hook(token).status_code, 200)
        self.assertNotIn(AUTH_CODE, file_text(automation_page.SECRETS_FILE))


class ReadOnlyTests(SettingsCase):
    def test_without_a_tool_service_the_page_is_read_only(self):
        with patch.object(ops_client, "OPS_URL", ""):
            view = self.view()
            self.assertFalse(view["writable"]["ok"])
            self.assertIn("OPS_URL", view["writable"]["reason"])
            self.assertIsNone(view["approval"])
            self.change({"kind": "alert-clients", "clients": ["10.0.0.0/8"]}, expect=403)   # 不要口令的也不行

    def test_an_old_tool_service_makes_the_page_read_only(self):
        real = ops_client._request

        def old(path, *args, **kwargs):
            if path == "/tools/approval/verify":
                raise ops_client.OpsUnavailable("接口返回 404", status=404)
            return real(path, *args, **kwargs)

        with patch.object(ops_client, "_request", side_effect=old):
            view = self.view()
            self.assertEqual(view["writable"]["reason"], ops_client.OLD_SERVICE_VERIFY)
            self.assertEqual(self.change({"kind": "alert-clients", "clients": ["10.0.0.0/8"]}, expect=403)["detail"],
                             ops_client.OLD_SERVICE_VERIFY)
        # 探测说有、核对时却回 404：一样按老工具服务处理
        with patch.object(ops_client, "verify_passphrase",
                          side_effect=ops_client.OpsUnavailable("接口返回 404", status=404)):
            self.change({"kind": "site-url", "value": "http://kb.example.com"}, passphrase=PASS, expect=403)
        self.assertFalse(automation_page.PAGE_FILE.exists())

    def test_page_config_off_makes_everything_read_only(self):
        with patch.dict(os.environ, {"OPS_PAGE_CONFIG": "off"}):
            view = self.view()
            self.assertIn("OPS_PAGE_CONFIG=off", view["writable"]["reason"])
            self.change({"kind": "alert-clients", "clients": ["10.0.0.0/8"]}, expect=403)
            self.change({"kind": "site-url", "value": "http://kb.example.com"}, passphrase=PASS, expect=403)
        self.assertEqual(self.failures(), 0)
        self.assertFalse(automation_page.PAGE_FILE.exists())


class _FakeOps(http.server.BaseHTTPRequestHandler):
    """探测说「有核对接口、页面配置开着」，核对时按 mode 出各种意外。"""
    mode = "ok"

    def log_message(self, *args):
        pass

    def reply(self, status, body):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/tools/approval/verify":
            return self.reply(200, {"page_config": True})
        return self.reply(200, {"approval": {"configured": True, "locked": False, "unlock_minutes": 0, "problem": ""}})

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        mode = type(self).mode
        if mode == "reset":
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        if mode == "slow":
            time.sleep(1.5)
            return self.reply(200, {"ok": True})
        answers = {"500": (500, {"error": "boom"}), "502": (502, b"<html>bad gateway</html>"),
                   "html": (200, b"<html>ok</html>"), "false": (200, {"ok": False}), "empty": (200, {}),
                   "string": (200, {"ok": "true"}), "list": (200, [True]), "401": (401, {"error": "令牌不对"}),
                   "201": (201, {"ok": True}), "ok": (200, {"ok": True})}
        return self.reply(*answers[mode])


class _QuietServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass                                     # 「连接被重置」是故意的，不打印回溯


class VerifyFailureTests(SettingsCase):
    """核对口令时出任何意外都按「没通过」处理：只有 200 且回 {"ok": true} 才写。"""

    def setUp(self):
        super().setUp()
        server = _QuietServer(("127.0.0.1", 0), _FakeOps)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        for patcher in (patch.object(ops_client, "OPS_URL", f"http://127.0.0.1:{server.server_address[1]}"),
                        patch.object(ops_client, "VERIFY_TIMEOUT", 0.5)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_anything_but_200_ok_true_is_not_a_pass(self):
        site = {"kind": "site-url", "value": "http://kb.example.com"}
        for mode, status in (("500", 502), ("502", 502), ("html", 502), ("false", 502), ("empty", 502), ("string", 502),
                             ("list", 502), ("401", 502), ("201", 502), ("reset", 503), ("slow", 503)):
            with self.subTest(mode=mode), patch.object(_FakeOps, "mode", mode):
                answer = self.change(site, passphrase=PASS, expect=status)
                self.assertIn("没有改", answer["detail"])
                self.assertFalse(automation_page.PAGE_FILE.exists())
                self.assertEqual(automation_page.changes(), [])
        with patch.object(ops_client, "verify_passphrase", side_effect=RuntimeError("surprise")):
            self.assertIn("不算通过", self.change(site, passphrase=PASS, expect=502)["detail"])
        self.assertFalse(automation_page.PAGE_FILE.exists())
        with patch.object(_FakeOps, "mode", "ok"):
            self.change(site, passphrase=PASS)
        self.assertEqual(automation_config.load().site_url, "http://kb.example.com")


class LockTests(SettingsCase):
    def test_the_whole_write_holds_one_lock(self):
        """两个请求拿着同一个版本号：先到的在核对口令时，后到的等着；先到的写完，后到的版本号过时，回 409，盖不掉。"""
        version = self.view()["version"]
        entered, release, results = threading.Event(), threading.Event(), {}
        real = ops_client.verify_passphrase

        def slow(*args, **kwargs):
            entered.set()
            release.wait(10)
            return real(*args, **kwargs)

        def run(name, change, passphrase=None):
            try:
                results[name] = automation_page.apply({"version": version, "change": change, "passphrase": passphrase},
                                                      "web user=t ip=1.2.3.4", "t", "1.2.3.4")
            except automation_page.Refused as exc:
                results[name] = exc

        with patch.object(ops_client, "verify_passphrase", side_effect=slow):
            first = threading.Thread(target=run, args=("first", {"kind": "site-url", "value": "http://a.example"}, PASS))
            first.start()
            self.assertTrue(entered.wait(10))
            second = threading.Thread(target=run, args=("second", {"kind": "alert-clients", "clients": ["10.0.0.0/8"]}))
            second.start()
            time.sleep(0.3)
            self.assertTrue(second.is_alive())                       # 在等锁：还没读、没核对版本号
            release.set()
            first.join(10)
            second.join(10)
        self.assertIsInstance(results["first"], dict)
        self.assertIsInstance(results["second"], automation_page.Refused)
        self.assertEqual((results["second"].status, results["second"].extra), (409, {"stale": True}))
        self.assertEqual((automation_config.load().site_url, automation_config.load().alert_clients), ("http://a.example", ()))


class CacheTests(SettingsCase):
    def test_a_replaced_file_with_the_same_size_and_time_is_noticed(self):
        write_page({"site_url": "http://a.example:1"})
        self.assertEqual(automation_config.load().site_url, "http://a.example:1")
        before = os.stat(automation_page.PAGE_FILE)
        temporary = automation_page.PAGE_FILE.with_name("replacement.tmp")
        temporary.write_text(json.dumps({"site_url": "http://b.example:1"}), encoding="utf-8")
        os.utime(temporary, ns=(before.st_atime_ns, before.st_mtime_ns))
        os.replace(temporary, automation_page.PAGE_FILE)
        after = os.stat(automation_page.PAGE_FILE)
        if after.st_ino == before.st_ino:
            self.skipTest("这个文件系统没有给新文件新的 inode")
        self.assertEqual((after.st_size, after.st_mtime_ns, after.st_mode), (before.st_size, before.st_mtime_ns, before.st_mode))
        self.assertEqual(automation_config.load().site_url, "http://b.example:1")

    def test_the_app_forgets_the_cache_after_its_own_writes(self):
        with patch.object(automation_config, "_stamp", return_value=("same",)):
            automation_config.reset()
            self.assertEqual(automation_config.load().site_url, "")
            self.change({"kind": "site-url", "value": "http://a.example"}, passphrase=PASS)
            self.assertEqual(automation_config.load().site_url, "http://a.example")


class GroupInUseTests(SettingsCase):
    def setUp(self):
        super().setUp()
        with playbooks.lock:
            playbooks.db.execute("DELETE FROM steps")
            playbooks.db.execute("DELETE FROM playbooks")
            playbooks.db.commit()
        self.pid = playbooks.save(None, "磁盘排查", "磁盘告警时", STEPS, {"host_disk"})

    def test_deleting_a_group_in_use_needs_the_current_list_and_then_mail_fails_with_a_reason(self):
        self.mail()
        self.change({"kind": "group", "create": True, "name": "值班", "addresses": ["a@x.com"]}, passphrase=PASS)
        groups = automation_config.load().groups
        schedule = schedules.create({"playbook_id": self.pid, "kind": "daily", "at": "09:00", "params": {"target": "gw"},
                                     "notify": {"group": "值班"}}, groups)
        alerts.create_rule({"playbook_id": self.pid, "name_contains": "Disk", "params": {"target": "gw"},
                            "notify": {"group": "值班"}}, groups)
        used = self.view()["used_by"]["值班"]
        self.assertEqual(sorted(item["kind"] for item in used), ["rule", "schedule"])
        self.assertTrue(all("磁盘排查" in item["name"] for item in used))
        refused = self.change({"kind": "group-delete", "name": "值班"}, expect=409)
        self.assertEqual(refused["used_by"], used)
        self.change({"kind": "group-delete", "name": "值班", "used_by": used[:1]}, expect=409)
        self.assertEqual(self.failures(), 0)
        done = self.change({"kind": "group-delete", "name": "值班", "used_by": used})
        self.assertIn("2 条计划、告警规则还选着它", done["detail"])
        # 计划照常在、照常执行；邮件那一项记成失败，写明原因
        self.assertTrue(schedules.get(schedule["id"])["enabled"])
        run_id = runs.create(playbooks.get(self.pid), "schedule", source_id=schedule["id"], params={"target": "gw"},
                             status="done")
        mail = notify.after_run(runs.get(run_id), {"group": "值班", "when": "always", "repeat": "always"}, {},
                                lambda state: None)
        self.assertEqual(mail["status"], "failed")
        self.assertIn("没有收件组「值班」：可能已经删掉了", mail["error"])
        self.assertEqual(runs.get(run_id)["mail"]["status"], "failed")


class MiscTests(SettingsCase):
    def test_nothing_configured_behaves_as_before(self):
        settings = automation_config.load()
        self.assertEqual((settings.exists, settings.mail, settings.groups, settings.alert_token, settings.site_url,
                          settings.problems, settings.skipped), (False, None, {}, "", "", (), ()))
        view = self.view()
        self.assertEqual((view["mail"]["source"], view["groups"], view["skipped"], view["problems"]), ("", [], [], []))
        self.assertTrue(view["writable"]["ok"])
        self.assertEqual(view["approval"]["configured"], True)

    def test_changes_are_recorded_without_secrets_and_capped(self):
        self.mail()
        self.change({"kind": "alert-token"}, passphrase=PASS)
        self.change({"kind": "mail-clear"})
        recorded = self.view()["changes"]
        self.assertEqual([item["kind"] for item in recorded], ["mail-clear", "alert-token", "mail"])
        self.assertEqual((recorded[0]["user"], recorded[0]["ip"]), (automation_api.WEB_USER, "testclient"))
        self.assertIn("新设发件设置：smtp.qq.com:465（SSL）；授权码已更新", recorded[2]["detail"])
        for _ in range(automation_page.CHANGES_KEEP + 5):
            automation_page._record("site-url", "x", "t", "-")
        self.assertEqual(len(automation_page.changes(1000)), automation_page.CHANGES_KEEP)

    def test_test_mail_uses_the_page_settings(self):
        self.assertIn("还没有配置发件邮箱", self.post("/api/automation/test-mail", {"group": "值班"}).json()["detail"])
        self.mail()
        self.change({"kind": "group", "create": True, "name": "值班", "addresses": ["a@x.com"]}, passphrase=PASS)
        self.assertIn("没有收件组「别的」", self.post("/api/automation/test-mail", {"group": "别的"}).json()["detail"])
        sent = []
        with patch.object(mailer, "send", side_effect=lambda *a, **k: sent.append(k["settings"]) or {"recipients": 1}), \
             patch.dict(automation_api._test_mail, {"times": __import__("collections").deque(), "by_group": {}}):
            self.assertEqual(self.post("/api/automation/test-mail", {"group": "值班"}).status_code, 200)
        self.assertEqual((sent[0].mail.password, sent[0].groups["值班"]), (AUTH_CODE, ("a@x.com",)))
        self.change({"kind": "mail", **MAIL, "host": "smtp.other.example"}, passphrase=PASS)   # 授权码作废了
        self.assertIn("要输入授权码", self.post("/api/automation/test-mail", {"group": "值班"}).json()["detail"])


class BackupTests(unittest.TestCase):
    """备份包带上页面上填的、不含密钥的设置；授权码、令牌（page-secrets.json、手写的 automation.yaml）不进。"""
    SCRIPT = REPO / "deploy" / "backup.sh"

    def test_the_copy_list(self):
        text = self.SCRIPT.read_text(encoding="utf-8")
        listed = " ".join(line for line in text.splitlines() if re.match(r"\s*for \w+ in ", line))
        self.assertIn("automation.page.json", listed)
        self.assertNotIn("page-secrets", listed)
        self.assertNotIn("automation.yaml", listed)
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("automation.page-secrets.json", code)

    @unittest.skipUnless(BASH and POSIX, "要 Linux 上的 bash、tar")
    def test_the_archive(self):
        with tempfile.TemporaryDirectory() as data, tempfile.TemporaryDirectory() as dest:
            for name, text in (("automation.yaml", "mail: {}\n"), ("automation.page.json", "{}\n"),
                               ("automation.page-secrets.json", '{"alert_token": {"value": "x"}}\n')):
                Path(data, name).write_text(text, encoding="utf-8")
            import subprocess
            done = subprocess.run([BASH, str(self.SCRIPT), dest], capture_output=True, text=True,
                                  env={**os.environ, "KB_DATA": data})
            self.assertEqual(done.returncode, 0, done.stderr)
            archive = next(Path(dest).glob("kb-*.tgz"))
            with tarfile.open(archive) as tar:
                names = {Path(name).name for name in tar.getnames()}
        self.assertIn("automation.page.json", names)
        self.assertNotIn("automation.page-secrets.json", names)
        self.assertNotIn("automation.yaml", names)


if __name__ == "__main__":
    unittest.main()
