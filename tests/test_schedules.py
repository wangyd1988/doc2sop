"""定时执行与后台执行（app/schedules.py、app/autorun.py）：时间计算、不重复执行、错过、并发上限、执行规则、发邮件。"""
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from tests.support import clear_graph

from app import automation_config, autorun, conversations, graph, mailer, playbooks, runs, schedules
from app.config import AUTOMATION_FILE

UTC = timezone.utc
STEPS = [{"tool": "host_disk", "args": {"target": ""}, "checkpoint": "根分区超过 80% 告警"}]
TOOLS = {"host_disk"}
OK = ("| 步骤 | 查看 | 实际数据 | 结论 |\n|---|---|---|---|\n| 1 | 宿主机磁盘 | / 40% | ✅ 正常 |\n\n需要跟进：无")
BAD = ("| 步骤 | 查看 | 实际数据 | 结论 |\n|---|---|---|---|\n| 1 | 宿主机磁盘 | / 91% | ❌ 严重：超过 90% |\n\n"
       "需要跟进：\n- 清理日志")


def at(text):
    return datetime.fromisoformat(text).replace(tzinfo=UTC) if "+" not in text else datetime.fromisoformat(text)


def write_config(text):
    AUTOMATION_FILE.write_text(text, encoding="utf-8")
    automation_config.reset()


def remove_config():
    AUTOMATION_FILE.unlink(missing_ok=True)
    automation_config.reset()


def reset_playbooks():
    with playbooks.lock:
        playbooks.db.execute("DELETE FROM steps")
        playbooks.db.execute("DELETE FROM playbooks")
        playbooks.db.commit()


class TimeTests(unittest.TestCase):
    """北京时间（UTC+8）：库里存 UTC。"""

    def slots(self, schedule, after, until):
        return [s.isoformat() for s in schedules.slots(schedule, at(after), at(until))]

    def test_daily_crosses_days(self):
        daily = {"kind": "daily", "at": "09:00"}
        self.assertEqual(self.slots(daily, "2026-11-01T00:30:00", "2026-11-02T02:00:00"),
                         ["2026-11-01T01:00:00+00:00", "2026-11-02T01:00:00+00:00"])
        # 北京时间 00:30 是前一天 UTC 16:30：跨了日期
        night = {"kind": "daily", "at": "00:30"}
        self.assertEqual(self.slots(night, "2026-11-01T16:00:00", "2026-11-01T17:00:00"), ["2026-11-01T16:30:00+00:00"])
        # 起点是开区间、终点是闭区间
        self.assertEqual(self.slots(daily, "2026-11-01T01:00:00", "2026-11-02T01:00:00"), ["2026-11-02T01:00:00+00:00"])

    def test_weekly_crosses_weeks(self):
        """2026-11-01 是周日。周一、周五 09:00。"""
        weekly = {"kind": "weekly", "at": "09:00", "weekdays": "1,5"}
        self.assertEqual(self.slots(weekly, "2026-10-31T00:00:00", "2026-11-09T02:00:00"),
                         ["2026-11-02T01:00:00+00:00", "2026-11-06T01:00:00+00:00", "2026-11-09T01:00:00+00:00"])
        # 北京时间周一 07:00 = UTC 周日 23:00：按北京时间算星期
        early = {"kind": "weekly", "at": "07:00", "weekdays": [1]}
        self.assertEqual(self.slots(early, "2026-11-01T00:00:00", "2026-11-02T00:00:00"), ["2026-11-01T23:00:00+00:00"])

    def test_interval_counts_from_beijing_midnight(self):
        anchor = schedules._anchor(at("2026-11-01T03:07:00"))          # 北京时间 11:07 → 当天 0 点
        self.assertEqual(anchor.isoformat(), "2026-11-01T00:00:00+08:00")
        every = {"kind": "interval", "every": 15, "anchor": anchor.isoformat()}
        self.assertEqual(self.slots(every, "2026-11-01T03:07:00", "2026-11-01T03:50:00"),
                         ["2026-11-01T03:15:00+00:00", "2026-11-01T03:30:00+00:00", "2026-11-01T03:45:00+00:00"])
        self.assertEqual(schedules.next_slot(every, at("2026-11-01T03:45:00")).isoformat(), "2026-11-01T04:00:00+00:00")

    def test_describe(self):
        self.assertEqual(schedules.describe({"kind": "daily", "at": "09:00"}), "每天 09:00")
        self.assertEqual(schedules.describe({"kind": "weekly", "at": "09:00", "weekdays": "1,3,5"}), "每周一、三、五 09:00")
        self.assertEqual(schedules.describe({"kind": "weekly", "at": "08:30", "weekdays": "1,2,3,4,5"}),
                         "工作日（周一到周五）08:30")
        self.assertEqual(schedules.describe({"kind": "interval", "every": 120}), "每 2 小时")
        self.assertEqual(schedules.describe({"kind": "interval", "every": 45}), "每 45 分钟")


class ScheduleCase(unittest.TestCase):
    def setUp(self):
        clear_graph()
        reset_playbooks()
        remove_config()
        self.addCleanup(remove_config)
        self.pid = playbooks.save(None, "每日资源巡检", "每天", STEPS, TOOLS)
        self.book = playbooks.get(self.pid)
        self.queued = []

    def enqueue(self, book, trigger, **kwargs):
        run_id = runs.create(book, trigger, source_id=kwargs.get("source_id", ""), note=kwargs.get("note", ""),
                             params=kwargs.get("params"), status="queued")
        self.queued.append((book["id"], trigger, kwargs))
        return run_id

    def create(self, now="2026-11-01T00:00:00", **raw):
        data = {"playbook_id": self.pid, "kind": "daily", "at": "09:00", "params": {"target": "gateway-b"}, **raw}
        return schedules.create(data, automation_config.load().groups, now=at(now))


class ValidationTests(ScheduleCase):
    def test_blank_params_need_defaults(self):
        with self.assertRaises(schedules.InvalidSchedule) as caught:
            self.create(params={})
        self.assertIn("target", str(caught.exception))
        self.assertEqual(self.create()["params"], {"target": "gateway-b"})

    def test_interval_has_a_floor_and_times_are_checked(self):
        with self.assertRaises(schedules.InvalidSchedule):
            self.create(kind="interval", every=5)
        with self.assertRaises(schedules.InvalidSchedule):
            self.create(at="25:00")
        with self.assertRaises(schedules.InvalidSchedule):
            self.create(kind="weekly", weekdays=[])
        self.assertEqual(self.create(kind="interval", every=15)["describe"], "每 15 分钟")

    def test_only_configured_groups_can_be_chosen(self):
        with self.assertRaises(schedules.InvalidSchedule) as caught:
            self.create(notify={"group": "外面的人"})
        self.assertIn("没有收件组「外面的人」", str(caught.exception))
        write_config("groups:\n  运维值班: [ops@example.com]\n")
        self.assertEqual(self.create(notify={"group": "运维值班"})["notify"]["group"], "运维值班")

    def test_disabled_sops_cannot_be_scheduled_and_limits(self):
        playbooks.set_enabled(self.pid, False)
        with self.assertRaises(schedules.InvalidSchedule):
            self.create()
        playbooks.set_enabled(self.pid, True)
        with patch.object(schedules, "MAX_PER_SOP", 2):
            self.create()
            self.create()
            with self.assertRaises(schedules.InvalidSchedule):
                self.create()


class TickTests(ScheduleCase):
    def test_runs_once_at_the_time(self):
        item = self.create()
        self.assertEqual(schedules.tick(at("2026-11-01T00:59:00"), self.enqueue), [])
        done = schedules.tick(at("2026-11-01T01:00:20"), self.enqueue)
        self.assertEqual([(d[0], d[1]) for d in done], [(item["id"], "run")])
        self.assertEqual(self.queued[0][2]["params"], {"target": "gateway-b"})
        self.assertEqual(self.queued[0][2]["note"], "每天 09:00")
        self.assertEqual(schedules.tick(at("2026-11-01T01:00:40"), self.enqueue), [])
        self.assertEqual(len(self.queued), 1)

    def test_two_processes_never_run_the_same_slot(self):
        """部署切换时新旧两份同时在跑：两边都看到同一个到点的时刻，只有占到的那个执行。"""
        item = self.create()
        schedules.tick(at("2026-11-01T01:00:20"), self.enqueue)
        with graph.lock:      # 另一个进程读到的还是旧的 last_slot
            graph.db.execute("UPDATE sop_schedules SET last_slot = ? WHERE id = ?", ("2026-11-01T00:00:00+00:00", item["id"]))
            graph.db.commit()
        self.assertEqual(schedules.tick(at("2026-11-01T01:00:25"), self.enqueue), [])
        self.assertEqual(len(self.queued), 1)

    def test_a_few_minutes_late_still_runs(self):
        self.create()
        done = schedules.tick(at("2026-11-01T01:08:00"), self.enqueue)
        self.assertEqual(done[0][1], "run")

    def test_missed_runs_are_recorded_once_and_not_caught_up(self):
        item = self.create()
        done = schedules.tick(at("2026-11-03T03:00:00"), self.enqueue)      # 停了两天多
        self.assertEqual([d[1] for d in done], ["missed"])
        self.assertEqual(self.queued, [])
        missed = runs.get(done[0][2])
        self.assertEqual((missed["status"], missed["trigger"], missed["source_id"]), ("missed", "schedule", item["id"]))
        self.assertIn("错过了 3 次", missed["summary"])
        self.assertIn("不补跑", missed["summary"])
        self.assertEqual(schedules.tick(at("2026-11-03T03:00:30"), self.enqueue), [])
        done = schedules.tick(at("2026-11-04T01:00:10"), self.enqueue)      # 下一次照常
        self.assertEqual([d[1] for d in done], ["run"])

    def test_disabled_sop_and_paused_schedule_do_not_run_or_miss(self):
        item = self.create()
        playbooks.set_enabled(self.pid, False)
        self.assertEqual([d[1] for d in schedules.tick(at("2026-11-01T01:00:10"), self.enqueue)], ["blocked"])
        self.assertEqual(runs.listing()[1], 0)
        playbooks.set_enabled(self.pid, True)
        schedules.set_enabled(item["id"], False, now=at("2026-11-01T02:00:00"))
        self.assertEqual(schedules.tick(at("2026-11-02T01:00:10"), self.enqueue), [])
        # 暂停了三天再恢复：暂停期间的不算错过，从恢复那一刻起算
        schedules.set_enabled(item["id"], True, now=at("2026-11-04T05:00:00"))
        self.assertEqual(schedules.tick(at("2026-11-04T05:00:30"), self.enqueue), [])
        self.assertEqual([d[1] for d in schedules.tick(at("2026-11-05T01:00:05"), self.enqueue)], ["run"])

    def test_busy_sop_skips_the_slot(self):
        self.create()
        runs.create(self.book, "web", status="running")                  # 对话里正在「▶ 执行」同一个 SOP
        done = schedules.tick(at("2026-11-01T01:00:10"))
        self.assertEqual(done[0][1], "skipped")
        skipped = runs.get(done[0][2])
        self.assertEqual(skipped["status"], "skipped")
        self.assertIn("上一次还没跑完", skipped["summary"])

    def test_overview_shows_next_and_last(self):
        item = self.create()
        schedules.tick(at("2026-11-01T01:00:10"), self.enqueue)
        listed = schedules.overview(now=at("2026-11-01T02:00:00"))
        self.assertEqual(listed[0]["next_at"], "2026-11-02T01:00:00+00:00")
        self.assertEqual(listed[0]["last"]["source_id"], item["id"])
        self.assertNotIn("notify_state", listed[0])


class AutorunCase(ScheduleCase):
    """后台执行：和「▶ 执行」同样的规则（知识库模式、默认模型、不联网），不建对话，Agent 记忆用完就删。"""

    def setUp(self):
        super().setUp()
        self.calls, self.forgotten = [], []
        patches = [patch.object(autorun, "AGENT_MODE", "auto"),
                   patch.object(autorun, "KB_TOOLS", False),
                   patch.object(autorun.registry, "sop_tools", return_value={"host_disk": "磁盘"}),
                   patch.object(autorun.registry, "has_tools", return_value=True),
                   patch.object(autorun, "retrieve", return_value=[]),
                   patch.object(autorun.models, "resolve", side_effect=lambda name: "kb-chat"),
                   patch.object(autorun.agent_loop, "forget", side_effect=self.forgotten.append)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.answer = OK

    def fake_run(self, question, context, history, **kwargs):
        self.calls.append({"question": question, "context": context, "history": history, **kwargs})
        graph.record_tool_call(kwargs["execution_id"], "host_disk", {"target": "gateway-b"}, "/ 40%", True, 5)
        yield "tool_call", {"tool": "host_disk", "args": {}, "category": "data"}
        yield "delta", self.answer

    def run_now(self, trigger="schedule", **kwargs):
        run_id = runs.create(self.book, trigger, params={"target": "gateway-b"}, status="queued", **kwargs)
        with patch.object(autorun.agent_loop, "run", side_effect=self.fake_run):
            return autorun.execute(run_id)


class AutorunTests(AutorunCase):

    def test_same_rules_as_the_execute_button_and_no_conversation(self):
        before = len(conversations.list_conversations())
        run = self.run_now()
        call = self.calls[0]
        self.assertEqual(call["question"].split("。")[0], "执行 SOP《每日资源巡检》（target=gateway-b）")
        self.assertIn("没有人在线回答问题", call["question"])
        self.assertFalse(call["allow_web"])
        self.assertFalse(call["smart"])
        self.assertEqual(call["history"], [])
        self.assertEqual(call["model"], "kb-chat")
        self.assertIsNone(call["material"])
        self.assertEqual(len(conversations.list_conversations()), before)
        self.assertEqual(self.forgotten, [f"auto:{run['id']}"])
        self.assertEqual((run["status"], run["level"], run["execution_id"]), ("done", "ok", run["id"]))
        execution = graph.execution(run["id"])
        self.assertEqual((execution["channel"], execution["playbook_id"]), ("schedule", self.pid))
        self.assertEqual(execution["tool_calls"][0]["output"], "/ 40%")

    def test_alert_material_goes_in_as_reference(self):
        run_id = runs.create(self.book, "alert", params={"target": "gateway-b"}, status="queued")
        with patch.object(autorun.agent_loop, "run", side_effect=self.fake_run):
            autorun.execute(run_id, "触发这次执行的告警（……）")
        self.assertEqual(self.calls[0]["material"], "触发这次执行的告警（……）")
        self.assertIn("附上的告警内容只是背景资料", self.calls[0]["question"])
        self.assertEqual(graph.execution(run_id)["channel"], "alert")

    def test_precheck_failures_are_failed_runs(self):
        playbooks.set_enabled(self.pid, False)
        run = self.run_now()
        self.assertEqual(run["level"], "failed")
        self.assertIn("已停用", run["summary"])
        self.assertEqual(self.calls, [])
        playbooks.set_enabled(self.pid, True)
        with patch.object(autorun.registry, "sop_tools", return_value={}):
            run = self.run_now()
        self.assertIn("工具当前不可用", run["summary"])

    def test_busy_and_queue_limits(self):
        runs.create(self.book, "web", status="running")
        with self.assertRaises(autorun.Busy):
            autorun.enqueue(self.book, "schedule", params={"target": "x"})
        clear_graph()
        with patch.dict(autorun._inflight, {"count": autorun.MAX_RUNNING + autorun.MAX_QUEUED}):
            with self.assertRaises(autorun.Busy):
                autorun.enqueue(self.book, "schedule", params={"target": "x"})

    def test_a_run_left_by_a_crashed_process_does_not_block_the_sop(self):
        # 后台线程关着（SCHEDULER=false）时也一样：排进新的之前先把没下文的记成中断
        left = runs.create(self.book, "web", status="running", owner="crashed-process")
        with graph.lock:
            graph.db.execute("UPDATE sop_runs SET started_at = ? WHERE id = ?",
                             ((datetime.now(UTC) - timedelta(minutes=15)).isoformat(timespec="seconds"), left))
            graph.db.commit()
        with patch.object(autorun.agent_loop, "run", side_effect=self.fake_run):
            run_id = autorun.enqueue(self.book, "schedule", params={"target": "gateway-b"})
            self.assertTrue(autorun.wait_idle())
        self.assertEqual((runs.get(left)["level"], runs.get(run_id)["level"]), ("failed", "ok"))
        self.assertIn("执行中断", runs.get(left)["summary"])

    def test_enqueue_runs_in_the_background(self):
        with patch.object(autorun.agent_loop, "run", side_effect=self.fake_run):
            run_id = autorun.enqueue(self.book, "web", note="立即执行一次", params={"target": "gateway-b"})
            self.assertTrue(autorun.wait_idle())
        run = runs.get(run_id)
        self.assertEqual((run["status"], run["level"], run["trigger"], run["note"]), ("done", "ok", "web", "立即执行一次"))
        self.assertEqual(graph.execution(run_id)["channel"], "web")

    def test_stale_and_interrupted_runs(self):
        now = datetime.now(UTC)
        old = runs.create(self.book, "schedule", status="running")
        foreign = runs.create(self.book, "schedule", status="running", owner="other-process")
        mine = runs.create(self.book, "schedule", status="running")
        with graph.lock:
            graph.db.execute("UPDATE sop_runs SET started_at = ? WHERE id = ?",
                             ((now - timedelta(minutes=40)).isoformat(timespec="seconds"), old))
            graph.db.execute("UPDATE sop_runs SET started_at = ? WHERE id IN (?, ?)",
                             ((now - timedelta(minutes=15)).isoformat(timespec="seconds"), foreign, mine))
            graph.db.commit()
        self.assertEqual(runs.interrupt_stale(now=now), 2)
        self.assertEqual([runs.get(i)["level"] for i in (old, foreign)], ["failed", "failed"])
        self.assertIn("执行中断", runs.get(old)["summary"])
        self.assertEqual(runs.get(mine)["status"], "running")
        self.assertEqual(runs.interrupt_mine(), 1)
        self.assertIn("应用停止", runs.get(mine)["summary"])


class NotifyAfterRunTests(AutorunCase):
    def setUp(self):
        super().setUp()
        write_config("mail:\n  host: smtp.example.com\n  port: 465\n  user: bot@example.com\n  password: secret-code\n"
                     "  from: bot@example.com\ngroups:\n  运维值班: [ops@example.com]\nsite_url: http://10.0.0.5:8765\n")
        self.schedule = self.create(notify={"group": "运维值班"})
        self.sent = []

    def fake_send(self, group, subject, text, html="", settings=None, **kwargs):
        self.sent.append((group, subject, text, html))
        return {"status": "sent", "attempts": 1, "recipients": 1}

    def run_scheduled(self, answer, now=None):
        self.answer = answer
        with patch.object(mailer, "send", side_effect=self.fake_send):
            return self.run_now(source_id=self.schedule["id"])

    def test_problem_then_quiet_repeat_then_recovered(self):
        first = self.run_scheduled(BAD)
        self.assertEqual(first["mail"]["status"], "sent")
        self.assertEqual(self.sent[0][0], "运维值班")
        self.assertIn("【有异常】SOP《每日资源巡检》", self.sent[0][1])
        self.assertIn("http://10.0.0.5:8765/sop?tab=runs&item=" + first["id"], self.sent[0][2])
        second = self.run_scheduled(BAD.replace("91%", "93%"))       # 同一个问题：一天内不重复发
        self.assertEqual(second["mail"]["status"], "skipped")
        self.assertIn("已经提醒过", second["mail"]["reason"])
        self.assertEqual(len(self.sent), 1)
        third = self.run_scheduled(OK)
        self.assertEqual(third["mail"]["kind"], "recovered")
        self.assertIn("【已恢复】", self.sent[1][1])
        fourth = self.run_scheduled(OK)                                # 正常：默认不发
        self.assertEqual(fourth["mail"]["status"], "skipped")
        self.assertEqual(len(self.sent), 2)

    def test_failed_mail_is_retried_next_time(self):
        def broken(*args, **kwargs):
            raise mailer.MailError("连接 SMTP 服务器超时", 3)

        self.answer = BAD
        with patch.object(mailer, "send", side_effect=broken):
            first = self.run_now(source_id=self.schedule["id"])
        self.assertEqual((first["mail"]["status"], first["mail"]["attempts"]), ("failed", 3))
        second = self.run_scheduled(BAD)
        self.assertEqual(second["mail"]["status"], "sent")

    def test_missed_runs_mail_as_not_run(self):
        with patch.object(mailer, "send", side_effect=self.fake_send):
            done = schedules.tick(at("2026-11-03T03:00:00"), self.enqueue)
        self.assertEqual(done[0][1], "missed")
        self.assertIn("【没跑成】", self.sent[0][1])
        self.assertIn("错过了 3 次", self.sent[0][2])


if __name__ == "__main__":
    unittest.main()
