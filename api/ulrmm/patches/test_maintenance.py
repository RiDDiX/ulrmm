# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
from types import SimpleNamespace
from unittest.mock import patch
from zoneinfo import ZoneInfo

from django.core.cache import cache as django_cache
from django.test import SimpleTestCase, override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from agents.utils import wake_agents
from logs.models import AuditLog
from ulrmm.constants import AgentMonType, AgentPlat
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase
from winupdate.installing import get_installing
from winupdate.tasks import check_agent_update_schedule_task

from .maintenance import install_finished, run_pass, scan_finished
from .models import MaintenanceSchedule, RunState, ScheduleRun
from .recurrence import current, upcoming
from .views import PREVIEW_RUNS

UTC = dt.timezone.utc
BERLIN = ZoneInfo("Europe/Berlin")
base_url = "/patches/schedules"


def rule(**kw):
    r = dict(
        frequency="weekly",
        run_time=dt.time(3, 0),
        dates=[],
        weekdays=[],
        month_day=None,
        month_week=None,
        month_weekday=None,
        start_date=None,
        end_date=None,
        excluded_dates=[],
    )
    r.update(kw)
    return SimpleNamespace(**r)


def local(starts, tz=BERLIN):
    return [s.astimezone(tz).strftime("%Y-%m-%d %H:%M %Z") for s in starts]


H2 = dt.timedelta(minutes=120)


class TestRecurrence(SimpleTestCase):
    def test_weekly_tuesday_0300(self):
        r = rule(weekdays=[1])
        after = dt.datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
        self.assertEqual(
            local(upcoming(r, BERLIN, after, H2, 3)),
            [
                "2026-10-20 03:00 CEST",
                "2026-10-27 03:00 CET",
                "2026-11-03 03:00 CET",
            ],
        )
        # the window open right now counts
        inside = dt.datetime(2026, 10, 20, 2, 30, tzinfo=UTC)
        self.assertEqual(
            current(r, BERLIN, inside, H2), dt.datetime(2026, 10, 20, 1, tzinfo=UTC)
        )
        self.assertEqual(upcoming(r, BERLIN, inside, H2, 1)[0].day, 20)
        self.assertIsNone(current(r, BERLIN, inside + H2, H2))

    def test_monthly_last_friday(self):
        r = rule(frequency="monthly", month_week=-1, month_weekday=4)
        after = dt.datetime(2026, 10, 1, tzinfo=UTC)
        self.assertEqual(
            [s.astimezone(BERLIN).date() for s in upcoming(r, BERLIN, after, H2, 5)],
            [
                dt.date(2026, 10, 30),
                dt.date(2026, 11, 27),
                dt.date(2026, 12, 25),
                dt.date(2027, 1, 29),
                dt.date(2027, 2, 26),
            ],
        )

    def test_monthly_nth_weekday_and_day(self):
        # patch tuesday
        r = rule(frequency="monthly", month_week=2, month_weekday=1)
        after = dt.datetime(2026, 10, 1, tzinfo=UTC)
        days = [s.astimezone(BERLIN).day for s in upcoming(r, BERLIN, after, H2, 3)]
        self.assertEqual(days, [13, 10, 8])

        # the 31st runs on the last day of shorter months
        r = rule(frequency="monthly", month_day=31)
        after = dt.datetime(2027, 1, 1, tzinfo=UTC)
        self.assertEqual(
            [s.astimezone(BERLIN).date() for s in upcoming(r, BERLIN, after, H2, 3)],
            [dt.date(2027, 1, 31), dt.date(2027, 2, 28), dt.date(2027, 3, 31)],
        )

    def test_one_off_and_excluded_dates(self):
        r = rule(
            frequency="once",
            run_time=dt.time(14, 30),
            dates=[dt.date(2026, 10, 1), dt.date(2026, 10, 15)],
        )
        after = dt.datetime(2026, 9, 1, tzinfo=UTC)
        self.assertEqual(
            local(upcoming(r, BERLIN, after, H2, 5)),
            ["2026-10-01 14:30 CEST", "2026-10-15 14:30 CEST"],
        )
        after = dt.datetime(2026, 10, 2, tzinfo=UTC)
        self.assertEqual(len(upcoming(r, BERLIN, after, H2, 5)), 1)

        r = rule(weekdays=[1], excluded_dates=[dt.date(2026, 10, 27)])
        after = dt.datetime(2026, 10, 19, tzinfo=UTC)
        self.assertEqual([s.day for s in upcoming(r, BERLIN, after, H2, 2)], [20, 3])

    def test_start_and_end_date(self):
        r = rule(
            frequency="daily",
            start_date=dt.date(2026, 10, 10),
            end_date=dt.date(2026, 10, 11),
        )
        after = dt.datetime(2026, 10, 1, tzinfo=UTC)
        self.assertEqual([s.day for s in upcoming(r, BERLIN, after, H2, 5)], [10, 11])

    def test_spring_forward_gap(self):
        # 02:30 does not exist on 2027-03-28, it runs at 03:30 CEST
        r = rule(frequency="daily", run_time=dt.time(2, 30))
        after = dt.datetime(2027, 3, 27, tzinfo=UTC)
        self.assertEqual(
            local(upcoming(r, BERLIN, after, H2, 3)),
            [
                "2027-03-27 02:30 CET",
                "2027-03-28 03:30 CEST",
                "2027-03-29 02:30 CEST",
            ],
        )
        # the window lasts the elapsed duration
        start = upcoming(r, BERLIN, after, H2, 2)[1]
        self.assertEqual(
            current(r, BERLIN, start + H2 - dt.timedelta(seconds=1), H2), start
        )

    def test_fall_back_runs_once(self):
        # 02:30 happens twice on 2026-10-25, the window opens at the first one
        r = rule(frequency="daily", run_time=dt.time(2, 30))
        span = dt.timedelta(minutes=30)
        after = dt.datetime(2026, 10, 24, 12, tzinfo=UTC)
        first = upcoming(r, BERLIN, after, span, 1)[0]
        self.assertEqual(first, dt.datetime(2026, 10, 25, 0, 30, tzinfo=UTC))
        self.assertEqual(local([first]), ["2026-10-25 02:30 CEST"])
        # 02:30 CET, one hour later on the wall clock, opens nothing
        self.assertIsNone(
            current(r, BERLIN, dt.datetime(2026, 10, 25, 1, 40, tzinfo=UTC), span)
        )

    def test_window_over_midnight(self):
        r = rule(frequency="daily", run_time=dt.time(23, 0))
        now = dt.datetime(2026, 10, 20, 22, 30, tzinfo=UTC)  # 00:30 CEST
        self.assertEqual(
            local([current(r, BERLIN, now, H2)]), ["2026-10-20 23:00 CEST"]
        )


class NatsAgent:
    """nats_cmd stand-in: answers per agent and function, records calls."""

    def __init__(self):
        self.answers = {}
        self.calls = []

    def __call__(self, agent, data, timeout=30, wait=True):
        self.calls.append((agent.hostname, data["func"], data))
        ans = self.answers.get((agent.hostname, data["func"]))
        if ans is None:
            ans = {"ping": "pong", "keepawake": "ok", "suspend": "ok"}.get(data["func"])
        return ans

    def funcs(self, host=None):
        return [f for h, f, _ in self.calls if host is None or h == host]


@patch("patches.maintenance.HOLD_FOR", 0)
@patch("patches.maintenance.get_mesh_ws_url", return_value="ws://mesh")
@patch("patches.maintenance.wake_on_lan")
@patch("patches.maintenance.wake_agents", return_value={})
class TestMaintenanceRuns(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.base = djangotime.now().replace(second=0, microsecond=0)
        self.site = baker.make("clients.Site")
        self.pc = self.make_agent("pc")
        self.nats = NatsAgent()
        p = patch("agents.models.Agent.nats_cmd", autospec=True, side_effect=self.nats)
        p.start()
        self.addCleanup(p.stop)

    def make_agent(self, name, **kw):
        kw.setdefault("monitoring_type", AgentMonType.WORKSTATION)
        kw.setdefault("plat", AgentPlat.WINDOWS)
        kw.setdefault("site", self.site)
        return baker.make_recipe(
            "agents.agent",
            hostname=name,
            time_zone="UTC",
            last_seen=self.base,
            wmi_detail={"nics": []},
            **kw,
        )

    def schedule(self, kind="maintenance", duration=120, owner="john", **kw):
        kw.setdefault("agents", [self.pc.agent_id])
        s = baker.make(
            "patches.MaintenanceSchedule",
            name=f"{kind} window",
            kind=kind,
            frequency="daily",
            run_time=(self.base - dt.timedelta(minutes=1)).time(),
            duration=duration,
            **kw,
        )
        # save() takes the user of the last request in this thread
        MaintenanceSchedule.objects.filter(pk=s.pk).update(modified_by=owner)
        s.modified_by = owner
        return s

    def at(self, minutes):
        run_pass(self.base + dt.timedelta(minutes=minutes))

    def get_run(self, agent=None):
        return ScheduleRun.objects.get(agent=agent or self.pc)

    def audits(self, action):
        return AuditLog.objects.filter(
            username="system", message__contains=f"executed {action}"
        ).count()

    def test_happy_path_wakes_installs_and_sleeps(self, wake, *_):
        self.schedule()
        baker.make("winupdate.WinUpdate", agent=self.pc, guid="g1", action="approve")
        self.nats.answers[("pc", "ping")] = "timeout"

        self.at(0)
        run = self.get_run()
        self.assertEqual((run.state, run.woke, run.wakes), (RunState.WAKING, True, 1))
        wake.assert_called_once()
        self.assertIsNone(wake.call_args.args[1])  # system: same-site relays only
        self.assertEqual(self.audits("wake"), 1)

        # retried at +5
        self.at(3)
        self.assertEqual(self.get_run().wakes, 1)
        self.at(5)
        self.assertEqual(self.get_run().wakes, 2)
        self.assertEqual(wake.call_count, 2)

        # answers: held awake until the window ends, then the scan
        self.nats.answers[("pc", "ping")] = "pong"
        self.at(6)
        self.assertEqual(self.get_run().state, RunState.SCANNING)
        keep = [d for _, f, d in self.nats.calls if f == "keepawake"][0]
        self.assertEqual(keep["until"], int(self.get_run().ends.timestamp()))
        self.assertIn("getwinupdates", self.nats.funcs())

        scan_finished(self.pc)
        self.assertEqual(self.get_run().state, RunState.SCANNED)
        self.at(7)
        self.assertEqual(self.get_run().state, RunState.INSTALLING)
        install = [d for _, f, d in self.nats.calls if f == "installwinupdates"][0]
        self.assertEqual(install["guids"], ["g1"])
        self.assertEqual(self.audits("install 1 updates"), 1)

        # the hourly task keeps out while the window runs
        with patch("winupdate.tasks.Agent.online_agents", return_value=[self.pc]):
            n = len(self.nats.calls)
            check_agent_update_schedule_task()
            self.assertEqual(len(self.nats.calls), n)

        install_finished(self.pc, rebooting=False)
        self.at(8)
        self.assertEqual(self.get_run().state, RunState.IDLE_WAIT)

        # somebody works on it: wait
        self.nats.answers[("pc", "idle")] = 60
        self.at(9)
        self.assertEqual(self.get_run().state, RunState.IDLE_WAIT)
        self.assertNotIn("suspend", self.nats.funcs())

        self.nats.answers[("pc", "idle")] = 901
        self.at(30)
        self.assertEqual(self.get_run().state, RunState.SLEPT)
        self.assertEqual(self.nats.funcs().count("suspend"), 1)
        self.assertEqual(self.audits("suspend"), 1)

        # done: nothing more for this occurrence
        n = len(self.nats.calls)
        self.at(31)
        self.assertEqual(len(self.nats.calls), n)

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_install_marks_only_after_nats_publish(self, *_):
        django_cache.clear()
        down = self.make_agent("down")
        self.schedule(agents=[self.pc.agent_id, down.agent_id])
        for agent in (self.pc, down):
            baker.make("winupdate.WinUpdate", agent=agent, guid="g1", action="approve")

        self.at(0)
        scan_finished(self.pc)
        scan_finished(down)
        self.nats.answers[("down", "installwinupdates")] = "natsdown"
        self.at(1)

        self.assertEqual(get_installing(self.pc.pk), {"g1"})
        self.assertEqual(get_installing(down.pk), set())

    def test_no_session_counts_as_idle(self, *_):
        self.schedule()
        self.nats.answers[("pc", "ping")] = "timeout"
        self.at(0)
        self.nats.answers[("pc", "ping")] = "pong"
        self.at(1)
        scan_finished(self.pc)
        self.at(2)  # nothing approved
        self.assertEqual(self.get_run().state, RunState.IDLE_WAIT)
        self.nats.answers[("pc", "idle")] = -1
        self.at(3)
        self.assertEqual(self.get_run().state, RunState.SLEPT)

    def test_awake_at_start_is_left_awake(self, wake, *_):
        self.schedule()
        self.at(0)
        run = self.get_run()
        # woken anyway, but not by us
        wake.assert_called_once()
        self.assertEqual((run.state, run.woke), (RunState.SCANNING, False))
        scan_finished(self.pc)
        self.at(1)
        self.assertEqual(self.get_run().state, RunState.DONE)
        self.assertNotIn("idle", self.nats.funcs())
        self.assertNotIn("suspend", self.nats.funcs())

    def test_server_never_sleeps(self, *_):
        self.pc.monitoring_type = AgentMonType.SERVER
        self.pc.save(update_fields=["monitoring_type"])
        self.schedule()
        self.nats.answers[("pc", "ping")] = "timeout"
        self.at(0)
        self.nats.answers[("pc", "ping")] = "pong"
        self.at(1)
        scan_finished(self.pc)
        self.at(2)
        self.assertEqual(self.get_run().state, RunState.DONE)
        self.assertNotIn("suspend", self.nats.funcs())

    def woken_idle_wait(self):
        self.schedule()
        self.nats.answers[("pc", "ping")] = "timeout"
        self.at(0)
        self.nats.answers[("pc", "ping")] = "pong"
        self.at(1)
        scan_finished(self.pc)
        self.at(2)
        self.assertEqual(self.get_run().state, RunState.IDLE_WAIT)

    def test_unknown_idle_leaves_awake(self, *_):
        for answer in ("timeout", "natsdown", "some error", True, -5, None):
            with self.subTest(answer=answer):
                ScheduleRun.objects.all().delete()
                MaintenanceSchedule.objects.all().delete()
                self.nats.answers.clear()
                self.woken_idle_wait()
                self.nats.answers[("pc", "idle")] = answer
                self.at(3)
                self.assertEqual(self.get_run().state, RunState.LEFT_AWAKE)
                self.assertNotIn("suspend", self.nats.funcs())

    def test_failed_suspend_leaves_awake(self, *_):
        self.woken_idle_wait()
        self.nats.answers[("pc", "idle")] = 1000
        self.nats.answers[("pc", "suspend")] = "timeout"
        self.at(3)
        self.assertEqual(self.get_run().state, RunState.LEFT_AWAKE)

    def test_window_end_leaves_awake(self, *_):
        self.schedule(duration=30)
        baker.make("winupdate.WinUpdate", agent=self.pc, guid="g1", action="approve")
        self.nats.answers[("pc", "ping")] = "timeout"
        self.at(0)
        self.nats.answers[("pc", "ping")] = "pong"
        self.at(1)
        scan_finished(self.pc)
        self.at(2)
        self.assertEqual(self.get_run().state, RunState.INSTALLING)
        self.at(29)
        self.assertEqual(self.get_run().state, RunState.TIMEOUT)
        # a report after the end changes nothing
        install_finished(self.pc, rebooting=False)
        self.at(30)
        self.assertEqual(self.get_run().state, RunState.TIMEOUT)
        self.assertNotIn("suspend", self.nats.funcs())

    def test_no_answer_fails_after_four_wakes(self, wake, *_):
        self.schedule()
        self.nats.answers[("pc", "ping")] = "timeout"
        for minute in range(0, 31):
            self.at(minute)
        run = self.get_run()
        self.assertEqual((run.state, run.wakes), (RunState.FAILED, 4))
        self.assertEqual(wake.call_count, 4)
        self.assertNotIn("keepawake", self.nats.funcs())

    def test_nats_down_decides_nothing(self, wake, *_):
        self.schedule()
        self.nats.answers[("pc", "ping")] = "natsdown"
        self.at(0)
        self.assertEqual(self.get_run().state, RunState.NEW)
        wake.assert_not_called()

    def test_reboot_waits_for_the_agent(self, *_):
        self.schedule()
        baker.make("winupdate.WinUpdate", agent=self.pc, guid="g1", action="approve")
        self.nats.answers[("pc", "ping")] = "timeout"
        self.at(0)
        self.nats.answers[("pc", "ping")] = "pong"
        self.at(1)
        scan_finished(self.pc)
        self.at(2)
        install_finished(self.pc, rebooting=True)
        self.assertEqual(self.get_run().state, RunState.REBOOTING)
        self.at(3)
        self.assertEqual(self.get_run().state, RunState.REBOOTING)
        self.nats.answers[("pc", "ping")] = "timeout"
        self.at(6)
        self.assertEqual(self.get_run().state, RunState.REBOOTING)
        self.nats.answers[("pc", "ping")] = "pong"
        keeps = self.nats.funcs().count("keepawake")
        self.at(7)
        # the hold died with the agent process, sent again
        self.assertEqual(self.nats.funcs().count("keepawake"), keeps + 1)
        self.assertEqual(self.get_run().state, RunState.IDLE_WAIT)

    def test_scan_without_report_installs_known_updates(self, *_):
        self.schedule()
        baker.make("winupdate.WinUpdate", agent=self.pc, guid="g1", action="approve")
        self.at(0)
        self.at(20)
        self.assertEqual(self.get_run().state, RunState.SCANNING)
        self.at(31)
        self.assertEqual(self.get_run().state, RunState.INSTALLING)

    def test_error_leaves_awake(self, *_):
        self.schedule()
        with patch(
            "agents.models.Agent.delete_superseded_updates",
            side_effect=RuntimeError("boom"),
        ):
            self.at(0)
        self.assertEqual(self.get_run().state, RunState.LEFT_AWAKE)
        self.assertIn("boom", self.get_run().detail)

    def test_posix_without_automation_installs_nothing(self, *_):
        self.pc.plat = AgentPlat.LINUX
        self.pc.save(update_fields=["plat"])
        self.schedule()
        self.nats.answers[("pc", "ping")] = "timeout"
        self.at(0)
        self.nats.answers[("pc", "ping")] = "pong"
        with self.settings(ULRMM_POSIX_PATCH_AUTOMATION=False):
            self.at(1)
        run = self.get_run()
        self.assertEqual(run.state, RunState.IDLE_WAIT)
        self.assertIn("POSIX", run.detail)
        self.assertIn("keepawake", self.nats.funcs())

    def test_owner_scope_and_permission(self, wake, *_):
        other = self.make_agent("other", site=baker.make("clients.Site"))
        s = self.schedule(agents=[self.pc.agent_id, other.agent_id], owner="bob")
        bob = baker.make("accounts.User", username="bob")
        bob.role = baker.make(
            "accounts.Role",
            can_manage_patch_policies=True,
            can_send_wol=True,
            can_reboot_agents=True,
            can_list_agents=True,
        )
        bob.role.can_view_sites.set([self.site])
        bob.save()

        self.at(0)
        self.assertEqual(self.get_run(other).state, RunState.REFUSED)
        self.assertEqual(self.get_run().state, RunState.SCANNING)
        self.assertNotIn("other", {h for h, _, _ in self.nats.calls})

        # bob loses the permission mid run: the run stops, nothing else is sent
        bob.role.can_manage_patch_policies = False
        bob.role.save()
        self.at(1)
        run = self.get_run()
        self.assertEqual(run.state, RunState.REFUSED)
        self.assertIn("bob", run.detail)

        # a disabled schedule opens nothing
        ScheduleRun.objects.all().delete()
        s.enabled = False
        s.save()
        self.at(2)
        self.assertFalse(ScheduleRun.objects.exists())

    def test_patch_manager_without_power_flags_is_refused(self, wake, *_):
        self.schedule(owner="bob")
        bob = baker.make("accounts.User", username="bob")
        bob.role = baker.make(
            "accounts.Role", can_manage_patch_policies=True, can_list_agents=True
        )
        bob.save()
        self.at(0)
        self.assertEqual(self.get_run().state, RunState.REFUSED)
        wake.assert_not_called()
        self.assertEqual(self.nats.calls, [])

    def test_unknown_owner_is_refused(self, wake, *_):
        self.schedule(owner="ghost")
        self.at(0)
        self.assertEqual(self.get_run().state, RunState.REFUSED)
        wake.assert_not_called()

    def test_hold_right_after_the_wake(self, *_):
        self.schedule()
        self.nats.answers[("pc", "ping")] = "timeout"

        def sleep(_):
            self.nats.answers[("pc", "ping")] = "pong"

        with (
            patch("patches.maintenance.HOLD_FOR", 30),
            patch("patches.maintenance.time.sleep", side_effect=sleep),
        ):
            self.at(0)
        self.assertEqual(self.nats.funcs().count("keepawake"), 1)
        self.assertEqual(self.get_run().state, RunState.WAKING)

    def test_hold_is_sent_again_every_pass(self, *_):
        # the agent drops its hold on a restart and keeps only the last one
        self.schedule(duration=240)
        self.schedule(duration=60)
        for minute in range(3):
            self.at(minute)
        ends = ScheduleRun.objects.get(schedule__duration=240).ends
        keeps = [d["until"] for _, f, d in self.nats.calls if f == "keepawake"]
        self.assertEqual(keeps, [int(ends.timestamp())] * 3)

        # not while it does not answer
        self.nats.answers[("pc", "ping")] = "timeout"
        self.at(3)
        self.assertEqual(self.nats.funcs().count("keepawake"), 3)

    def test_winupdates_put_reports_the_install(self, *_):
        self.schedule()
        baker.make("winupdate.WinUpdate", agent=self.pc, guid="g1", action="approve")
        self.at(0)
        scan_finished(self.pc)
        self.at(1)
        self.assertEqual(self.get_run().state, RunState.INSTALLING)

        self.authenticate_agent(self.pc)
        r = self.client.put(
            "/api/v3/winupdates/", {"needs_reboot": False}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.get_run().state, RunState.INSTALLED)

    # sleep schedules
    def test_sleep_schedule(self, *_):
        self.schedule(kind="sleep", duration=60)
        self.nats.answers[("pc", "idle")] = 300
        self.at(0)
        self.assertEqual(self.get_run().state, RunState.IDLE_WAIT)
        self.nats.answers[("pc", "idle")] = 900
        self.at(1)
        self.assertEqual(self.get_run().state, RunState.SLEPT)
        self.assertEqual(self.audits("suspend"), 1)

    def test_sleep_schedule_skips(self, *_):
        server = self.make_agent("srv", monitoring_type=AgentMonType.SERVER)
        away = self.make_agent("away")
        self.nats.answers[("away", "ping")] = "timeout"
        self.schedule(kind="sleep", duration=60, sites=[self.site.pk], agents=[])
        self.nats.answers[("pc", "idle")] = 100
        self.at(0)
        self.assertEqual(self.get_run(server).state, RunState.SKIPPED)
        self.assertEqual(self.get_run(away).state, RunState.SKIPPED)
        self.assertEqual(self.get_run().state, RunState.IDLE_WAIT)
        self.assertNotIn("suspend", self.nats.funcs())
        # still in use when the time is up
        self.at(59)
        self.assertEqual(self.get_run().state, RunState.TIMEOUT)

    def test_sleep_waits_for_a_maintenance_run(self, *_):
        self.schedule()
        self.schedule(kind="sleep", duration=60)
        self.nats.answers[("pc", "idle")] = 1000
        self.at(0)
        sleep_run = ScheduleRun.objects.get(schedule__kind="sleep")
        self.assertEqual(sleep_run.state, RunState.IDLE_WAIT)
        self.assertNotIn("suspend", self.nats.funcs())

    # wake schedules
    def test_wake_schedule(self, wake, *_):
        self.schedule(kind="wake", duration=60)
        self.nats.answers[("pc", "ping")] = "timeout"
        self.at(0)
        self.assertEqual(self.get_run().state, RunState.WAKING)
        self.assertEqual(self.audits("wake"), 1)
        self.nats.answers[("pc", "ping")] = "pong"
        self.at(1)
        self.assertEqual(self.get_run().state, RunState.DONE)
        self.assertEqual(self.nats.funcs().count("keepawake"), 1)
        self.assertNotIn("getwinupdates", self.nats.funcs())

    def test_wake_schedule_holds_until_the_end(self, *_):
        s = self.schedule(kind="wake", duration=60)
        self.nats.answers[("pc", "ping")] = "timeout"
        self.at(0)
        self.nats.answers[("pc", "ping")] = "pong"
        self.at(1)
        self.at(30)
        self.assertEqual(self.get_run().state, RunState.DONE)
        self.assertEqual(self.nats.funcs().count("keepawake"), 2)

        # disabled: the device is not contacted any more
        MaintenanceSchedule.objects.filter(pk=s.pk).update(enabled=False)
        n = len(self.nats.calls)
        self.at(31)
        self.assertEqual(len(self.nats.calls), n)

        # nor after the end
        MaintenanceSchedule.objects.filter(pk=s.pk).update(enabled=True)
        self.at(59)
        self.assertEqual(len(self.nats.calls), n)

    def test_wake_schedule_already_awake(self, wake, *_):
        self.schedule(kind="wake", duration=60)
        self.at(0)
        self.assertEqual(self.get_run().state, RunState.DONE)
        wake.assert_not_called()


class TestSystemWake(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()

    @patch("agents.utils.send_magic_packet")
    @patch("agents.utils.server_networks", return_value=set())
    @patch("agents.utils.abulk_nats_command")
    def test_relays_same_site_only(self, bulk, *_):
        nic = {"nics": [{"mac": "00:11:22:33:44:55", "ips": ["192.168.1.20/24"]}]}
        relay_nic = {"nics": [{"mac": "00:11:22:33:44:66", "ips": ["192.168.1.21/24"]}]}
        site, other = baker.make("clients.Site", _quantity=2)
        target = baker.make_recipe(
            "agents.agent", site=site, public_ip="1.2.3.4", wmi_detail=nic
        )
        for s in (site, other):
            baker.make_recipe(
                "agents.agent",
                hostname=f"relay-{s.pk}",
                site=s,
                public_ip="1.2.3.4",
                wmi_detail=relay_nic,
                last_seen=djangotime.now(),
            )

        from agents.models import Agent

        sent = wake_agents(Agent.objects.filter(pk=target.pk), None)
        self.assertEqual(sent[target.pk], [f"relay-{site.pk}"])


class TestScheduleApi(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.site = baker.make("clients.Site")
        self.agent = baker.make_recipe("agents.agent", site=self.site)

    def body(self, **kw):
        b = {
            "name": "Patch Tuesday",
            "kind": "maintenance",
            "frequency": "weekly",
            "run_time": "03:00",
            "weekdays": [1],
            "duration": 120,
            "agents": [self.agent.agent_id],
        }
        b.update(kw)
        return b

    def limited_user(self, **perms):
        user = baker.make("accounts.User", username="limited")
        user.role = baker.make("accounts.Role", can_list_agents=True, **perms)
        user.save()
        self.client.force_authenticate(user=user)
        return user

    def test_create_list_update_delete(self):
        r = self.client.post(f"{base_url}/", self.body(), format="json")
        self.assertEqual(r.status_code, 200, r.data)
        s = MaintenanceSchedule.objects.get()
        self.assertEqual((s.created_by, s.modified_by), ("john", "john"))
        self.assertEqual(s.run_time, dt.time(3, 0))
        audit = AuditLog.objects.get(object_type="maintenanceschedule")
        self.assertEqual(audit.after_value["agents"], [self.agent.agent_id])

        r = self.client.get(f"{base_url}/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data), 1)
        self.assertEqual(len(r.data[0]["next_runs"]), 1)

        # alice saves it last and owns it from now on
        self.client.force_authenticate(user=self.alice)
        body = self.body(frequency="monthly", month_week=-1, month_weekday=4)
        r = self.client.put(f"{base_url}/{s.pk}/", body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        s.refresh_from_db()
        self.assertEqual((s.modified_by, s.weekdays, s.month_week), ("alice", [], -1))
        changed = AuditLog.objects.filter(object_type="maintenanceschedule").last()
        self.assertEqual(changed.before_value["weekdays"], [1])

        r = self.client.delete(f"{base_url}/{s.pk}/")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(MaintenanceSchedule.objects.exists())

        self.check_not_authenticated("get", f"{base_url}/")

    def test_validation(self):
        bad = [
            {"weekdays": []},
            {"weekdays": [7]},
            {"duration": 361},
            {"duration": 1},
            {"frequency": "once", "dates": []},
            {"frequency": "monthly"},
            {"frequency": "monthly", "month_week": 5, "month_weekday": 1},
            {"agents": []},
            {"agents": ["nope" * 10]},
            {"sites": [999999]},
            {"kind": "reboot"},
            {"start_date": "2026-10-10", "end_date": "2026-10-01"},
        ]
        for data in bad:
            with self.subTest(data=data):
                r = self.client.post(f"{base_url}/", self.body(**data), format="json")
                self.assertEqual(r.status_code, 400)
        self.assertFalse(MaintenanceSchedule.objects.exists())

    def test_kind_permissions(self):
        self.limited_user(can_send_wol=True)
        for kind, code in (("maintenance", 403), ("sleep", 403), ("wake", 200)):
            with self.subTest(kind=kind):
                r = self.client.post(
                    f"{base_url}/", self.body(kind=kind), format="json"
                )
                self.assertEqual(r.status_code, code)

        user = baker.make("accounts.User", username="sleeper")
        user.role = baker.make(
            "accounts.Role", can_list_agents=True, can_reboot_agents=True
        )
        user.save()
        self.client.force_authenticate(user=user)
        r = self.client.post(f"{base_url}/", self.body(kind="sleep"), format="json")
        self.assertEqual(r.status_code, 200)

        # changing the kind needs the permission of the new kind too
        s = MaintenanceSchedule.objects.get(kind="sleep")
        r = self.client.put(
            f"{base_url}/{s.pk}/", self.body(kind="wake"), format="json"
        )
        self.assertEqual(r.status_code, 403)

        # listing needs can_list_agents
        user.role.can_list_agents = False
        user.role.save()
        self.assertEqual(self.client.get(f"{base_url}/").status_code, 403)

        # a maintenance window also wakes and suspends
        user = baker.make("accounts.User", username="patcher")
        user.role = baker.make(
            "accounts.Role", can_list_agents=True, can_manage_patch_policies=True
        )
        user.save()
        self.client.force_authenticate(user=user)
        r = self.client.post(f"{base_url}/", self.body(), format="json")
        self.assertEqual(r.status_code, 403)
        user.role.can_send_wol = user.role.can_reboot_agents = True
        user.role.save()
        r = self.client.post(f"{base_url}/", self.body(), format="json")
        self.assertEqual(r.status_code, 200)

    def test_scope(self):
        other_site = baker.make("clients.Site")
        other = baker.make_recipe("agents.agent", site=other_site)
        foreign = MaintenanceSchedule.objects.create(
            name="x",
            kind="wake",
            frequency="daily",
            run_time=dt.time(3),
            agents=[other.agent_id],
        )
        user = self.limited_user(can_send_wol=True)
        user.role.can_view_sites.set([self.site])

        r = self.client.post(
            f"{base_url}/",
            self.body(kind="wake", agents=[other.agent_id]),
            format="json",
        )
        self.assertEqual(r.status_code, 403)
        r = self.client.post(
            f"{base_url}/",
            self.body(kind="wake", agents=[], sites=[self.site.pk]),
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        # the sites of a client are not the client
        r = self.client.post(
            f"{base_url}/",
            self.body(kind="wake", agents=[], clients=[self.site.client_id]),
            format="json",
        )
        self.assertEqual(r.status_code, 403)

        r = self.client.get(f"{base_url}/")
        self.assertEqual([i["name"] for i in r.data], ["Patch Tuesday"])
        self.assertEqual(self.client.get(f"{base_url}/{foreign.pk}/").status_code, 403)
        r = self.client.put(
            f"{base_url}/{foreign.pk}/", self.body(kind="wake"), format="json"
        )
        self.assertEqual(r.status_code, 403)
        self.assertEqual(
            self.client.delete(f"{base_url}/{foreign.pk}/").status_code, 403
        )
        self.assertTrue(MaintenanceSchedule.objects.filter(pk=foreign.pk).exists())

    def test_preview(self):
        body = self.body(agents=[])
        r = self.client.post(f"{base_url}/preview/", body, format="json")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(len(r.data["runs"]), PREVIEW_RUNS)
        tz = ZoneInfo(r.data["timezone"])
        for run in r.data["runs"]:
            start = dt.datetime.fromisoformat(run["start"]).astimezone(tz)
            self.assertEqual((start.weekday(), start.hour, start.minute), (1, 3, 0))

        r = self.client.post(
            f"{base_url}/preview/", self.body(weekdays=[]), format="json"
        )
        self.assertEqual(r.status_code, 400)

    def test_agent_schedules(self):
        s = MaintenanceSchedule.objects.create(
            name="site wide",
            kind="sleep",
            frequency="daily",
            run_time=dt.time(23),
            sites=[self.site.pk],
        )
        MaintenanceSchedule.objects.create(
            name="elsewhere", kind="sleep", frequency="daily", run_time=dt.time(23)
        )
        ScheduleRun.objects.create(
            schedule=s,
            agent=self.agent,
            occurrence=djangotime.now(),
            ends=djangotime.now(),
            changed=djangotime.now(),
            state=RunState.SLEPT,
        )
        r = self.client.get(f"{base_url}/agent/{self.agent.agent_id}/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([i["name"] for i in r.data], ["site wide"])
        self.assertEqual(r.data[0]["last_run"]["state"], "slept")
        self.assertNotIn("sites", r.data[0])
