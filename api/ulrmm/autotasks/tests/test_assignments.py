# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, UTC
from threading import Barrier
from unittest.mock import AsyncMock, patch

import time_machine
from django.db import connections
from django.test import TransactionTestCase, override_settings
from model_bakery import baker

from automation.models import Policy
from autotasks.models import TaskResult
from core.models import CoreSettings
from core.tasks import _add_failing, scheduled_task_runner, sync_scheduled_tasks
from ulrmm import scheduler
from ulrmm.constants import (
    AgentPlat,
    AlertSeverity,
    TaskStatus,
    TaskSyncStatus,
    TaskType,
)
from ulrmm.test import TEST_CACHE, TEST_MESH_KEY, ULRMMTestCase

DUE = datetime(2026, 10, 12, 10, 30, tzinfo=UTC)


class TestAssignments(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_base_instance()
        self.authenticate()
        self.agent = baker.make_recipe(
            "agents.online_agent",
            site=self.site1,
            plat=AgentPlat.LINUX,
            monitoring_type="workstation",
            time_zone="UTC",
        )
        self.policies = baker.make("automation.Policy", active=True, _quantity=2)
        self.site1.workstation_policy = self.policies[0]
        self.site1.save()
        self.company1.workstation_policy = self.policies[1]
        self.company1.save()
        self.task = baker.make(
            "autotasks.AutomatedTask",
            agent=self.agent,
            task_type=TaskType.DAILY,
            task_supported_platforms=[AgentPlat.LINUX],
            run_time_date=DUE,
            daily_interval=2,
        )
        self.endpoint = f"/tasks/{self.task.pk}/assignments/"

    def change(self, **payload):
        reply = self.client.patch(self.endpoint, payload, format="json")
        self.assertEqual(reply.status_code, 200, reply.data)
        return next(row for row in reply.data["devices"] if row["id"] == self.agent.pk)

    @patch("core.tasks.abulk_nats_command", new_callable=AsyncMock)
    def test_three_sources_single_claim_and_removal(self, publish):
        originals = [p.pk for p in self.policies]
        row = self.change(add_policies=originals)
        self.assertEqual(row["policy_ids"], originals)
        self.assertTrue(row["direct"])
        self.assertEqual(row["schedule"], "Daily at 10:30")
        reply = self.client.get(f"/agents/{self.agent.agent_id}/tasks/")
        self.assertEqual(reply.status_code, 200, reply.data)
        self.assertEqual(len(reply.data), 1)
        self.assertEqual(
            reply.data[0]["assignment_sources"],
            {
                "direct": True,
                "policies": [{"id": p.pk, "name": p.name} for p in self.policies],
            },
        )
        with time_machine.travel(DUE, tick=False):
            sync_scheduled_tasks()
            expected = [
                (self.agent.agent_id, {"func": "runtask", "taskpk": self.task.pk})
            ]
            self.assertEqual(scheduled_task_runner(), expected)
            # A retry in the same due minute cannot claim it, even after the lock is clear.
            TaskResult.objects.filter(task=self.task, agent=self.agent).update(
                locked_at=None
            )
            self.assertEqual(scheduled_task_runner(), [])
        publish.assert_awaited_once_with(items=expected)

        row = self.change(remove_agents=[self.agent.pk])
        self.assertFalse(row["direct"])
        self.assertTrue(row["effective"])
        row = self.change(remove_policies=originals[:1])
        self.assertEqual(row["policy_ids"], originals[1:])
        with time_machine.travel(DUE + timedelta(days=1), tick=False):
            self.assertEqual(scheduled_task_runner(), expected)
        row = self.change(remove_policies=originals[1:])
        self.assertFalse(row["effective"])
        with time_machine.travel(DUE + timedelta(days=2), tick=False):
            self.assertEqual(scheduled_task_runner(), [])
        self.assertEqual(publish.await_count, 2)
        self.assertTrue(
            any(
                row["id"] == self.task.pk
                for row in self.client.get("/tasks/catalog/").data
            )
        )
        self.authenticate_agent(self.agent)
        response = self.client.get(
            f"/api/v3/{self.task.pk}/{self.agent.agent_id}/taskrunner/"
        )
        self.assertEqual(response.status_code, 400)

    def test_policy_reaches_later_members_and_respects_inheritance_blocks(self):
        self.change(add_policies=[self.policies[0].pk])
        later = baker.make_recipe(
            "agents.online_agent",
            site=self.site1,
            plat=AgentPlat.LINUX,
            monitoring_type="workstation",
        )
        tasks = later.get_tasks_with_policies()
        self.assertEqual([t.pk for t in tasks], [self.task.pk])
        self.assertFalse(tasks[0].effective_sources["direct"])
        later.block_policy_inheritance = True
        later.save(update_fields=["block_policy_inheritance"])
        self.assertEqual(later.get_tasks_with_policies(), [])
        # No record cloning means a deliberately separate time remains separate.
        other = baker.make(
            "autotasks.AutomatedTask",
            agent=self.agent,
            name=self.task.name,
            task_type=TaskType.DAILY,
            run_time_date=DUE + timedelta(hours=1),
        )
        self.assertCountEqual(
            [t.pk for t in self.agent.get_tasks_with_policies()],
            [self.task.pk, other.pk],
        )

    def test_deleting_original_device_keeps_shared_definition(self):
        self.change(add_policies=[self.policies[0].pk])
        private = baker.make("autotasks.AutomatedTask", agent=self.agent)
        later = baker.make_recipe(
            "agents.online_agent",
            site=self.site1,
            plat=AgentPlat.LINUX,
            monitoring_type="workstation",
        )
        self.agent.delete()
        self.task.refresh_from_db()
        self.assertIsNone(self.task.agent_id)
        self.assertEqual(self.task.run_time_date, DUE)
        self.assertFalse(type(self.task).objects.filter(pk=private.pk).exists())
        self.assertEqual(
            [task.pk for task in later.get_tasks_with_policies()], [self.task.pk]
        )

    @patch("autotasks.tasks.remove_orphaned_win_tasks.delay")
    def test_delete_of_unassigned_definition_removes_it_before_refresh(self, cleanup):
        self.change(remove_agents=[self.agent.pk])
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.delete(f"/tasks/{self.task.pk}/")
        self.assertEqual(response.data, f"{self.task.name} was deleted")
        cleanup.assert_called_once()
        self.assertFalse(type(self.task).objects.filter(pk=self.task.pk).exists())

    @patch("autotasks.tasks.delete_win_task_schedule.delay")
    def test_pending_windows_delete_cannot_be_reassigned(self, delete_copy):
        self.agent.plat = AgentPlat.WINDOWS
        self.agent.save(update_fields=["plat"])
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.delete(f"/tasks/{self.task.pk}/")
        self.assertEqual(response.data, f"{self.task.name} will be deleted shortly")
        delete_copy.assert_called_once_with(pk=self.task.pk)
        self.task.refresh_from_db()
        self.assertFalse(self.task.owner_assigned)
        response = self.client.patch(
            self.endpoint, {"add_agents": [self.agent.pk]}, format="json"
        )
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(
            TaskResult.objects.get(task=self.task).sync_status,
            TaskSyncStatus.PENDING_DELETION,
        )

    def test_batch_denies_foreign_device_or_policy_without_partial_mutation(self):
        in_scope, foreign = [
            baker.make_recipe("agents.online_agent", site=site, plat=AgentPlat.LINUX)
            for site in (self.site1, self.site3)
        ]
        foreign_policy = baker.make("automation.Policy")
        self.site3.server_policy = foreign_policy
        self.site3.save()
        user = self.create_user_with_roles(
            [
                "can_manage_autotasks",
                "can_list_autotasks",
                "can_manage_automation_policies",
                "can_run_bulk",
            ]
        )
        user.role.can_view_sites.set([self.site1])
        self.client.force_authenticate(user=user)

        for payload in (
            {"add_agents": [in_scope.pk, foreign.pk]},
            {"add_agents": [in_scope.pk], "add_policies": [foreign_policy.pk]},
        ):
            result = self.client.patch(self.endpoint, payload, format="json")
            self.assertEqual(result.status_code, 403, result.data)
            self.assertFalse(self.task.additional_agents.exists())
            self.assertFalse(self.task.additional_policies.exists())

    def test_scoped_user_can_remove_only_their_device_link(self):
        foreign = baker.make_recipe(
            "agents.online_agent", site=self.site3, plat=AgentPlat.LINUX
        )
        self.change(add_agents=[foreign.pk])
        user = self.create_user_with_roles(
            ["can_manage_autotasks", "can_list_autotasks"]
        )
        user.role.can_view_sites.set([self.site1])
        self.client.force_authenticate(user=user)
        row = self.change(remove_agents=[self.agent.pk])
        self.assertFalse(row["effective"])
        self.assertTrue(self.task.additional_agents.contains(foreign))

    def test_definition_edit_and_delete_require_policy_management(self):
        self.change(add_policies=[self.policies[0].pk])
        user = self.create_user_with_roles(
            ["can_manage_autotasks", "can_list_autotasks"]
        )
        self.client.force_authenticate(user=user)
        response = self.client.get(self.endpoint)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(response.data["can_delete_definition"])
        definition = f"/tasks/{self.task.pk}/"
        self.assertEqual(
            self.client.put(definition, {"enabled": False}, format="json").status_code,
            403,
        )
        self.assertEqual(self.client.delete(definition).status_code, 403)

    def test_policy_copy_of_a_shared_definition_requires_task_management(self):
        source = self.policies[0]
        self.change(add_policies=[source.pk])
        user = self.create_user_with_roles(["can_manage_automation_policies"])
        self.client.force_authenticate(user=user)
        body = {"name": "Copy of the source policy", "copyId": source.pk}
        response = self.client.post("/automation/policies/", body, format="json")
        self.assertEqual(response.status_code, 403, response.data)
        self.assertFalse(type(source).objects.filter(name=body["name"]).exists())

        self.client.force_authenticate(user=self.john)
        response = self.client.post("/automation/policies/", body, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        copy = type(source).objects.get(name=body["name"]).autotasks.get()
        self.assertNotEqual(copy.pk, self.task.pk)
        self.assertEqual(copy.run_time_date, self.task.run_time_date)

    def test_scoped_user_can_assign_a_policy_on_their_empty_site(self):
        policy = baker.make("automation.Policy", active=True)
        self.site2.workstation_policy = policy
        self.site2.save()
        user = self.create_user_with_roles(
            [
                "can_manage_autotasks",
                "can_list_autotasks",
                "can_manage_automation_policies",
            ]
        )
        user.role.can_view_sites.set([self.site1, self.site2])
        self.client.force_authenticate(user=user)
        response = self.client.get(self.endpoint)
        row = next(row for row in response.data["policies"] if row["id"] == policy.pk)
        self.assertTrue(row["editable"])
        self.change(add_policies=[policy.pk])
        response = self.client.get(f"/automation/policies/{policy.pk}/tasks/")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual([row["id"] for row in response.data], [self.task.pk])
        later = baker.make_recipe(
            "agents.online_agent",
            site=self.site2,
            plat=AgentPlat.LINUX,
            monitoring_type="workstation",
        )
        self.assertEqual(
            [task.pk for task in later.get_tasks_with_policies()], [self.task.pk]
        )

    def test_global_list_masks_env_vars_when_task_reaches_outside_scope(self):
        foreign = baker.make_recipe(
            "agents.online_agent", site=self.site3, plat=AgentPlat.LINUX
        )
        self.task.actions = [{"type": "script", "env_vars": ["TOKEN=example-secret"]}]
        self.task.save(update_fields=["actions"])
        self.change(add_agents=[foreign.pk])
        user = self.create_user_with_roles(
            ["can_manage_autotasks", "can_list_autotasks"]
        )
        user.role.can_view_sites.set([self.site1])
        self.client.force_authenticate(user=user)
        result = self.client.get("/tasks/")
        self.assertEqual(result.status_code, 200, result.data)
        self.assertNotIn("example-secret", str(result.data))

    def test_catalog_includes_allowed_shared_and_empty_policy_definitions(self):
        device = baker.make_recipe(
            "agents.online_agent",
            site=self.site3,
            plat=AgentPlat.LINUX,
        )
        empty_policy = baker.make("automation.Policy", active=True)
        self.site3.server_policy = empty_policy
        self.site3.save()
        empty_task = baker.make("autotasks.AutomatedTask", policy=empty_policy)
        invisible = baker.make("autotasks.AutomatedTask", agent=self.agent)
        self.change(add_agents=[device.pk])

        user = self.create_user_with_roles(["can_list_autotasks"])
        user.role.can_view_sites.set([self.site3])
        self.client.force_authenticate(user=user)
        reply = self.client.get("/tasks/catalog/")
        self.assertEqual(reply.status_code, 200, reply.data)
        ids = {task["id"] for task in reply.data}
        self.assertEqual(ids, {self.task.pk, empty_task.pk})
        self.assertNotIn(invisible.pk, ids)
        self.assertEqual(self.client.get(self.endpoint).status_code, 200)

        self.agent.delete()
        reply = self.client.get("/tasks/catalog/")
        self.assertEqual({task["id"] for task in reply.data}, ids)

    def test_unplaced_policy_definition_is_hidden_from_scoped_roles(self):
        policy = baker.make("automation.Policy")
        task = baker.make(
            "autotasks.AutomatedTask",
            policy=policy,
            actions=[{"type": "script", "env_vars": ["TOKEN=private-fixture"]}],
        )
        for relation, owner in (
            ("can_view_clients", self.company1),
            ("can_view_sites", self.site1),
        ):
            with self.subTest(relation=relation):
                user = self.create_user_with_roles(
                    ["can_list_autotasks", "can_manage_autotasks"]
                )
                getattr(user.role, relation).add(owner)
                self.client.force_authenticate(user=user)
                response = self.client.get(f"/tasks/{task.pk}/")
                self.assertEqual(response.status_code, 403, response.data)
                self.assertNotIn("private-fixture", str(response.data))
                self.assertEqual(
                    self.client.get(f"/tasks/{task.pk}/assignments/").status_code, 403
                )
                ids = {row["id"] for row in self.client.get("/tasks/catalog/").data}
                self.assertNotIn(task.pk, ids)

        # the default slot also reaches a device outside the scope: read only
        baker.make_recipe(
            "agents.online_agent", site=self.site3, monitoring_type="workstation"
        )
        self.coresettings.workstation_policy = policy
        self.coresettings.save()
        response = self.client.get(f"/tasks/{task.pk}/")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertNotIn("private-fixture", str(response.data))

    @patch("autotasks.tasks.run_win_task.delay")
    @patch("automation.tasks.run_win_policy_autotasks_task.delay")
    def test_manual_targets_match_the_selected_view(self, policy_run, agent_run):
        policy = self.policies[0]
        self.change(add_policies=[policy.pk])
        result = self.client.post(
            f"/automation/tasks/{self.task.pk}/run/",
            {"policy": policy.pk},
            format="json",
        )
        self.assertEqual(result.status_code, 200, result.data)
        policy_run.assert_called_once_with(
            task=self.task.pk, policy_id=policy.pk, agent_pks=[self.agent.pk]
        )
        result = self.client.post(
            f"/tasks/{self.task.pk}/run/",
            {"agent_id": self.agent.agent_id},
            format="json",
        )
        self.assertEqual(result.status_code, 200, result.data)
        agent_run.assert_called_once_with(pk=self.task.pk, agent_id=self.agent.agent_id)

    @patch("core.tasks._run_win_task_sync", new_callable=AsyncMock)
    def test_windows_registers_one_native_schedule_and_unlinks_last_source(self, sync):
        self.agent.plat = AgentPlat.WINDOWS
        self.agent.version = "2.14.0"
        self.agent.save(update_fields=["plat", "version"])
        self.task.task_supported_platforms = [AgentPlat.WINDOWS]
        self.task.save(update_fields=["task_supported_platforms"])
        self.change(add_policies=[p.pk for p in self.policies])

        async def acknowledge(creates, modifies, deletes, unlinks):
            return [
                (action, agent, task, "ok")
                for action, rows in (("create", creates), ("unlink", unlinks))
                for agent, task, _ in rows
            ]

        sync.side_effect = acknowledge
        sync_scheduled_tasks()
        creates, modifies, deletes, unlinks = sync.await_args.args
        self.assertEqual(len(creates), 1)
        self.assertFalse(modifies or deletes or unlinks)
        self.assertEqual(
            creates[0][2]["schedtaskpayload"]["name"], self.task.win_task_name
        )
        self.assertEqual(
            TaskResult.objects.get(task=self.task).sync_status, TaskSyncStatus.SYNCED
        )
        self.authenticate_agent(self.agent)
        response = self.client.get(
            f"/api/v3/{self.task.pk}/{self.agent.agent_id}/taskrunner/"
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.client.force_authenticate(user=self.john)

        self.change(
            remove_agents=[self.agent.pk], remove_policies=[self.policies[0].pk]
        )
        sync.reset_mock()
        sync_scheduled_tasks()
        sync.assert_not_awaited()

        self.change(remove_policies=[self.policies[1].pk])
        sync_scheduled_tasks()
        creates, modifies, deletes, unlinks = sync.await_args.args
        self.assertFalse(creates or modifies or deletes)
        self.assertEqual(len(unlinks), 1)
        self.assertEqual(unlinks[0][1].pk, self.task.pk)
        self.task.refresh_from_db()
        self.assertEqual(
            TaskResult.objects.get(task=self.task).sync_status, TaskSyncStatus.INITIAL
        )

    def test_windows_one_off_registration_retry_verifies_the_existing_name(self):
        for trigger in (TaskType.RUN_ONCE, TaskType.ONBOARDING):
            self.task.task_type = trigger
            payload = {
                "func": "schedtask",
                "schedtaskpayload": self.task.generate_nats_task_payload(initial=True),
            }
            self.assertFalse(payload["schedtaskpayload"]["overwrite_task"])
            self.assertTrue(self.task.generate_nats_task_payload()["overwrite_task"])
            for names, expected in (
                ([self.task.win_task_name], "ok"),
                (["Other_task"], "Something went wrong"),
            ):
                send = AsyncMock(side_effect=["Something went wrong", names])
                reply = asyncio.run(self.task.send_windows_schedule(send, payload))
                self.assertEqual(reply, expected)
                self.assertEqual(send.await_args.args[0], {"func": "listschedtasks"})

    def test_deleting_owner_and_linked_device_together_keeps_definition(self):
        other = baker.make_recipe(
            "agents.online_agent", site=self.site1, plat=AgentPlat.LINUX
        )
        self.change(add_agents=[other.pk])
        type(self.agent).objects.filter(pk__in=[self.agent.pk, other.pk]).delete()
        self.task.refresh_from_db()
        self.assertIsNone(self.task.agent_id)

    def test_failing_result_of_a_removed_assignment_does_not_flag_the_site(self):
        self.task.alert_severity = AlertSeverity.ERROR
        self.task.save(update_fields=["alert_severity"])
        baker.make(
            "autotasks.TaskResult",
            agent=self.agent,
            task=self.task,
            status=TaskStatus.FAILING,
        )
        checks = {"has_failing_checks": False, "warning": False, "failing": False}
        for removed in (False, True):
            if removed:
                self.change(remove_agents=[self.agent.pk])
            data = {"error": False, "warning": False}
            _add_failing(data, type(self.agent).objects.get(pk=self.agent.pk), checks)
            self.assertEqual(data["error"], not removed)

    def test_edit_keeps_pending_deletion_and_unlinked_windows_rows(self):
        self.agent.plat = AgentPlat.WINDOWS
        self.agent.save(update_fields=["plat"])
        unlinked = baker.make_recipe(
            "agents.online_agent", site=self.site1, plat=AgentPlat.WINDOWS
        )
        TaskResult.objects.create(agent=unlinked, task=self.task)
        self.client.delete(f"/tasks/{self.task.pk}/")
        response = self.client.put(
            f"/tasks/{self.task.pk}/", {"enabled": False}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(
            dict(
                TaskResult.objects.filter(task=self.task).values_list(
                    "agent_id", "sync_status"
                )
            ),
            {
                self.agent.pk: TaskSyncStatus.PENDING_DELETION,
                unlinked.pk: TaskSyncStatus.INITIAL,
            },
        )

    def test_unshared_policy_task_needs_only_task_management(self):
        policy = self.policies[0]
        task = baker.make(
            "autotasks.AutomatedTask", policy=policy, task_type=TaskType.MANUAL
        )
        user = self.create_user_with_roles(
            ["can_list_autotasks", "can_manage_autotasks", "can_send_cmd"]
        )
        self.client.force_authenticate(user=user)
        action = {"type": "cmd", "command": "echo hi", "timeout": 30, "shell": "cmd"}
        body = {
            "name": "Policy task",
            "task_type": TaskType.MANUAL,
            "actions": [action],
        }
        response = self.client.post(
            f"/automation/policies/{policy.pk}/tasks/", body, format="json"
        )
        self.assertEqual(response.status_code, 200, response.data)
        definition = f"/tasks/{task.pk}/"
        response = self.client.put(definition, {"enabled": False}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.client.delete(definition).status_code, 200)

    def test_scoped_role_manages_a_policy_task_that_reaches_only_its_devices(self):
        policy = self.policies[0]
        # also placed on an empty site outside the role's scope
        self.site3.workstation_policy = policy
        self.site3.save()
        task = baker.make(
            "autotasks.AutomatedTask",
            policy=policy,
            actions=[{"type": "script", "env_vars": ["TOKEN=policy-fixture"]}],
        )
        user = self.create_user_with_roles(
            ["can_list_autotasks", "can_manage_autotasks"]
        )
        user.role.can_view_sites.set([self.site1])
        self.client.force_authenticate(user=user)
        definition = f"/tasks/{task.pk}/"
        response = self.client.get(definition)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn("policy-fixture", str(response.data))
        response = self.client.put(definition, {"enabled": False}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.client.delete(definition).status_code, 200)

    @patch("core.tasks._run_win_task_sync", new_callable=AsyncMock)
    def test_windows_run_once_registers_after_a_run_by_hand_before_its_time(self, sync):
        self.agent.plat = AgentPlat.WINDOWS
        self.agent.version = "2.14.0"
        self.agent.save(update_fields=["plat", "version"])
        self.task.task_type = TaskType.RUN_ONCE
        self.task.task_supported_platforms = [AgentPlat.WINDOWS]
        self.task.save(update_fields=["task_type", "task_supported_platforms"])
        sync.return_value = []
        result = TaskResult.objects.create(
            agent=self.agent, task=self.task, last_run=DUE - timedelta(days=1)
        )
        sync_scheduled_tasks()
        self.assertEqual(len(sync.await_args.args[0]), 1)

        result.last_run = DUE
        result.save(update_fields=["last_run"])
        sync.reset_mock()
        sync_scheduled_tasks()
        sync.assert_not_awaited()

    @patch("autotasks.tasks.run_win_task.delay")
    def test_run_without_device_uses_the_owner_of_a_shared_task(self, run):
        other = baker.make_recipe(
            "agents.online_agent", site=self.site1, plat=AgentPlat.LINUX
        )
        self.change(add_agents=[other.pk])
        response = self.client.post(f"/tasks/{self.task.pk}/run/", {}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        run.assert_called_once_with(pk=self.task.pk)

    def test_scoped_role_reads_a_task_linked_to_its_device(self):
        device = baker.make_recipe(
            "agents.online_agent", site=self.site3, plat=AgentPlat.LINUX
        )
        self.task.actions = [{"type": "script", "env_vars": ["TOKEN=example-secret"]}]
        self.task.save(update_fields=["actions"])
        self.change(add_agents=[device.pk])
        user = self.create_user_with_roles(
            ["can_list_autotasks", "can_manage_autotasks"]
        )
        user.role.can_view_sites.set([self.site3])
        self.client.force_authenticate(user=user)
        response = self.client.get(f"/tasks/{self.task.pk}/")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertNotIn("example-secret", str(response.data))

    @patch("core.tasks.abulk_nats_command", new_callable=AsyncMock)
    def test_runner_resolves_policies_once_per_device(self, publish):
        baker.make(
            "autotasks.AutomatedTask",
            agent=self.agent,
            task_type=TaskType.DAILY,
            task_supported_platforms=[AgentPlat.LINUX],
            run_time_date=DUE,
            daily_interval=1,
        )
        with time_machine.travel(DUE, tick=False):
            sync_scheduled_tasks()
            with patch.object(
                Policy, "_active_policies", wraps=Policy._active_policies
            ) as resolve:
                self.assertEqual(len(scheduled_task_runner()), 2)
        self.assertEqual(resolve.call_count, 1)


@override_settings(CACHES=TEST_CACHE, MESH_TOKEN_KEY=TEST_MESH_KEY)
class TestConcurrentAssignmentClaim(TransactionTestCase):
    @patch("core.tasks.abulk_nats_command", new_callable=AsyncMock)
    def test_separate_workers_contend_for_the_same_occurrence(self, publish):
        CoreSettings.objects.create()
        agent = baker.make_recipe(
            "agents.online_agent", plat=AgentPlat.LINUX, time_zone="UTC"
        )
        task = baker.make(
            "autotasks.AutomatedTask",
            agent=agent,
            task_type=TaskType.DAILY,
            run_time_date=DUE,
        )
        TaskResult.objects.create(task=task, agent=agent)
        barrier = Barrier(2)
        should_run = scheduler.should_run_daily_task

        def due(*args):
            matches = should_run(*args)
            barrier.wait(timeout=10)
            return matches

        def dispatch():
            try:
                return scheduled_task_runner()
            finally:
                connections.close_all()

        with (
            time_machine.travel(DUE, tick=False),
            patch("ulrmm.scheduler.should_run_daily_task", side_effect=due),
            ThreadPoolExecutor(max_workers=2) as workers,
        ):
            claims = list(workers.map(lambda _: dispatch(), range(2)))

        expected = [(agent.agent_id, {"func": "runtask", "taskpk": task.pk})]
        self.assertCountEqual(claims, [expected, []])
        publish.assert_awaited_once_with(items=expected)
