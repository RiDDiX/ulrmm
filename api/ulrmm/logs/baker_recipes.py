# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from itertools import cycle

from model_bakery.recipe import Recipe

from ulrmm.constants import AuditActionType, AuditObjType, PAAction, PAStatus

audit_log = Recipe("logs.AuditLog")

# actions taken on an agent: remote session, script and command runs
agent_logs = audit_log.extend(
    object_type=AuditObjType.AGENT,
    action=cycle(
        [
            AuditActionType.REMOTE_SESSION,
            AuditActionType.EXEC_SCRIPT,
            AuditActionType.EXEC_COMMAND,
        ]
    ),
)

# add/modify/view/delete spread over the object types user .. coresettings
object_logs = audit_log.extend(
    object_type=cycle(AuditObjType.values[:10]),
    action=cycle(
        [
            AuditActionType.ADD,
            AuditActionType.MODIFY,
            AuditActionType.VIEW,
            AuditActionType.DELETE,
        ]
    ),
)

login_logs = audit_log.extend(
    object_type=AuditObjType.USER,
    action=cycle([AuditActionType.FAILED_LOGIN, AuditActionType.LOGIN]),
)

pending_agentupdate_action = Recipe(
    "logs.PendingAction", action_type=PAAction.AGENT_UPDATE, status=PAStatus.PENDING
)
