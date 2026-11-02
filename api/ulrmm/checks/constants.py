# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Columns the agent result path never reads, deferred to keep its queries small.
# handle_check reads fail_when for event log checks, so that one stays loaded.
CHECK_DEFER = tuple("""
    created_by created_time modified_by modified_time timeout svc_display_name
    svc_policy_mode log_name event_id event_id_is_wildcard event_type event_source
    event_message search_last_days
    """.split())

CHECK_RESULT_DEFER = tuple("""
    more_info outage_history extra_details stdout stderr execution_time
    """.split())
