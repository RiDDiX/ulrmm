# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest.mock import patch

from model_bakery import baker

from ulrmm.constants import AlertSeverity, AlertType
from ulrmm.test import ULRMMTestCase

from .tasks import network_alert_email_task


@patch("alerts.tasks.sleep")
class TestNetworkSendFailure(ULRMMTestCase):
    @patch("core.models.CoreSettings.send_mail")
    def test_failed_mail_hands_the_claim_back(self, send_mail, _):
        self.setup_coresettings()
        device = baker.make(
            "netmon.NetworkDevice", name="fw", host="192.168.178.1", email_alert=True
        )
        alert = baker.make(
            "alerts.Alert",
            network_device=device,
            alert_type=AlertType.NETWORK,
            severity=AlertSeverity.ERROR,
        )
        send_mail.return_value = ("boom", False)
        self.assertEqual(network_alert_email_task(pk=alert.pk), "send failed")
        alert.refresh_from_db()
        self.assertIsNone(alert.email_sent)

        send_mail.return_value = ("ok", True)
        self.assertEqual(network_alert_email_task(pk=alert.pk), "ok")
        alert.refresh_from_db()
        self.assertIsNotNone(alert.email_sent)
