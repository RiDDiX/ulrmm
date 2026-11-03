# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

from ulrmm.helpers import get_client_ip


class _ClientIPAnonThrottle(AnonRateThrottle):
    """Anonymous throttle keyed on the same client address the rest of the
    server trusts, instead of DRF's raw X-Forwarded-For handling, so a client
    cannot rotate forwarded-for values to dodge brute-force limits.
    """

    def get_ident(self, request):
        return get_client_ip(request.META) or super().get_ident(request)


class CheckCredsMinThrottle(_ClientIPAnonThrottle):
    scope = "check_creds_min"


class CheckCredsDayThrottle(_ClientIPAnonThrottle):
    scope = "check_creds_day"


class LoginMinThrottle(_ClientIPAnonThrottle):
    scope = "login_min"


class LoginDayThrottle(_ClientIPAnonThrottle):
    scope = "login_day"


class BrandingThrottle(_ClientIPAnonThrottle):
    scope = "branding"


class StepUpMinThrottle(UserRateThrottle):
    scope = "login_min"


class NetmonTestThrottle(UserRateThrottle):
    scope = "netmon_test"


class VaultRevealThrottle(UserRateThrottle):
    scope = "vault_reveal"
