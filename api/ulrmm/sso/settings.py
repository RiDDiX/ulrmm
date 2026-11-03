# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# allauth configuration for OpenID Connect sign-in. ulrmm/settings.py
# star-imports this module before local_settings.py, so every value here can
# be overridden there.

HEADLESS_ONLY = True
SOCIALACCOUNT_ONLY = True
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "https"
ACCOUNT_EMAIL_VERIFICATION = "none"
SOCIALACCOUNT_ADAPTER = "sso.adapter.SSOAccountAdapter"

# An IdP that reports the address of an existing user must not sign in as that
# user or link to it. Only set these to True in local_settings.py for a
# provider that alone controls every address it reports.
SOCIALACCOUNT_EMAIL_AUTHENTICATION = False
SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = False

SOCIALACCOUNT_EMAIL_VERIFICATION = "none"
SOCIALACCOUNT_PROVIDERS = {"openid_connect": {"OAUTH_PKCE_ENABLED": True}}

SESSION_COOKIE_SECURE = True
CORS_ALLOW_CREDENTIALS = True

# issuer URLs on loopback, link-local, private or metadata addresses are
# refused, on save and on every request to the IdP. True allows an IdP on the
# internal network.
SSO_ALLOW_PRIVATE_ISSUER = False
