# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path, re_path

from . import views

# mounted under accounts/
urlpatterns = [
    path("ssoproviders/", views.GetAddSSOProviders.as_view()),
    path("ssoproviders/<int:pk>/", views.GetUpdateDeleteSSOProvider.as_view()),
    path("ssoproviders/settings/", views.GetEditSSOSettings.as_view()),
    path("ssoproviders/account/", views.DisconnectSocialAccount.as_view()),
    path("ssoproviders/token/", views.SSOTokenExchange.as_view()),
    # allauth reverses this name to build the redirect_uri sent to the IdP
    re_path(
        r"^oidc/(?P<provider_id>[^/]+)/login/callback/$",
        views.provider_callback,
        name="openid_connect_callback",
    ),
]

# mounted under _allauth/. The provider's own login/ start URL is not routed:
# a login only starts through the CSRF-protected POST below.
browser_urlpatterns = [
    path("browser/v1/config/", views.LoginConfig.as_view()),
    path("browser/v1/auth/provider/redirect/", views.StartLogin.as_view()),
]
