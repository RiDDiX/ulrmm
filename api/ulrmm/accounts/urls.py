# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views


def _list_and_detail(prefix, listing, detail):
    return [
        path(prefix, listing.as_view()),
        path(f"{prefix}<int:pk>/", detail.as_view()),
    ]


user_actions = views.UserActions.as_view()

urlpatterns = [
    path("users/", views.GetAddUsers.as_view()),
    path("<int:pk>/users/", views.GetUpdateDeleteUser.as_view()),
    path("users/reset/", user_actions),
    path("users/reset_totp/", user_actions),
    path("sessions/<str:pk>/", views.DeleteActiveLoginSession.as_view()),
    path(
        "users/<int:pk>/sessions/", views.GetDeleteActiveLoginSessionsPerUser.as_view()
    ),
    path("users/setup_totp/", views.TOTPSetup.as_view()),
    path("users/console_stepup/", views.ConsoleStepUp.as_view()),
    path("users/ui/", views.UserUI.as_view()),
    *_list_and_detail("roles/", views.GetAddRoles, views.GetUpdateDeleteRole),
    *_list_and_detail("apikeys/", views.GetAddAPIKeys, views.GetUpdateDeleteAPIKey),
    path("resetpw/", views.ResetPass.as_view()),
    path("reset2fa/", views.Reset2FA.as_view()),
]
