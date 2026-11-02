# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("channels/", views.Channels.as_view()),
    path("channels/<int:pk>/", views.ChannelDetail.as_view()),
    path("channels/<int:pk>/test/", views.TestChannel.as_view()),
    path("routes/", views.Routes.as_view()),
    path("routes/<int:pk>/", views.RouteDetail.as_view()),
    path("notifications/", views.Notifications.as_view()),
]
