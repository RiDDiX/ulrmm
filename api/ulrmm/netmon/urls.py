# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("devices/", views.GetAddNetworkDevices.as_view()),
    path("devices/<int:pk>/", views.GetEditDeleteNetworkDevice.as_view()),
    path("devices/<int:pk>/test/", views.TestNetworkDevice.as_view()),
]
