# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("scans/", views.GetAddScans.as_view()),
    path("scans/<int:pk>/", views.GetScan.as_view()),
    path("devices/", views.GetDevices.as_view()),
    path("devices/<int:pk>/ignore/", views.IgnoreDevice.as_view()),
    path("devices/<int:pk>/netmon/", views.AddToNetmon.as_view()),
    path("networks/", views.GetNetworks.as_view()),
]
