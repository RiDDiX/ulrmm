# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("licenses/", views.Licenses.as_view()),
    path("licenses/<int:pk>/", views.LicenseDetail.as_view()),
    path("licenses/<int:pk>/reveal/", views.RevealLicenseKey.as_view()),
    path("summary/", views.Summary.as_view()),
]
