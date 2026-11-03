# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("layout/", views.Layout.as_view()),
    path("widgets/<str:kind>/", views.WidgetData.as_view()),
]
