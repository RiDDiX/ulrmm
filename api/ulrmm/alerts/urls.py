# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

TEMPLATE = "templates/<int:pk>/"

urlpatterns = [
    path("", views.GetAddAlerts.as_view()),
    path("<int:pk>/", views.GetUpdateDeleteAlert.as_view()),
    path("templates/", views.GetAddAlertTemplates.as_view()),
    path(TEMPLATE, views.GetUpdateDeleteAlertTemplate.as_view()),
    path(TEMPLATE + "related/", views.RelatedAlertTemplate.as_view()),
    path("bulk/", views.BulkAlerts.as_view()),
]
