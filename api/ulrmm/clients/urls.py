# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

deployments = views.AgentDeployment.as_view()

urlpatterns = [
    path("", views.GetAddClients.as_view()),
    path("<int:pk>/", views.GetUpdateDeleteClient.as_view()),
    path("deployments/", deployments),
    path("sites/", views.GetAddSites.as_view()),
    path("sites/<int:pk>/", views.GetUpdateDeleteSite.as_view()),
    path("deployments/<int:pk>/", deployments),
    path("<str:uid>/deploy/", views.GenerateAgent.as_view()),
]
