# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import routers

from . import views

router = routers.DefaultRouter()
for prefix, viewset in (
    ("agent", views.AgentViewSet),
    ("client", views.ClientViewSet),
    ("site", views.SiteViewSet),
):
    router.register(prefix, viewset, basename=prefix)

urlpatterns = router.urls
