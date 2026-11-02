# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("", views.GetAddPackages.as_view()),
    path("<int:pk>/", views.EditDeletePackage.as_view()),
    path("<int:pk>/install/", views.InstallPackage.as_view()),
    path("installs/", views.PackageInstalls.as_view()),
    path("uploads/", views.Uploads.as_view()),
    path("uploads/<str:uid>/", views.UploadDetail.as_view()),
    path("uploads/<str:uid>/finish/", views.FinishUpload.as_view()),
    path("drivers/remove/", views.RemoveDriver.as_view()),
    path("download/<str:token>/", views.DownloadPackage.as_view()),
]
