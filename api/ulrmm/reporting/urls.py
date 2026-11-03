# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import include, path, re_path

from . import views

PK = "<int:pk>/"

template_routes = [
    path("", views.ReportTemplates.as_view()),
    path(PK, views.GetEditDeleteReportTemplate.as_view()),
    path(PK + "run/", views.GenerateReport.as_view()),
    path(PK + "export/", views.ExportReportTemplate.as_view()),
    path(PK + "email/", views.EmailReport.as_view()),
    path("preview/", views.GenerateReportPreview.as_view()),
    path("preview/analysis/", views.GenerateReportVariableAnalysis.as_view()),
    path("import/", views.ImportReportTemplate.as_view()),
]

asset_routes = [
    path("", views.GetReportAssets.as_view()),
    path("all/", views.GetAllAssets.as_view()),
    path("rename/", views.RenameReportAsset.as_view()),
    path("newfolder/", views.CreateAssetFolder.as_view()),
    path("delete/", views.DeleteReportAssets.as_view()),
    path("upload/", views.UploadReportAsset.as_view()),
    path("download/", views.DownloadReportAsset.as_view()),
    # after the fixed routes: everything else below assets/ is a file
    path("<path:path>", views.NginxRedirect.as_view()),
]

schedule_routes = [
    path("", views.GetAddReportSchedule.as_view()),
    path(PK, views.GetEditDeleteReportSchedule.as_view()),
    path(PK + "run/", views.RunReportSchedule.as_view()),
]

history_routes = [
    path("", views.GetReportHistory.as_view()),
    path(PK, views.DeleteReportHistory.as_view()),
    path(PK + "run/", views.GenerateReportFromHistory.as_view()),
]

urlpatterns = [
    path("templates/", include(template_routes)),
    path("assets/", include(asset_routes)),
    path("htmltemplates/", views.GetAddReportHTMLTemplate.as_view()),
    path("htmltemplates/" + PK, views.GetEditDeleteReportHTMLTemplate.as_view()),
    path("dataqueries/", views.GetAddReportDataQuery.as_view()),
    path("dataqueries/" + PK, views.GetEditDeleteReportDataQuery.as_view()),
    path("queryschema/", views.QuerySchema.as_view()),
    path("schedules/", include(schedule_routes)),
    path("history/", include(history_routes)),
    path("frame/", views.ReportFrame.as_view()),
    re_path(r"^frame/(?P<token>[A-Za-z0-9_-]{43})/$", views.report_frame),
]
