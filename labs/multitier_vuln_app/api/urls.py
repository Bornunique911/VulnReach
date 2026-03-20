from django.urls import path
from api import views

urlpatterns = [
    path("", views.home),
    path("health/", views.health),
    path("posts/", views.posts),
    path("posts/<int:pk>/", views.post_detail),
    path("posts/import/", views.import_posts),
    path("images/upload/", views.upload_image),
    path("fetch-preview/", views.fetch_preview),
    path("auth/token/", views.auth_token),
    path("auth/verify/", views.auth_verify),
    path("content/sanitize/", views.sanitize_content),
    path("feed/parse/", views.parse_feed),
    path("posts/search/", views.search_posts),
    path("backup/export/", views.backup_export),
    path("backup/import/", views.backup_import),
]
