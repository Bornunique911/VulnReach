from django.db import models


class Post(models.Model):
    title = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    content = models.TextField()
    rendered_html = models.TextField(blank=True)
    cover_image = models.CharField(max_length=500, blank=True)
    author = models.CharField(max_length=100, default="anonymous")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "api"


class ImageAsset(models.Model):
    filename = models.CharField(max_length=255)
    path = models.CharField(max_length=500)
    width = models.IntegerField(default=0)
    height = models.IntegerField(default=0)
    format = models.CharField(max_length=20, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "api"
