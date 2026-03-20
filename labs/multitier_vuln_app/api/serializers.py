from rest_framework import serializers
from api.models import Post, ImageAsset


class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = ["id", "title", "slug", "content", "rendered_html",
                  "cover_image", "author", "created_at"]
        read_only_fields = ["id", "rendered_html", "created_at"]


class ImageAssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = ImageAsset
        fields = ["id", "filename", "path", "width", "height", "format", "uploaded_at"]
        read_only_fields = ["id", "path", "width", "height", "format", "uploaded_at"]
