from django.contrib.auth import get_user_model
from rest_framework import serializers


User = get_user_model()


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "credits", "auth_provider")
        read_only_fields = fields


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ("username", "email", "password")

    def validate_email(self, value: str) -> str:
        email = value.lower().strip()
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("這個 Email 已經被使用。")
        return email

    def validate_username(self, value: str) -> str:
        username = value.strip()
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError("這個使用者名稱已經存在。")
        return username

    def create(self, validated_data):
        return User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            auth_provider=User.AuthProvider.LOCAL,
        )


class GoogleLoginSerializer(serializers.Serializer):
    credential = serializers.CharField()
