from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.crypto import get_random_string
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import GoogleLoginSerializer, RegisterSerializer, UserProfileSerializer


User = get_user_model()


def _issue_tokens(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(
            {
                "tokens": _issue_tokens(user),
                "user": UserProfileSerializer(user).data,
            },
            status=status.HTTP_201_CREATED,
        )


class MeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return Response(UserProfileSerializer(request.user).data)


class GoogleLoginView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        if not settings.GOOGLE_OAUTH_CLIENT_ID:
            return Response({"detail": "Google OAuth Client ID 尚未設定。"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        serializer = GoogleLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            token_info = id_token.verify_oauth2_token(
                serializer.validated_data["credential"],
                google_requests.Request(),
                settings.GOOGLE_OAUTH_CLIENT_ID,
            )
        except Exception:
            return Response({"detail": "Google 登入驗證失敗。"}, status=status.HTTP_400_BAD_REQUEST)

        if token_info.get("email_verified") is not True:
            return Response({"detail": "Google 帳號的 Email 尚未驗證。"}, status=status.HTTP_400_BAD_REQUEST)

        email = token_info["email"].lower().strip()
        sub = token_info["sub"]
        username_base = email.split("@", 1)[0]

        user = User.objects.filter(google_sub=sub).first() or User.objects.filter(email=email).first()
        if user is None:
            candidate = username_base
            suffix = 1
            while User.objects.filter(username=candidate).exists():
                suffix += 1
                candidate = f"{username_base}{suffix}"

            user = User.objects.create_user(
                username=candidate,
                email=email,
                password=get_random_string(32),
                auth_provider=User.AuthProvider.GOOGLE,
                google_sub=sub,
            )
        else:
            updated_fields = []
            if not user.google_sub:
                user.google_sub = sub
                updated_fields.append("google_sub")
            if user.auth_provider != User.AuthProvider.GOOGLE:
                user.auth_provider = User.AuthProvider.GOOGLE
                updated_fields.append("auth_provider")
            if user.email != email:
                user.email = email
                updated_fields.append("email")
            if updated_fields:
                user.save(update_fields=updated_fields)

        return Response(
            {
                "tokens": _issue_tokens(user),
                "user": UserProfileSerializer(user).data,
            }
        )
