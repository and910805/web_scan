from django.conf import settings
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView


class HealthCheckView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def get(self, request, *args, **kwargs):
        missing = []
        if not settings.SECRET_KEY or settings.SECRET_KEY == "unsafe-dev-key":
            missing.append("DJANGO_SECRET_KEY")
        if not settings.CELERY_BROKER_URL:
            missing.append("CELERY_BROKER_URL")
        if not settings.CELERY_RESULT_BACKEND:
            missing.append("CELERY_RESULT_BACKEND")
        if not settings.GOOGLE_OAUTH_CLIENT_ID:
            missing.append("GOOGLE_OAUTH_CLIENT_ID")
        if settings.ZAP_ENABLED and not settings.ZAP_API_URL:
            missing.append("ZAP_API_URL")

        return Response(
            {
                "status": "ok" if not missing else "degraded",
                "debug": settings.DEBUG,
                "missing_required_env": missing,
            }
        )
