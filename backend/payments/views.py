from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView


class ECPayWebhookView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        return Response(
            {
                "status": "received",
                "message": "ECPay webhook placeholder. Add signature validation and credit top-up logic here.",
                "payload": request.data,
            },
            status=status.HTTP_202_ACCEPTED,
        )
