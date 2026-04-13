from django.urls import path

from .views import ECPayWebhookView

urlpatterns = [
    path("ecpay/webhook/", ECPayWebhookView.as_view(), name="ecpay-webhook"),
]
