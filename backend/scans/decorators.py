from functools import wraps

from django.db import transaction
from rest_framework import status
from rest_framework.response import Response


def deduct_credit(cost: int = 1):
    def decorator(view_method):
        @wraps(view_method)
        def wrapped(view, request, *args, **kwargs):
            user = request.user
            if not user.is_authenticated:
                return Response({"detail": "Authentication required."}, status=status.HTTP_401_UNAUTHORIZED)
            if user.credits < cost:
                return Response({"detail": "Insufficient credits."}, status=status.HTTP_402_PAYMENT_REQUIRED)

            with transaction.atomic():
                locked_user = type(user).objects.select_for_update().get(pk=user.pk)
                if locked_user.credits < cost:
                    return Response({"detail": "Insufficient credits."}, status=status.HTTP_402_PAYMENT_REQUIRED)
                locked_user.credits -= cost
                locked_user.save(update_fields=["credits"])
                request.user = locked_user

            return view_method(view, request, *args, **kwargs)

        return wrapped

    return decorator
