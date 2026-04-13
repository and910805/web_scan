from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    credits = models.PositiveIntegerField(default=settings.DEFAULT_USER_CREDITS)

    def has_scan_credits(self, amount: int = 1) -> bool:
        return self.credits >= amount
