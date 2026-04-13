from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    class AuthProvider(models.TextChoices):
        LOCAL = "local", "Local"
        GOOGLE = "google", "Google"

    email = models.EmailField(unique=True)
    credits = models.PositiveIntegerField(default=settings.DEFAULT_USER_CREDITS)
    auth_provider = models.CharField(max_length=16, choices=AuthProvider.choices, default=AuthProvider.LOCAL)
    google_sub = models.CharField(max_length=255, blank=True, unique=True, null=True)

    def has_scan_credits(self, amount: int = 1) -> bool:
        return self.credits >= amount
