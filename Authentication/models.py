from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from Core.utils import generate_random_code

class PasswordResetCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6, default=generate_random_code)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        # Check if the code is valid for 10 minutes
        return self.created_at >= timezone.now() - timedelta(minutes=10)

    def __str__(self):
        return f"{self.user.email} - {self.code}"