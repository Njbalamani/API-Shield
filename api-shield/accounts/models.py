from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = "admin", "Administrator"
        ANALYST = "analyst", "Security Analyst"
        DEVELOPER = "developer", "Developer"
        VIEWER = "viewer", "Viewer"

    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=160)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.ANALYST)
    mfa_enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username", "full_name"]

    class Meta:
        ordering = ["full_name", "email"]

    def __str__(self):
        return self.full_name or self.email

    @property
    def is_admin_role(self):
        return self.role == self.Role.ADMIN

    @property
    def is_analyst_role(self):
        return self.role in {self.Role.ADMIN, self.Role.ANALYST}

    @property
    def is_developer_role(self):
        return self.role in {self.Role.ADMIN, self.Role.DEVELOPER}


class LoginAttempt(models.Model):
    email = models.EmailField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    success = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.email} {'success' if self.success else 'failed'}"


class ApiKey(models.Model):
    name = models.CharField(max_length=120)
    user = models.ForeignKey("accounts.User", on_delete=models.CASCADE, related_name="api_keys")
    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="api_keys")
    prefix = models.CharField(max_length=16, db_index=True)
    key_hash = models.CharField(max_length=64, unique=True)
    is_active = models.BooleanField(default=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.prefix})"

    @classmethod
    def create_key(cls, *, name, user, organization):
        import secrets

        raw_key = f"apishield_{secrets.token_urlsafe(32)}"
        key = cls.objects.create(
            name=name,
            user=user,
            organization=organization,
            prefix=raw_key[:16],
            key_hash=cls.hash_key(raw_key),
        )
        return key, raw_key

    @staticmethod
    def hash_key(raw_key):
        import hashlib

        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
