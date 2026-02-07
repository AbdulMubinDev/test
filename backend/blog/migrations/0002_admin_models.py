# Generated migration for admin portal models

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("blog", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="AdminSetup",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("configured", models.BooleanField(default=False)),
            ],
            options={
                "verbose_name": "Admin setup",
                "verbose_name_plural": "Admin setup",
            },
        ),
        migrations.CreateModel(
            name="AuditLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("path", models.CharField(blank=True, max_length=500)),
                ("method", models.CharField(blank=True, max_length=10)),
                ("action", models.CharField(max_length=100)),
                ("details", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("user", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "verbose_name": "Audit log",
                "verbose_name_plural": "Audit logs",
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="BannedIP",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("ip_address", models.GenericIPAddressField(unique=True)),
                ("reason", models.CharField(blank=True, max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "verbose_name": "Banned IP",
                "verbose_name_plural": "Banned IPs",
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="TrafficLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("path", models.CharField(max_length=500)),
                ("method", models.CharField(max_length=10)),
                ("status_code", models.PositiveSmallIntegerField(blank=True, null=True)),
                ("user_agent", models.CharField(blank=True, max_length=500)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "verbose_name": "Traffic log",
                "verbose_name_plural": "Traffic logs",
                "ordering": ["-created_at"],
            },
        ),
    ]
