from django.db import migrations, models
import django.core.validators

class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [
        migrations.CreateModel(
            name="Domain",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("tenant_key", models.CharField(db_index=True, max_length=100)),
                ("site_key", models.CharField(db_index=True, max_length=100)),
                ("hostname", models.CharField(max_length=253, validators=[django.core.validators.RegexValidator(regex=r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$", message="Enter a fully qualified DNS hostname.")])),
                ("domain_type", models.CharField(default="Production", max_length=32)),
                ("description", models.TextField(blank=True)),
                ("is_active", models.BooleanField(default=True)),
                ("dns_status", models.CharField(default="Unknown", max_length=20)),
                ("ssl_status", models.CharField(default="Unknown", max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering":["hostname"]},
        ),
        migrations.AddConstraint(model_name="domain", constraint=models.UniqueConstraint(fields=("tenant_key","hostname"),name="domain_tenant_hostname_unique")),
    ]
