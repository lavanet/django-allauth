# Generated by Django 5.0.1 on 2024-04-14 15:03

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("socialaccount", "0006_alter_socialaccount_extra_data"),
    ]

    operations = [
        migrations.AlterField(
            model_name="socialapp",
            name="provider",
            field=models.CharField(
                choices=[
                    ("twitter", "Twitter"),
                    ("google", "Google"),
                    ("metamask", "Metamask"),
                    ("keplr", "Keplr"),
                    ("leap", "Leap"),
                    ("near", "Near"),
                    ("trustwallet", "Trust"),
                    ("walletconnect", "Walletconnect"),
                ],
                db_index=True,
                max_length=30,
                verbose_name="provider",
            ),
        ),
        migrations.AlterField(
            model_name="socialapp",
            name="provider_id",
            field=models.CharField(
                blank=True, db_index=True, max_length=200, verbose_name="provider ID"
            ),
        ),
    ]
