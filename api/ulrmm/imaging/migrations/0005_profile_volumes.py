from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("imaging", "0004_imagepart_bigint_transfer_renew_until_profile_keep_last"),
    ]

    operations = [
        migrations.AddField(
            model_name="profile",
            name="volumes",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
