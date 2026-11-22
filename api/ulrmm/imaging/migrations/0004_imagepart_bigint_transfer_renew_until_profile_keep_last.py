from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("imaging", "0003_imageblock_created_at_imageblock_network_mode"),
    ]

    operations = [
        migrations.AlterField(
            model_name="imagepart",
            name="id",
            field=models.BigAutoField(primary_key=True, serialize=False),
        ),
        migrations.AddField(
            model_name="transfer",
            name="renew_until",
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name="profile",
            name="keep_last",
            field=models.PositiveSmallIntegerField(default=0),
        ),
    ]
