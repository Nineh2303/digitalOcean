# Generated by Django 3.2.3 on 2022-03-01 07:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cart', '0008_auto_20220110_1542'),
    ]

    operations = [
        migrations.AddField(
            model_name='item',
            name='itemKey',
            field=models.CharField(max_length=10, null=True),
        ),
    ]
