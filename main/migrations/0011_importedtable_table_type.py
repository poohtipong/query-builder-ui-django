# Generated by Django 5.2 on 2025-05-02 04:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0010_querylog_output_parameters_alter_querylog_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='importedtable',
            name='table_type',
            field=models.CharField(choices=[('patient', 'Patient'), ('study', 'Study'), ('study_sub', 'Study Sub')], default='study_sub', max_length=20),
        ),
    ]
