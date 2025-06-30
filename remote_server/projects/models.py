from django.db import models
import uuid

class Project(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    phone_number = models.CharField(max_length=20)
    amount = models.FloatField()
    project_name = models.CharField(max_length=255)
    encryption_status = models.BooleanField(default=False)
    deposit_payment_status = models.BooleanField(default=False)

    def __str__(self):
        return self.project_name