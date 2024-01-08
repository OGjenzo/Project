# App/models.py
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models

class CustomUser(AbstractUser):
    # Your custom fields here

    class Meta:
        permissions = (
            ("can_change_specific_permission", "Can change specific permission"),
            # Add other custom permissions here if needed
        )

    # Specify custom related names for groups and user_permissions
    groups = models.ManyToManyField(Group, related_name="customuser_set", blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="customuser_set", blank=True)
    # Field for storing encryption key
    encryption_key = models.CharField(max_length=255, blank=True, null=True)



class Reclamation(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    encrypted_message = models.TextField()
    date_created = models.DateTimeField(auto_now_add=True)