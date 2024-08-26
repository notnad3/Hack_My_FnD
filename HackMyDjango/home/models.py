from django.core.exceptions import ValidationError
from django.utils import timezone

from django.contrib.auth.models import AbstractUser
from django.db import models

class User(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, unique=True, null=False)
    password = models.CharField(max_length=100, null=False)

    class Meta:
        db_table = 'user_Django'

class Postform(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=200, null=False)
    content = models.TextField(null=False)

    # def is_valid(self):
    #     errors = {}
    #     if not self.title:
    #         errors['title'] = "Title cannot be empty."
    #     if not self.content:
    #         errors['content'] = "Content cannot be empty."
    #
    #     if errors:
    #         raise ValidationError(errors)
    #     return True

class Post(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()
    author_name = models.CharField(max_length=200)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'content_Django'