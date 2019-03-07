from django.db import models

class DebugInfo(models.Model):
  ip = models.CharField('IP address', max_length=45, db_index=True, blank=True)
  info = models.TextField('info')
  visible = models.BooleanField('visible', default=True, db_index=True)
  created = models.DateTimeField('created', auto_now_add=True)
  updated = models.DateTimeField('updated', auto_now=True)
