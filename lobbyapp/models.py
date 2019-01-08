from django.db import models

HOST_METHOD_UNKNOWN = 0
HOST_METHOD_MANUAL = 1
HOST_METHOD_UPNP = 2
HOST_METHOD_MITM = 3

HOST_CHOICES = (
  (HOST_METHOD_UNKNOWN, 'Unknown'),
  (HOST_METHOD_MANUAL, 'Manual'),
  (HOST_METHOD_UPNP, 'UPNP'),
  (HOST_METHOD_MITM, 'MITM'),
)

class RelayServer(models.Model):
  name = models.CharField('server name', max_length=200)
  description = models.CharField('description', max_length=200)
  address = models.CharField('address', max_length=200, help_text='specify optional port with a colon')
  enabled = models.BooleanField('enabled', default=True)
  created = models.DateTimeField('created', auto_now_add=True)
  updated = models.DateTimeField('updated', auto_now=True)

class Entry(models.Model):
  username = models.CharField('username', max_length=32)
  ip = models.CharField('IP address', max_length=45)
  port = models.PositiveIntegerField('port')
  mitm_ip = models.CharField('MITM IP address', max_length=45, blank=True)
  mitm_port = models.PositiveIntegerField('MITM Port', default=0)
  core_name = models.CharField('core name', max_length=200)
  core_version = models.CharField('core version', max_length=200)
  game_name = models.CharField('game name', max_length=200)
  game_crc = models.CharField('game CRC', max_length=200, help_text='RetroArch expects the CRC as 8-character hex, in all caps.')
  fixed = models.BooleanField('fixed', default=False)
  has_password = models.BooleanField('has password', default=False)
  has_spectate_password = models.BooleanField('has spectator password', default=False)
  host_method = models.PositiveSmallIntegerField('host method', choices=HOST_CHOICES)
  retroarch_version = models.CharField('RetroArch version', max_length=32, blank=True)
  frontend = models.CharField('Frontend identifier', max_length=32, blank=True)
  subsystem_name = models.CharField('subsystem name', max_length=200)
  country = models.CharField('country', max_length=200, blank=True)
  created = models.DateTimeField('created', auto_now_add=True)
  updated = models.DateTimeField('updated', auto_now=True)

  def __unicode__(self):
    return self.username + '@' + self.ip + ' Core: ' + self.core_name + ' ' + self.core_version + ' Game: ' + self.game_name + ' Country: ' + self.country

  class Meta:
    verbose_name_plural = 'Entries'

class LogEntry(models.Model):
  username = models.CharField('username', max_length=32)
  ip = models.CharField('IP address', max_length=45)
  port = models.PositiveIntegerField('port')
  mitm_ip = models.CharField('MITM IP address', max_length=45, blank=True)
  mitm_port = models.PositiveIntegerField('MITM Port', default=0)
  core_name = models.CharField('core name', max_length=200)
  core_version = models.CharField('core version', max_length=200)
  game_name = models.CharField('game name', max_length=200)
  game_crc = models.CharField('game CRC', max_length=200, help_text='RetroArch expects the CRC as 8-character hex, in all caps.')
  has_password = models.BooleanField('has password', default=False)
  has_spectate_password = models.BooleanField('has spectator password', default=False)
  host_method = models.PositiveSmallIntegerField('host method', choices=HOST_CHOICES)
  retroarch_version = models.CharField('RetroArch version', max_length=32, blank=True)
  frontend = models.CharField('Frontend identifier', max_length=32, blank=True)
  subsystem_name = models.CharField('subsystem name', max_length=200)
  country = models.CharField('country', max_length=200, blank=True)
  created = models.DateTimeField('created', auto_now_add=True)

  def __unicode__(self):
    return str(self.created) + ': ' + self.username + '@' + self.ip + ' Core: ' + self.core_name + ' ' + self.core_version + ' Game: ' + self.game_name + ' Country: ' + self.country

  class Meta:
    verbose_name_plural = 'Log Entries'

class GeoIP(models.Model):
  network = models.PositiveIntegerField(db_index=True)
  broadcast = models.PositiveIntegerField(db_index=True)
  country = models.CharField(max_length=2, db_index=True)
