from django.shortcuts import render, render_to_response
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.views.decorators.csrf import csrf_exempt
from django.db import connection
from django.template import RequestContext
from django.utils.timezone import localtime, now
from django.core import serializers
from datetime import timedelta
from models import *
from lobby import settings_secret
import json, socket, struct, urllib, urllib2, hashlib, hmac, os

ENTRY_TIMEOUT = 60
THROTTLE = True
THROTTLE_SECS = 5
MITM_HOST = 'lobby.libretro.com'
MITM_PORT = 55435
MITM_SOCKET_TIMEOUT = 10

def ip2int(addr):
  return struct.unpack("!I", socket.inet_aton(addr))[0]

def get_country(ip):
  country = ''

  try:
    ip_int = ip2int(ip)
    country = GeoIP.objects.filter(network__lte=ip_int, broadcast__gte=ip_int)[0].country
  except:
    pass

  return country

def handle_exception():
  info = os.sys.exc_info()

  if len(info) >= 3:
    exc_type = str(info[0])
    exc_obj = info[1]
    exc_tb = info[2]
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)

    if len(fname) > 1:
      msg = 'ERROR: ' + exc_type + ' at ' + fname[1] + ':' + str(exc_tb.tb_lineno)
      return msg

def make_digest(message, key):
  digester = hmac.new(key, message, hashlib.sha1)
  signature = digester.hexdigest()

  return signature

def send_irc_netplay_message(msg):
  try:
    data = {
      'message': msg,
      'channel': settings_secret.irc_netplay_channel,
      'sign': make_digest(msg, settings_secret.irc_netplay_message_key)
    }

    url = settings_secret.irc_netplay_message_endpoint + '?' + urllib.urlencode(data)

    request = urllib2.Request(url)

    # ignore response for now
    urllib2.urlopen(request, timeout=10)
  except Exception, e:
    msg = handle_exception()

    with open('/tmp/irc_error', 'wb') as f:
      f.write('ERROR: ' + str(e) + '\n' + msg + '\n')

def send_discord_netplay_message(msg):
  try:
    request = urllib2.Request(settings_secret.discord_netplay_message_endpoint)
    request.add_header("Authorization", settings_secret.discord_retrobot_token)
    request.add_header("User-Agent", settings_secret.discord_user_agent)

    data = {'content': msg}

    # ignore response for now
    urllib2.urlopen(request, urllib.urlencode(data), timeout=10)
  except Exception, e:
    msg = handle_exception()

    with open('/tmp/discord_error', 'wb') as f:
      f.write('ERROR: ' + str(e) + '\n' + msg + '\n')

def request_new_mitm_port(mitm_ip=MITM_HOST, mitm_port=MITM_PORT):
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(MITM_SOCKET_TIMEOUT)
    s.connect((mitm_ip, mitm_port))

    # CMD_REQ_PORT
    s.sendall('\x00\x00\x46\x49\x00\x00\x00\x00')

    data = ''

    while len(data) < 12:
      data += s.recv(12)

    s.close()

    # CMD_NEW_PORT
    if data[0:8] == '\x00\x00\x46\x4a\x00\x00\x00\x04':
      port_unpack = struct.unpack('!I', data[8:12])

      if len(port_unpack) > 0:
        port = port_unpack[0]

        return port
  except Exception, e:
    msg = handle_exception()

    f = open('/tmp/entry_mitm_error', 'wb')
    f.write(str(e) + '\n' + msg + '\n')
    f.close()

  return 0

def is_valid(entry):
  banned_usernames = [
    'sp ',
    'vagina',
    'penis',
    'archive.org'
  ]
  banned_ips = [
    '13.235.33.105',
    '15.164.165.48',
    '13.124.115.58',
    '13.209.96.155',
    '15.164.220.235',
    '15.164.217.149',
    '13.125.23.158',
    '15.164.226.219',
    '52.79.76.79',
    '52.79.227.43'
  ]
  banned_frontends = [
    'DannyBoy'
  ]
  banned_subsystem_names = [
    'LittleJuan'
  ]
  for username in banned_usernames:
    if username in entry['username']:
      return False
  for ip in banned_ips:
    if ip in entry['ip']:
      return False
  for frontend in banned_frontends:
    if frontend in entry['frontend']:
      return False
  for subsystem_name in banned_subsystem_names:
    if subsystem_name in entry['subsystem_name']:
      return False
  return True

@csrf_exempt
def add_entry(request):
  if request.method != 'POST' or \
    not request.POST.has_key('username') or \
    not request.POST.has_key('core_name') or \
    not request.POST.has_key('game_name') or \
    not request.POST.has_key('game_crc') or \
    not request.POST.has_key('core_version'):
      raise Http404

  username = request.POST['username']
  ip = None
  port = None
  update = None
  host_method = HOST_METHOD_UNKNOWN
  has_password = False
  has_spectate_password = False
  retroarch_version = ''
  frontend = ''
  subsystem_name = ''

  if request.POST.has_key('retroarch_version'):
    retroarch_version = request.POST['retroarch_version']

  if request.POST.has_key('frontend'):
    frontend = request.POST['frontend']

  if request.POST.has_key('subsystem_name'):
    subsystem_name = request.POST['subsystem_name']

  if request.POST.has_key('has_password') and int(request.POST['has_password']) == 1:
    has_password = True

  if request.POST.has_key('has_spectate_password') and int(request.POST['has_spectate_password']) == 1:
    has_spectate_password = True

  if request.POST.has_key('force_mitm') and int(request.POST['force_mitm']) == 1:
    host_method = HOST_METHOD_MITM

  if request.POST.has_key('port'):
    port = int(request.POST['port'])

  if not port:
    port = 55435

  if port <= 0 or port > 65535:
    f = open('/tmp/entry_add_error', 'wb')
    f.write('invalid port' + '\n')
    f.close()
    raise Http404

  if request.META.has_key('REMOTE_ADDR'):
    ip = request.META['REMOTE_ADDR']

  if not ip or len(ip) == 0:
    ip = '127.0.0.1'

  if len(username) == 0:
    username = ip

  if len(request.POST['core_name']) == 0 or \
    len(request.POST['game_name']) == 0 or \
    len(request.POST['game_crc']) == 0 or \
    len(request.POST['core_version']) == 0:
      f = open('/tmp/entry_add_error', 'wb')
      f.write('invalid post contents' + '\n')
      f.close()
      raise Http404

  t = localtime(now())

  delete_old_entries()

  entries = Entry.objects.filter()

  for entry in entries:
    if THROTTLE and ip != '127.0.0.1':
      if entry.ip == ip and (t - entry.updated).seconds < THROTTLE_SECS:
        # only one new/updated entry allowed per IP every X seconds
        raise Http404

    if entry.username == username and \
      entry.ip == ip and \
      entry.port == port and \
      entry.core_name == request.POST['core_name'] and \
      entry.core_version == request.POST['core_version'] and \
      entry.game_name == request.POST['game_name'] and \
      entry.game_crc == request.POST['game_crc']:
        update = entry.id
        break

  kwargs = {
    'username': username,
    'core_name': request.POST['core_name'],
    'game_name': request.POST['game_name'],
    'game_crc': request.POST['game_crc'].upper(),
    'core_version': request.POST['core_version'],
    'ip': ip,
    'port': port,
    'host_method': host_method,
    'has_password': has_password,
    'has_spectate_password': has_spectate_password,
    'retroarch_version': retroarch_version,
    'frontend' : frontend,
    'subsystem_name' : subsystem_name,
    'country': get_country(ip),
  }
  if not is_valid(kwargs):
    raise Http404

  try:
    connection.close()

    change_mitm = False
    mitm_ip = MITM_HOST
    mitm_port = MITM_PORT

    if request.POST.has_key('mitm_ip') and len(request.POST['mitm_ip']) > 0:
      mitm_ip = request.POST['mitm_ip']
      change_mitm = True

      if request.POST.has_key('mitm_port') and int(request.POST['mitm_port']) > 0:
        mitm_port = int(request.POST['mitm_port'])
      else:
        mitm_port = MITM_PORT

    if request.POST.has_key('mitm_server') and len(request.POST['mitm_server']) > 0:
      change_mitm = True

      try:
        mitm_server = RelayServer.objects.get(name=request.POST['mitm_server'], enabled=True).address.split(':')
        mitm_ip = mitm_server[0]

        if len(mitm_server) > 1:
          mitm_port = int(mitm_server[1])
        else:
          mitm_port = MITM_PORT
      except Exception, e:
        msg = handle_exception()

        f = open('/tmp/mitm_server_error', 'wb')
        f.write(str(e) + '\n' + msg + '\n')
        f.close()

        # fall back to regular server if we could not parse the desired server
        mitm_ip = MITM_HOST
        mitm_port = MITM_PORT

    if update:
      entries = Entry.objects.filter(pk=update)

      entries.update(**kwargs)

      for entry in entries:
        if entry.host_method != HOST_METHOD_MITM and host_method == HOST_METHOD_MITM and not change_mitm:
          new_mitm_port = request_new_mitm_port(mitm_ip, mitm_port)

          if new_mitm_port > 0:
            entry.mitm_ip = mitm_ip
            entry.mitm_port = new_mitm_port

        entry.save()
    else:
      if host_method == HOST_METHOD_MITM:
        new_mitm_port = request_new_mitm_port(mitm_ip, mitm_port)

        f = open('/tmp/mitm_entry_add_log', 'wb')
        f.write('using mitm address ' + mitm_ip + ':' + str(mitm_port) + ': new mitm port ' + str(new_mitm_port) + '\n')
        f.close()

        if new_mitm_port > 0:
          kwargs['mitm_ip'] = mitm_ip
          kwargs['mitm_port'] = new_mitm_port

      entry = Entry.objects.create(**kwargs)
      entry.save()

      kwargs['id'] = entry.id

      log = LogEntry.objects.create(**kwargs)
      log.save()

      if not has_password:
        irc_msg = kwargs['username'] + ' wants to play ' + kwargs['game_name'] + ' using ' + kwargs['core_name'] + '. There are currently ' + str(Entry.objects.count()) + ' active rooms.'
        disc_msg = '`' + kwargs['username'] + '` wants to play `' + kwargs['game_name'] + '` using `' + kwargs['core_name'] + '`. There are currently `' + str(Entry.objects.count()) + '` active rooms.'

        send_discord_netplay_message(disc_msg.encode('utf-8'))
        send_irc_netplay_message(irc_msg.encode('utf-8'))

    result = 'status=OK\n'

    if not update:
      for key in kwargs.keys():
        result += str(key) + '=' + str(kwargs[key]) + '\n'

    response = HttpResponse(result, content_type='text/plain')

    return response
  except Exception, e:
    msg = handle_exception()

    f = open('/tmp/entry_error', 'wb')
    f.write(str(e) + '\n' + msg + '\n')
    f.close()
    #pass

  raise Http404

def delete_old_entries():
  t = localtime(now()) - timedelta(seconds=ENTRY_TIMEOUT)
  entries = Entry.objects.filter(fixed=False, updated__lt=t)

  for entry in entries:
    entry.delete()

@csrf_exempt
def index(request):
  delete_old_entries()

  entries = Entry.objects.filter()

  return render_to_response("index.html", {
    'entries': entries
  })

@csrf_exempt
def list_entries(request):
  delete_old_entries()

  entries = Entry.objects.filter()

  if len(entries) == 0:
    data = '[]'
  else:
    data = serializers.serialize("json", entries, indent=2)

  return HttpResponse(data, content_type='text/plain')

@csrf_exempt
def get_entry(request, idx):
  entry = None

  try:
    entry = Entry.objects.get(id=int(idx))
  except Entry.DoesNotExist:
    raise Http404

  data = serializers.serialize("json", [entry,], indent=2)

  return HttpResponse(data, content_type='text/plain')
