from django.shortcuts import render
from django.utils.timezone import localtime, now
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, HttpResponseRedirect, Http404
from models import *

THROTTLE = True
THROTTLE_SECS = 120

@csrf_exempt
def add_entry(request):
  if request.method != 'POST' or \
    not request.POST.has_key('info'):
      raise Http404

  if request.META.has_key('REMOTE_ADDR'):
    existing = DebugInfo.objects.filter(ip=request.META['REMOTE_ADDR']).order_by('-created')

    if len(existing) > 0:
      t = localtime(now())

      if (t - existing[0].created).seconds < THROTTLE_SECS:
        raise Http404

  obj = DebugInfo()

  if request.META.has_key('REMOTE_ADDR'):
    obj.ip = request.META['REMOTE_ADDR']
  else:
    obj.ip = ''

  obj.info = request.POST['info']
  obj.save()

  return HttpResponse('OK')
