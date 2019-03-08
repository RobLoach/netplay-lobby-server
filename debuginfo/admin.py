from django.contrib import admin
from models import *

class DebugInfoAdmin(admin.ModelAdmin):
  list_display = ['id', 'ip', 'created']

  def get_queryset(self, request):
    qs = super(DebugInfoAdmin, self).get_queryset(request)

    if request.user.is_superuser:
      return qs

    qs = qs.filter(visible=True)

    if len(qs) >= 5:
      return qs[-5:]
    else:
      return qs

  def save_model(self, request, obj, form, change):
    if change:
      # discard all changes
      return

    super(DebugInfoAdmin, self).save_model(request, obj, form, change)

admin.site.register(DebugInfo, DebugInfoAdmin)
