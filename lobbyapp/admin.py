from django import forms
from django.utils.safestring import mark_safe
from django.contrib import admin
from models import *

class HTMLWidget(forms.widgets.Input):
  input_type = 'text'

  def render(self, name, value, attrs=None):
    if value is None: value = ''
    final_attrs = self.build_attrs(attrs, type=self.input_type, name=name)
    if value != '':
        # Only add the 'value' attribute if a value is non-empty.
        final_attrs['value'] = force_unicode(value)
    return mark_safe(final_attrs['value'])

class NoInput(forms.widgets.Input):
    input_type = 'text'

    def render(self, name, value, attrs=None):
        if value is None: value = ''
        final_attrs = self.build_attrs(attrs, type=self.input_type, name=name)
        if value != '':
            # Only add the 'value' attribute if a value is non-empty.
            final_attrs['value'] = force_unicode(value)
        return mark_safe(final_attrs['value'])

class EntryForm(forms.ModelForm):
  created = forms.CharField(required=False, widget=NoInput(attrs={'value':'0'}))
  updated = forms.CharField(required=False, widget=NoInput(attrs={'value':'0'}))

  def __init__(self, *args, **kwargs):
    super(EntryForm, self).__init__(*args, **kwargs)

    instance = getattr(self, 'instance', None)

    if instance and instance.id:
      """ using disabled for some reason makes the fields act as if they are blank when submitting, which raises a form validation error """
      try:
        self.fields['created'].widget.attrs['readonly'] = True
        self.fields['updated'].widget.attrs['readonly'] = True
      except KeyError:
        pass

  class Meta:
    model = Entry
    fields = '__all__'
    exclude = ()

class LogEntryForm(forms.ModelForm):
  created = forms.CharField(required=False, widget=NoInput(attrs={'value':'0'}))

  def __init__(self, *args, **kwargs):
    super(LogEntryForm, self).__init__(*args, **kwargs)

    instance = getattr(self, 'instance', None)

    if instance and instance.id:
      """ using disabled for some reason makes the fields act as if they are blank when submitting, which raises a form validation error """
      try:
        self.fields['created'].widget.attrs['readonly'] = True
      except KeyError:
        pass

  class Meta:
    model = LogEntry
    fields = '__all__'
    exclude = ()

class EntryAdmin(admin.ModelAdmin):
  form = EntryForm

  def get_form(self, request, obj=None, **kwargs):
    if obj is not None:
      form = super(EntryAdmin, self).get_form(request, obj, **kwargs)
      form.base_fields['created'].widget.attrs['value'] = obj.created
      form.base_fields['updated'].widget.attrs['value'] = obj.updated

      return super(EntryAdmin, self).get_form(request, obj, **kwargs)
    else:
      return super(EntryAdmin, self).get_form(request, obj, **kwargs)

class LogEntryAdmin(admin.ModelAdmin):
  form = LogEntryForm
  search_fields = ['username', 'ip', 'core_name', 'core_version', 'game_name', 'game_crc']

  def get_form(self, request, obj=None, **kwargs):
    if obj is not None:
      form = super(LogEntryAdmin, self).get_form(request, obj, **kwargs)
      form.base_fields['created'].widget.attrs['value'] = obj.created

      return super(LogEntryAdmin, self).get_form(request, obj, **kwargs)
    else:
      return super(LogEntryAdmin, self).get_form(request, obj, **kwargs)

  def save_model(self, request, obj, form, change):
    # ignore changes to log entries
    pass

admin.site.site_header = 'Lobby Administration'
admin.site.register(Entry, EntryAdmin)
admin.site.register(LogEntry, LogEntryAdmin)
