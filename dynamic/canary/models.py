# Copyright (C) 2022 Shubham Agarwal
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


from django.db import models

""" Model that stores Tranco Top n(100) URLs and their sub-domains, used for our runtime analysis for extensions that operate on "<all_urls>". """
class TrancoUrlList(models.Model):
    domain = models.TextField()
    subdomains = models.JSONField()
    timestamp = models.DateTimeField(auto_now=True)

""" Models that stores all the extensions and their runtime data under analysis after scrutinizing duriong static analysis. """
class ChromeExtensions(models.Model):
    extension_id = models.CharField(max_length=256, null=False, blank=False)
    urls = models.JSONField()
    is_processed = models.BooleanField(default=False)
    extension_type = models.SmallIntegerField(default=0)
    year = models.PositiveSmallIntegerField(blank=False, null=False)
    timestamp = models.DateTimeField(auto_now=True)

class FirefoxExtensions(models.Model):
    extension_id = models.CharField(max_length=256, null=False, blank=False)
    urls = models.JSONField()
    is_processed = models.BooleanField(default=False)
    extension_type = models.SmallIntegerField(default=0)
    year = models.PositiveSmallIntegerField(blank=False, null=False)
    timestamp = models.DateTimeField(auto_now=True)

""" Models that store the header data collected from dynamic analysis for each extensions, seperately for each store. """
class ChromeHeaders(models.Model):
    extension_id = models.CharField(max_length=256, null=False, blank=False)
    request_url = models.TextField()
    request_id = models.CharField(max_length=256, null=False, blank=False, default="")
    frame_id = models.CharField(max_length=256, null=False, blank=False, default="")
    request_initiator = models.TextField(default="")
    old_headers = models.TextField()
    new_headers = models.TextField()
    request_method = models.CharField(max_length=50)
    resource_type = models.CharField(max_length=100)
    registered_domain = models.TextField()
    source = models.CharField(max_length=50, null=False, blank=False, default="")
    year = models.PositiveSmallIntegerField(blank=False, null=False)
    timestamp = models.DateTimeField(auto_now=True)

class FirefoxHeaders(models.Model):
    extension_id = models.CharField(max_length=256, null=False, blank=False)
    request_url = models.TextField()
    request_id = models.CharField(max_length=256, null=False, blank=False, default="")
    frame_id = models.CharField(max_length=256, null=False, blank=False, default="")
    request_initiator = models.TextField(default="")
    old_headers = models.TextField()
    new_headers = models.TextField()
    request_method = models.CharField(max_length=50)
    resource_type = models.CharField(max_length=100)
    registered_domain = models.TextField()
    source = models.CharField(max_length=50, null=False, blank=False, default="")
    year = models.PositiveSmallIntegerField(blank=False, null=False)
    timestamp = models.DateTimeField(auto_now=True)

""" Models which store hook success/failure log data for the extensions from respective stores. """
class ChromeHookData(models.Model):
    extension_id = models.CharField(max_length=256, null=False, blank=False)
    hook_log_type = models.CharField(max_length=20, null=False, default="")
    is_type_enabled = models.BooleanField(default=False, null=True)
    hook_target = models.CharField(max_length=10, null=True, blank=True, default="")
    year = models.PositiveSmallIntegerField(blank=False, null=False)
    timestamp = models.DateTimeField(auto_now=True)

class FirefoxHookData(models.Model):
    extension_id = models.CharField(max_length=256, null=False, blank=False)
    hook_log_type = models.CharField(max_length=20, null=False, default="")
    is_type_enabled = models.BooleanField(default=False, null=True)
    hook_target = models.CharField(max_length=10, null=True, blank=True, default="")
    year = models.PositiveSmallIntegerField(blank=False, null=False)
    timestamp = models.DateTimeField(auto_now=True)

""" Models which store results from comparitive analysis of header modifications for extensions from differnt stores seperately. """
class ChromeResults(models.Model):
    extension_id = models.CharField(max_length=256, null=False, blank=False)
    alter_type = models.CharField(max_length=20, null=True, blank=True, default="")
    url_domain = models.TextField()
    header_name = models.CharField(max_length=512, null=True, blank=True, default="")
    orig_val = models.TextField()
    orig_parsed_val = models.JSONField()
    new_val = models.TextField()
    new_parsed_val = models.JSONField()
    source = models.CharField(max_length=10, null=True, blank=True, default="")
    year = models.PositiveSmallIntegerField(blank=False, null=False)
    timestamp = models.DateTimeField(auto_now=True, null=True, blank=True)

class FirefoxResults(models.Model):
    extension_id = models.CharField(max_length=256, null=False, blank=False)
    alter_type = models.CharField(max_length=20, null=True, blank=True, default="")
    url_domain = models.TextField()
    header_name = models.CharField(max_length=512, null=True, blank=True, default="")
    orig_val = models.TextField()
    orig_parsed_val = models.JSONField()
    new_val = models.TextField()
    new_parsed_val = models.JSONField()
    source = models.CharField(max_length=10, null=True, blank=True, default="")
    year = models.PositiveSmallIntegerField(blank=False, null=False)
    timestamp = models.DateTimeField(auto_now=True, null=True, blank=True)
