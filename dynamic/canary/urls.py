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


from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('fetch', views.fetchTrancoURLs, name='fetchTrancoURLs'),
    path('urls', views.getTrancoURLs, name="getTrancoURLs"),
    path('extension', views.getExtension, name='getExtension'),
    path('requestdata', views.requestHeaders, name='requestdata'),
    path('responsedata', views.responseHeaders, name='responsedata'),
    path('hookdata', views.hookData, name='hookData'),
    path('flush', views.flushTableData, name='flushTableData')
]
