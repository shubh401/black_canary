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


from django.db import (close_old_connections, connection)
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from tranco import Tranco
from datetime import date
from .models import *

import numpy as np
import tldextract
import json

def index(request):
    """ Returns Demo Homepage
    Args:
        request (HttpRequest): Navigation to Homepage/Index Page
    Returns:
        (HttpResponse): Demo Page
    """    
    indexString = """ <html><head><title> Demo </title></head><body><p>My page</p><script>alert('Test!')</script></body></html> """
    response = HttpResponse(indexString)
    response["content-security-policy"] = "default-src 'none'; script-src 'none'; child-src 'none'; object-src 'none'"
    return response

@csrf_exempt
def getTrancoURLs(request):
    """ Returns Tranco Top 100 domains and their sundomains, if available, for runtime analysis, for each crawler instance.
    Args:
        request (HttpRequest): Requests for the list of generic Top 100 URLs used for runtime analysis.
    Returns:
        (JSON): Serialized list of URLs
    """    
    urls = []
    if request != None and request.method == "GET":
        try:
            close_old_connections()
            cursor = connection.cursor()
            cursor.execute(
                """ SELECT "domain" FROM canary_trancourllist ORDER BY id LIMIT 100; """
            )
            urls = cursor.fetchall()
            urls = list(np.asarray(urls).reshape(len(urls)))
        except Exception as e:
            print("Exception Occurred: ", e)
        finally:
            return HttpResponse(json.dumps(urls))

@csrf_exempt
def fetchTrancoURLs(request):
    """ Fetches the Tranco Top n (100, by deafult) URLs for a given date from the Tranco server and stores it in the database for runtime analysis of extensions.
    Args:
        request (HttpRequest): [Request to fecth the Tranco Top n URLs for given date from the Tranco server.
    Returns:
        (HttpResponse): Operation Status - whether the Tranco URLs were successfully fetched and stored
    """    
    dateRequired = ""
    totalURLs = ""
    if request != None and request.method == 'GET':
        if 'totalurls' in request.GET:
            totalURLs = int(request.GET['totalurls'])
        else:
            totalURLs = 1000000
        if 'dateRequired' in request.GET:
            dateRequired = request.GET['dateRequired']
        else:
            dateRequired = str(date.today().year) + '-' + str(
                date.today().month) + '-' + str(date.today().day - 1)
    tranco = Tranco(cache=False)
    latestList = tranco.list(date=dateRequired)
    latestList = latestList.top(totalURLs)

    print("URLs Succesfully Fetched, Performing Database Operation Now...")
    if latestList != None and len(latestList) > 0:
        for url in latestList:
            trancoUrlObject = TrancoUrlList(domain=url,
                                              subdomains='[]')
            trancoUrlObject.save()
    return HttpResponse("Done!\n")

@csrf_exempt
def getExtension(request):
    """ Returns the extension and its URLs for dynamic analysis.
    Args:
        request (HttpRequest): Request to get extension-data to be analyzed next
    Returns:
        (tuple): Extension to be analyzed with the list of its target host
    """
    table_name = "canary_"
    extension_data = ""
    if request != None and request.method == "GET":
        try:
            if request.GET["store"] == "firefox":
                table_name += "firefoxextensions"
            elif request.GET["store"] == "chrome":
                table_name += "chromeextensions"
            else:
                return HttpResponse("Invalid store type!")
            cursor = connection.cursor()
            cursor.execute(""" START TRANSACTION; """)
            cursor.execute(
                """ SELECT "extension_id", "urls" FROM %s WHERE "year" = %s AND "is_processed" = 'f' ORDER BY "id" LIMIT 1 FOR UPDATE; """ % (table_name, str(request.GET["year"]))
            )
            extension_data = cursor.fetchall()
            if extension_data != None and len(extension_data):
                cursor.execute(
                    """ UPDATE %s SET "is_processed" = 't', "timestamp" = now() WHERE "extension_id" = \'%s\' AND "year" = %s """ % (table_name, str(extension_data[0][0]), str(request.GET["year"]))
                )
            cursor.execute(""" COMMIT; """)
        except Exception as e:
            print("Exception Occurred: ", e)
    return HttpResponse(json.dumps(extension_data))

@csrf_exempt
def flushTableData(request):
    """ Flushes all the data from all the tables/models collected so fara nd flags all the extensions as unprocessed (from both stores).
    Args:
        request (HttpRequest): Request to flush DB data.
    Returns:
        (HttpResponse): Operation Status
    """
    response = ""
    if request != None and request.method == "GET" and "year" in request.GET.keys():
        try:
            close_old_connections()
            cursor = connection.cursor()
            cursor.execute(""" START TRANSACTION; """)
            cursor.execute(""" DELETE FROM canary_chromeheaders WHERE "year" = %s; """ % str(request.GET["year"]))
            cursor.execute(""" DELETE FROM canary_firefoxheaders; """)
            cursor.execute(""" UPDATE canary_chromeextensions SET "is_processed" = 'f' WHERE "year" = %s; """ % str(request.GET["year"]))
            cursor.execute(""" UPDATE canary_firefoxextensions SET "is_processed" = 'f'; """)
            cursor.execute(""" DELETE FROM canary_chromehookdata WHERE "year" = %s; """ % str(request.GET["year"]))
            cursor.execute(""" DELETE FROM canary_firefoxhookdata; """)
            cursor.execute(""" COMMIT; """)
            response = HttpResponse("Done\n")
        except Exception as e:
            response = HttpResponse("Exception Occurred: ", e)
    response["Access-Control-Allow-Origin"] = "*"
    return response

@csrf_exempt
def requestHeaders(request):
    """ Store request headers for an extension over domains during dynamic analysis.
    Args:
        request (HttpRequest): Request with "Request Headers" intercepted during runtime analysis.
    Returns:
        (HttpResponse): Operation/Log Status
    """
    response = {} 
    try:
        try:
            request_data = json.loads(str(request.body.decode('utf-8')))
        except UnicodeEncodeError as ude:
            request_data = json.loads(str(request.body.decode('utf-16')))
        if type(request_data) == list and len(request_data) > 0:
            store = request.GET["store"]
            for item in request_data:
                request_initiator = ""
                if "initiator" in item.keys():
                    request_initiator = item["initiator"]
                extension_id = str(item["extensionId"])
                request_url = str(item["url"])
                request_id = str(item["requestId"])
                frame_id = str(item["frameId"])
                year = int(request.GET["year"])
                old_headers = ""
                if "requestHeaders" in item.keys():
                    old_headers = json.dumps(item["requestHeaders"])
                new_headers = ""
                if "newHeaders" in item.keys():
                    new_headers = json.dumps(item["newHeaders"]["requestHeaders"])
                request_method = ""
                if "method" in item.keys():
                    request_method = str(item["method"])
                resource_type = ""
                if "type" in item.keys():
                    resource_type = str(item["type"])
                registered_domain = ""
                if request_initiator == "":
                    registered_domain = tldextract.extract(
                        request_url).registered_domain
                else:
                    registered_domain = tldextract.extract(
                        request_initiator).registered_domain
                if store == "firefox":
                    headerModel = FirefoxHeaders(
                        extension_id=extension_id,
                        source="request",
                        year=year,
                        request_url=request_url,
                        request_id=request_id,
                        frame_id=frame_id,
                        request_initiator=request_initiator,
                        old_headers=old_headers,
                        new_headers=new_headers,
                        request_method=request_method,
                        resource_type=resource_type,
                        registered_domain=registered_domain)
                else:
                    headerModel = ChromeHeaders(
                        extension_id=extension_id,
                        source="request",
                        year=year,
                        request_url=request_url,
                        request_id=request_id,
                        frame_id=frame_id,
                        request_initiator=request_initiator,
                        old_headers=old_headers,
                        new_headers=new_headers,
                        request_method=request_method,
                        resource_type=resource_type,
                        registered_domain=registered_domain)
                headerModel.save()
            response = HttpResponse(
                "Hello, world. Request Header Data Submitted Successfully!"
            )
        else:
            response = HttpResponse("No Header Data Found!")
    except Exception as e:
        response = HttpResponse("Error while logging extension crawl status!", e)
    finally:
        response["Access-Control-Allow-Origin"] = "*"
        return response

@csrf_exempt
def responseHeaders(request):
    """ Store response headers for an extension over domains during dynamic analysis.
    Args:
        request (HttpRequest): Request with "Response Headers" intercepted during dynamic analysis.
    Returns:
        (HttpResponse): Operation/Log Status
    """
    response = {}
    try:
        try:
            request_data = json.loads(str(request.body.decode('utf-8')))
        except UnicodeEncodeError as ude:
            request_data = json.loads(str(request.body.decode('utf-16')))
        if type(request_data) == list and len(request_data) > 0:
            store = request.GET["store"]
            for item in request_data:
                request_initiator = ""
                if "initiator" in item.keys():
                    request_initiator = item["initiator"]
                extension_id = str(item["extensionId"])
                request_url = str(item["url"])
                request_id = str(item["requestId"])
                frame_id = str(item["frameId"])
                year = int(request.GET["year"])
                old_headers = ""
                if "responseHeaders" in item.keys():
                    old_headers = json.dumps(item["responseHeaders"])
                new_headers = ""
                if "newHeaders" in item.keys():
                    new_headers = json.dumps(item["newHeaders"]["responseHeaders"])
                request_method = ""
                if "method" in item.keys():
                    request_method = str(item["method"])
                resource_type = ""
                if "type" in item.keys():
                    resource_type = str(item["type"])
                registered_domain = ""
                if request_initiator == "":
                    registered_domain = tldextract.extract(
                        request_url).registered_domain
                else:
                    registered_domain = tldextract.extract(
                        request_initiator).registered_domain
                if store == "firefox":
                    headerModel = FirefoxHeaders(
                        extension_id=extension_id,
                        request_url=request_url,
                        request_id=request_id,
                        frame_id=frame_id,
                        request_initiator=request_initiator,
                        old_headers=old_headers,
                        new_headers=new_headers,
                        request_method=request_method,
                        resource_type=resource_type,
                        source="response",
                        year=year,
                        registered_domain=registered_domain)
                else:
                    headerModel = ChromeHeaders(
                        extension_id=extension_id,
                        request_url=request_url,
                        request_id=request_id,
                        frame_id=frame_id,
                        request_initiator=request_initiator,
                        old_headers=old_headers,
                        new_headers=new_headers,
                        request_method=request_method,
                        resource_type=resource_type,
                        source="response",
                        year=year,
                        registered_domain=registered_domain)
                headerModel.save()
            response = HttpResponse(
                "Hello, world. Request Header Data Submitted Successfully!"
            )
        else:
            response = HttpResponse("No Header Data Found!")
    except Exception as e:
        response =  HttpResponse("Error while logging extension crawl status!", e)
    finally:
        response["Access-Control-Allow-Origin"] = "*"
        return response

@csrf_exempt
def hookData(request):
    """ Stores the API Instrumentation status for each extension while dynamic analysis.
    Args:
        request (HttpRequest): Request with API trigger stages and its status data.
    Returns:
        (HttpResponse): Log Status
    """
    response = {}
    try:
        hook_data = dict(request.GET)
        if type(hook_data) is dict and len(hook_data.keys()) > 0:
            extension_id = str(hook_data["extensionId"][0])
            if "hookInjected" in hook_data.keys():
                hook_log_type = "injection"
                hook_status = bool(hook_data["hookInjected"][0])
                hook_target = str(hook_data["hookInjectionType"][0])

            elif "hookRegistered" in hook_data.keys():
                hook_log_type = "registration"
                hook_status = bool(hook_data["hookRegistered"][0])
                hook_target = str(hook_data["hookRegistrationType"][0])

            elif "hookTriggered" in hook_data.keys():
                hook_log_type = "trigger"
                hook_status = bool(hook_data["hookTriggered"][0])
                hook_target = str(hook_data["hookTriggerType"][0])
            
            if extension_id != "":
                if request.GET["store"] == "chrome":
                    hookModel = ChromeHookData(
                        extension_id=extension_id,
                        hook_log_type=hook_log_type,
                        is_type_enabled=hook_status,
                        hook_target=hook_target,
                        year = request.GET["year"]
                    )
                else:
                    hookModel = FirefoxHookData(
                        extension_id=extension_id,
                        hook_log_type=hook_log_type,
                        is_type_enabled=hook_status,
                        hook_target=hook_target,
                        year = "2022"
                    )
                hookModel.save()
                response = HttpResponse(
                    "Hello, world. Hook Log Data Submitted Successfully!"
                )
            else:
                response = HttpResponse("No Valid Data!")
    except Exception as e:
        response = HttpResponse("Error in Hook Data!", e)
    finally:
        response["Access-Control-Allow-Origin"] = "*"
        return response
