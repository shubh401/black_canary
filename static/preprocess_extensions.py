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


""" 
    We start our analysis by statitically analyzing all the extensions with this script. We perform the following operations here:
        1. Extract the extension package.
        2. Checks the permissions in the manifest and discard all those extensions that does not have header-modifiying privileges, does not have any background scripts or are not exetnsions by definition.
        3. Check and, if necessary, alter the CSP definition defined by the extension to allow header collection.
        4. Parse the background scripts and inject hooks.
        5. Extract the target hosts from the manifest and from target APIs within code.
            - Whenever necessary, inject test domain to the host permissions of the extension.
        6. Store the instrumented extension on the disk and clean auxillary files.
"""


from psycopg2.extras import execute_values
from collections import defaultdict
from jsoncomment import JsonComment
from tldextract import tldextract
from datetime import datetime
from bs4 import BeautifulSoup
from zipfile import ZipFile
from tqdm import tqdm

import multiprocessing as mp
import subprocess
import traceback
import jstyleson
import psycopg2
import argparse
import logging
import shutil
import jsmin
import json
import copy
import sys
import ast
import os

CHROME_EXTENSION_DIR = "./chrome_ext/"
FIREFOX_EXTENSION_DIR = "./firefox_ext/"
CRX_INSTRUMENTATED_HOOKS = "./static/crx_instrumented_hooks.js"
XPI_INSTRUMENTED_HOOKS = "./static/xpi_instrumented_hooks.js"

API_PERMISSIONS = json.loads(open("./static/api_permissions.json", "r").read())

DB_HOST = os.environ.get("SQL_HOST", "localhost")
DB_NAME = os.environ.get("SQL_DATABASE", "extension_headers")
DB_USER = os.environ.get("SQL_USER", "black_canary")
DB_PASS = os.environ.get("SQL_PASSWORD", "130e9548318bd85ac30c6b17e93efedc")

""" WORKERS, EXTENSION_TYPE, DATASET_YEAR values hard-coded as per the extensions available for demonstrative purposes only. 
    Should be changed or optionally passed as an argument depending upon target extension and dataset for analysis. 
"""
WORKERS = 1
EXTENSION_TYPE = "firefox"
DATASET_YEAR = "2022"

""" These domains below are controlled by us and serves all security headers and on all paths and resources.
    The values set are  only for demonstrative purposes. We instead use our own domains here. """
PROXY = "*://www.example.org/"
FILE_PATH_SUBSTITUTE = "*://www.example.org/path/files/"

class StaticAnalyzer:
    def __init__(self, extension_id, extension_type, year):
        """ Instantiates analytical environment for the given extensions used thoroughout its analysis.
        Args:
            extension_id (str): extension_id
            ext_type (str): chrome/firefox
            year (str): 2020/2021/2022
        """
        self.extension_id = extension_id
        self.source_type = extension_type
        if self.source_type == 'chrome':
            self.source_dir = CHROME_EXTENSION_DIR
        elif self.source_type == 'firefox':
            self.source_dir = FIREFOX_EXTENSION_DIR
        else:
            print("Unaccepted extension type!")
            return
        self.source_year = year
        self.unzip_target = f"./unzipped_ext_{EXTENSION_TYPE}_{DATASET_YEAR}/"
        self.instrumented_dir = f"./instrumented_ext_{EXTENSION_TYPE}_{DATASET_YEAR}/"
        self.has_activeTab = False
        self.host_modified = False
   
    def extract_crx(self):
        """Extracts the raw Chrome extension package downloaded from the store and return its status.
        Returns:
            (Bool): Whether or not the extension was extracted successfully.
        """
        try:
            if os.path.exists(self.source_dir + self.extension_id):
                unzip_process = subprocess.Popen(["node", "./static/unpack_crx.js", self.source_dir + self.extension_id, self.unzip_target + self.extension_id[:-4]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                unzip_output, unzip_error = unzip_process.stdout.read().decode(), unzip_process.stderr.read().decode()
                if unzip_output == "Error!":
                    logging.error("Error while unzipping crx: " + self.extension_id)
                    return False
                else:
                    return True
            else:
                logging.warn("Error!: Package not found for extension: " + self.extension_id)
                return False
        except:
            logging.error("Error while extracting package for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
            return False
        
    def extract_xpi(self):
        """Extracts the raw Firefox extension package downloaded from the store and return its status.
        Returns:
            (Bool): Whether or not the extension was extracted successfully.
        """
        try:
            if os.path.exists(self.source_dir + self.extension_id):
                with ZipFile(self.source_dir + self.extension_id, 'r') as zip_file:
                    os.mkdir(self.unzip_target + self.extension_id[:-4])
                    zip_file.extractall(self.unzip_target + self.extension_id[:-4] + "/")
                return True
            else:
                logging.warn("Error!: Package not found for extension: " + self.extension_id)
                return False
        except:
            logging.error("Error while extracting package for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
            return False
   
    def extract_package(self):
        """ Extracts the raw extension package downloaded from the store and return its status.
        Returns:
            (Bool): Whether or not the extension was extracted successfully.
        """
        if self.source_type == 'chrome': return self.extract_crx()
        else: return self.extract_xpi()

    def get_manifest(self, manifest_path):
        """ Parses the manifest data (using multiple parsing libraries for error-handling among firefox extensions).
        Args:
            manifest_path (str): The absolute path of the manifest for the extension.
        Returns:
            manifest_data (dict): Parsed manifest data.
        """
        manifest_data = None
        try:
            if not os.path.exists(manifest_path):
                logging.warn("Serious issues in manifest for extension: " + self.extension_id)
                return None
            try:
                manifest = open(manifest_path, "r", encoding='utf-8-sig').read()
            except:
                manifest = open(manifest_path, "rb").read()
            if manifest is not None and manifest != "":
                try:
                    manifest_data = json.loads(manifest)
                except:
                    try:
                        manifest_data = ast.literal_eval(manifest)
                    except:
                        try:
                            json_comment = JsonComment()
                            manifest_data = json_comment.loads(manifest)
                        except:
                            try:
                                manifest_data= jstyleson.loads(manifest)
                            except:
                                try:
                                    minified = jsmin(manifest)
                                    manifest_data = json.loads(minified)
                                except:
                                    try:
                                        manifest = open(manifest_path, "r", encoding='utf-8-sig', errors='ignore').read()
                                        manifest_data = json.loads(manifest)
                                    except:
                                        logging.warn("Serious issues in manifest for extension: " + self.extension_id)
                                        return None
            return manifest_data
        except:
            logging.error("Error while parsing the manifest for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
            return None

    def has_permissions(self, manifest_content):
        """ Parses the manifest of the extension to detect whetehr or not the extension has the permissions to modify headers.
            Further, if the permissions are optional, this is shifted to the default permissions category for dynamic analysis. 
        Args:
            manifest_content (dict): manifest_content
        Returns:
            (Bool): Whether the extension has sufficient privilges to modify headers or not.
        """
        try:
            preliminary_check = [manifest_content, "manifest_version" in manifest_content.keys(), manifest_content["manifest_version"] == 2]
            if all(preliminary_check):
                if "permissions" in manifest_content.keys():
                    permissions = manifest_content["permissions"]
                    if "webRequest" in permissions and "webRequestBlocking" in permissions:
                        return True
                if "optional_permissions" in manifest_content.keys():
                    optional_permissions = manifest_content["optional_permissions"]
                    if "webRequest" in optional_permissions and "webRequestBlocking" in optional_permissions:
                        manifest_content["optional_permissions"].remove("webRequest")
                        manifest_content["optional_permissions"].remove("webRequestBlocking")
                        manifest_content["permissions"].extend(["webRequest", "webRequestBlocking"])
                        
                        if not len(manifest_content["optional_permissions"]):
                            del manifest_content["optional_permissions"]
                        return True
            return False
        except:
            logging.error("Error while checking for relevant permissions for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))

    def get_background_scripts(self, manifest_content):
        """ Extracts the background script or page definitions from the manifest.
        Args:
            manifest_content (dict): manifest_content
        Returns:
            (List): The background scripts/pages as in the manifest of the extension.
        """
        bg_scripts = []
        try:
            if manifest_content:
                if "background" in manifest_content.keys():
                    """ It only checks for the valid data structures used to define the background scripts, as per the store guidelines. """
                    if type(manifest_content["background"]) is str:
                        bg_scripts.extend(manifest_content["background"])
                        return bg_scripts
                    if "scripts" in manifest_content["background"].keys():
                        if type(manifest_content["background"]["scripts"]) is list:
                            bg_scripts.extend(
                                manifest_content["background"]["scripts"])
                        elif type(manifest_content["background"]["scripts"]) is str:
                            bg_scripts.append(
                                manifest_content["background"]["scripts"])
                    if "page" in manifest_content["background"].keys():
                        if type(manifest_content["background"]["page"]) is list:
                            bg_scripts.extend(
                                manifest_content["background"]["page"])
                        elif type(manifest_content["background"]["page"]) is str:
                            bg_scripts.append(
                                manifest_content["background"]["page"])
        except:
            logging.error("Error while extracting background scripts from the manifest for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        finally:
            return bg_scripts

    def copy_dir(self, source, target):
        """ Copies the unzipped directory to a separate folder for instrumentation.
        Args:
            source (str): Source of the directory to be copied.
            target (str): Target of the directory to be copied.
        """
        try:
            shutil.copytree(source, target)
            if self.source_type == 'chrome':
                shutil.copy2(CRX_INSTRUMENTATED_HOOKS, target + "/instrumented_hooks.js")
            else:
                shutil.copy2(XPI_INSTRUMENTED_HOOKS, target + "/instrumented_hooks.js")
        except:
            logging.error("Error while copying directory for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))

    def list_of_files(self):
        """ Enumerates all the filenames with full path for a given extension directory.
        Args:
            directory_path (str): The extension directory to enumerate files.
        Returns:
            (List): The list of enumerated files.
        """
        self.file_list = []
        try:
            for root, dir_names, file_names in os.walk(self.instrumented_dir + self.extension_id):
                for file in file_names:
                    self.file_list.append(os.path.join(root, file))
        except:
            logging.error("Error while enumerating all the files for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))

    def absolute_file_path_from_dir(self, extension, file):
        """ Resolves the absolute path for each background script declared in the manifest or within the background page.
        Args:
            extension (str): The extension Id or absolute path of the Background Page as specified in the manifest.
            file (str): The background script as specified in the manifest or in as ``script-src`` in the background page.
        Returns:
            absolute_path (str): The absolute path of the background script.
        """
        absolute_path = ""
        extension_name = extension
        try:
            if file[0] == '/':
                extension_name = extension_name.split("/", 1)[0]
                file_name = file[1:]
            elif file.startswith("../"):
                while (file.startswith("../")):
                    if "/" in extension_name:
                        extension_name = extension_name.rsplit("/", 1)[0]
                    file = file[3:]
                file_name = file
            elif file.startswith("./"):
                if "/" in extension_name:
                    extension_name = extension_name.rsplit("/", 1)[0]
                file_name = file[2:]
            else:
                file_name = file
            for file_path in self.file_list:
                if os.path.abspath(os.path.join(self.instrumented_dir + extension_name, file_name)).lower() == os.path.abspath(file_path.lower()):
                    absolute_path = file_path
                    break
            if absolute_path == "":
                if file[0] == '/':
                    file_name = file[1:]
                    extension_name = extension
                elif file.startswith("./"):
                    file_name = file[2:]
                    extension_name = extension
                for file_path in self.file_list:
                    if os.path.join(self.instrumented_dir + extension_name, file_name).lower() == file_path.lower():
                        absolute_path = file_path
                        break
        except:
            logging.error("Error while resolving absolute path for script for: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        finally:
            return absolute_path

    def script_src_from_html(self, html_path):
        """ Extracts all the scripts included in the given background page.
        Args:
            html_path (str): The absolute path of the background page.
        Returns:
            (List): The list of all the background scripts in the given background page.
        """
        is_modified = False
        script_srcs = []
        try:
            html_data = open(html_path, "r").read()
            if html_path is not None and html_path != "":
                parsed_html = BeautifulSoup(html_data, 'html.parser')
                scripts = parsed_html.find_all('script')
                for link in scripts:
                    if 'src' in link.attrs:
                        """ If the included scripts contain hashes, the attributes are removed to allow our modifications. """
                        script_srcs.append(link['src'])
                        if 'integrity' in link.attrs:
                            del link['integrity']
                            is_modified = True
                if is_modified:
                    with open(html_path, 'wb') as fh:
                        fh.write(parsed_html.prettify('utf-8'))
        except:
            logging.error("Error while extracting scripts paths from the background page for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        finally:
            return script_srcs

    def absolute_path_of_scripts(self, bg_scripts):
        """ Resolves the absolute path for each background script declared in the manifest or within the background page.
        Args:
            bg_scripts (list): list fo all the background scripts/pages from the manifest.
        Returns:
            (List): List of all the valid background script which were instrumented.
        """
        scripts_absolute_path = []
        try:
            self.list_of_files()
            for script in bg_scripts:
                """ Remove unwanted characters appended at the end. """
                if ".js#" in script or ".htm#" in script or ".html#" in script:
                    script = script.rsplit("#", 1)[0]
                if ".js?" in script or ".htm?" in script or ".html?" in script:
                    script = script.split("?", 1)[0]
                    
                """ Skip jquery libraries. """
                if (not script.startswith("jquery")) and script.endswith("js"):
                    script_path = self.absolute_file_path_from_dir(self.extension_id, script)
                    if script_path is not None and script_path != "" and not script.startswith("jquery"):
                        scripts_absolute_path.append(script_path)
                elif script.endswith("html") or script.endswith("htm"):
                    """ For scripts included within the background page, as declared in the manifest. """
                    html_path = self.absolute_file_path_from_dir(self.extension_id, script)
                    html_script_src = self.script_src_from_html(html_path)
                    if html_script_src is not None and len(html_script_src) > 0:
                        if "/" in script:
                            html_path_dir = "/" + script.rsplit("/", 1)[0]
                        else:
                            html_path_dir = "/"
                        for script_src in html_script_src:
                            """ Similar steps as for the scripts directly included above."""
                            if ".js#" in script_src or ".htm#" in script_src or ".html#" in script_src:
                                script_src = script_src.rsplit("#", 1)[0]
                            if ".js?" in script_src or ".htm?" in script_src or ".html?" in script_src:
                                script_src = script_src.split("?", 1)[0]
                            if (not (script_src.startswith("jquery") or script_src.startswith("http"))) and script_src.endswith("js"):
                                script_src_path = self.absolute_file_path_from_dir(self.extension_id + html_path_dir, script_src)
                                if script_src_path is not None and script_src_path != "" and not script.startswith("jquery"):
                                    scripts_absolute_path.append(script_src_path)
            if len(scripts_absolute_path) == 0:
                """ If there is no background script declared or found in the extension directory. """
                shutil.rmtree(self.instrumented_dir + self.extension_id)
        except:
            logging.error("Error while instrumenting extension:" + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        finally:
            return scripts_absolute_path

    def extract_inline_hosts(self, script_absolute_path):
        """ Extracts the host permissions from the given script if it contains any of the target APIs and have literal values passed as second argument.
            This is done by forming the AST of the given script which does not included commented code.
            It then processes them into appropriate URLs by resolving the wildcards.
        Args:
            script_absolute_path (str): the absolute path of the given script to be inspected for host permissions.
        Returns:
            (List): all the hosts extracted from the code after preprocessing and resolving them into appropriate URLs.
        """
        processed_hosts = []
        try:
            for script_path in script_absolute_path:
                script_path = script_path.replace(self.instrumented_dir, self.unzip_target)
                extractor_process = subprocess.Popen(["node", "./static/url_extractor.js", script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                extractor_output, extractor_error = extractor_process.stdout.read().decode().strip(), extractor_process.stderr.read().decode().strip()
                if extractor_output != "":
                    extracted_urls = json.loads(extractor_output) or []
                    api_processed_urls = self.preprocess_urls(extracted_urls) or {}
                    if len(api_processed_urls.keys()):
                        processed_hosts.extend(list(api_processed_urls.values()))
        except:
            logging.error("Error while extracting hosts from the code for extension: " + self.extension_id)
        finally:
            return list(set(processed_hosts))

    def rewrite_inline_hosts(self, script_absolute_path):
        """ Rewrites the host permissions from the given script if it contains any of the target APIs and have literal values passed as second argument.
            This is done by forming the AST of the given script which does not included commented code.
            It then rewrites them into <all_urls> to allow header-modification on test domain.
        Args:
            script_absolute_path (str): the absolute path of the given script to be inspected for host permissions.
        """
        processed_hosts = []
        modified_hosts = defaultdict(lambda: defaultdict(str))
        try:
            for script_path in script_absolute_path:
                script_path = script_path.replace(self.unzip_target, self.instrumented_dir)
                script_path = script_path.replace(self.extension_id, self.extension_id + "_2")
                subprocess.Popen(["node", "./static/url_injector.js", script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except:
            logging.error("Error while rewriting hosts within the code for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        finally:
            return modified_hosts, list(set(processed_hosts))
    
    def manifest_host_permissions(self, manifest_content):
        """ Extracts all the privileges and filters out the API-related privilges to get the hosts.
        Args:
            manifest_content (dict): manifest_content
        Returns:
            (List): All the hosts-related permissions extracted from the manifest.
        """
        host_permissions = []
        total_permissions  = []
        try:
            if manifest_content:
                if "permissions" in manifest_content.keys() and type(manifest_content["permissions"]) is list:
                    total_permissions.extend(manifest_content["permissions"])
                if "optional_permissions" in manifest_content.keys() and type(manifest_content["optional_permissions"]) is list:
                    total_permissions.extend(manifest_content["optional_permissions"])
                if True in (perm in total_permissions for perm in ["activeTab", "ActiveTab", "activeTab>", "active_tab", "activeTabs"]):
                    self.has_activeTab = True
                if type(total_permissions) == list:
                    host_permissions = list(set(total_permissions) - set(API_PERMISSIONS))
                
                """ If there is no host permission in the manifest, we fall back to <all_urls>, as it could also target "topSites" which could be known. """
                if not len(host_permissions) or self.has_activeTab:
                    if "<all_urls>" not in host_permissions: host_permissions.append("<all_urls>")
                    if "<all_urls>" not in manifest_content["permissions"]: manifest_content["permissions"].insert(0, "<all_urls>")
        except:
            logging.error("Error while extracting host permissions from manifest for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        finally:
            return host_permissions

    def process_scheme(self, url):
        """ Processes the scheme of the URL to remove wildcards.
        Args:
            url (str): the extracted url
        Returns:
            (list): the original url with resolved scheme.
        """
        try:
            if url.startswith('file') or url.startswith('ftp') or url.startswith('urn'):
                return None
            if url.startswith('http://') or url.startswith('https://') or url.startswith("*://"):
                scheme, host = url.split('://', 1)
                return [scheme, host]
            else:
                return None
        except:
            logging.error("Error while processing URL scheme for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
            return None

    def process_host(self, url):
        """ Processes the host of the URL to remove wildcards.
        Args:
            url (str): the extracted url
        Returns:
            (list): the resolved host and the remaining path.
        """
        host, path, extracted_host = None, None, None
        try:
            if "/" in url:
                host, path = url.split("/", 1)
            else:
                host = url
            try:
                extracted_host = tldextract.extract(host)
            except:
                print("Error while extracting host for:", host)
            return extracted_host, path
        except:
            logging.error("Error while processing URL host for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
            return None

    def process_path(self, path):
        """ Processes the path of the URL to remove wildcards.
        Args:
            url (str): the extracted url
        Returns:
            (str): the resolved path.
        """
        try:
            if path in ["", "*", None]:
                path = ""
            else:
                while path.startswith("*/"):
                    path = path.split("*/", 1)[1]
                if path.startswith("*"):
                    path = path.split("*", 1)[1]    
                if path.endswith("*"):
                    path = path.split("*")[0]
                if path.endswith("*/"):
                    path = path.split("*/")[0]
                if "/*/" in path:
                    while "/*/" in path:
                        path = path.replace("/*/", "/")
            return path
        except:
            logging.error("Error while processing URL path for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
            return None

    def combine_url_components(self, scheme, host, path):
        """ Combines the different components of the URLs processed by the analyzed to remove wildcards.
        Args:
            scheme (str): The resolved scheme
            host (str): The resolved host
            path (str): The resolved path
        Returns:
            (str): combined url string for the resolves components of the extracted URLs.
        """
        processed_url, domain = "", ""
        try:
            if scheme in ["", "*"] and host.subdomain == "" and host.domain == '*' and path in [None, "", "*", "/*"]:
                return "<all_urls>"
            if scheme == '*':
                scheme = "http"
            if host.subdomain in ["*", ""] and host.domain != "*":
                if host.domain.lower() == 'whatsapp':
                    domain = "web." + host.domain + "."
                else:
                    domain = "www." + host.domain + "."
                if host.suffix != "":
                    domain += host.suffix
                else:
                    domain += "com"
            elif host.subdomain == "" and host.domain == "*":
                domain = FILE_PATH_SUBSTITUTE[4:-1]
            elif host.subdomain != "" and host.domain != "":
                if host.subdomain.startswith('*.'):
                    domain = host.subdomain[2:] + "." + host.domain + "."
                else:
                    domain = host.subdomain + "." + host.domain + "."
                if host.suffix != "":
                    domain += host.suffix
                else:
                    domain += "com"
            if path not in [None, "", "*", "/*"]:
                if path.startswith("."):
                    path = "/test" + path
                else:
                    path = "/" + path
            else:
                path = "/"
            processed_url = scheme + "://" + domain + path
            return processed_url
        except:
            logging.error("Error while combining URL components for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
            return processed_url
        
    def preprocess_urls(self, hosts):
        """ Processes each of the extracted URLs from the mainfest or the code to remove wildcards and resolve them into appropriate hosts.
        Args:
            hosts (List): The list of urls extracted from the manifest or from the code.
        Returns:
            (dict): A collection of originally extracted urls along with their respective processed/resolved forms.
        """
        extracted_urls = defaultdict(str)
        try:
            for url in hosts:
                if type(url) is str and url not in [
                    "BinaryExpression", "MemberExpression", "CallExpression",
                    "LogicalExpression", "Identifier", "app", "dns"
                ]:
                    if url.startswith("file://") or url.startswith("ws:") or url.startswith("wss:") \
                            or url.startswith("chrome://favicon") or url.startswith("chrome-extension:") \
                            or "127.0.0.1" in url or "localhost" in url:
                        continue
                    if url in [
                            "*://*/", "*://*/*", "*://*/*/", "*://*/*/*",
                            "*://*/*/*/*", "http://*/*/", "https://*/*/",
                            "http://*/*", "https://*/*", "http://*/", "https://*/",
                            "<all_urls>"
                    ]:
                        extracted_urls[url] = "<all_urls>"
                    else:
                        scheme, host, path, extracted_url = "" , "", "", ""
                        scheme = self.process_scheme(url)
                        if scheme is not None:
                            host = self.process_host(scheme[1])
                            if host is not None:
                                path = self.process_path(host[1])
                                if scheme[0] and host[0] and path is not None:
                                    extracted_url = self.combine_url_components(scheme[0], host[0], path)
                                    extracted_urls[url] = extracted_url
        except:
            logging.error("Error while preprocessing URLs for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        finally:
            return extracted_urls

    def inject_hook(self, script_path):
        """ Injects the instrumented hook to the given path of the script.
        Args:
            script_path (str): The absolute path of the script to be rewritten.
        """
        try:
            hook_path = self.instrumented_dir + self.extension_id + '/instrumented_hooks.js'
            hook_data = open(hook_path, 'r').read()
            hook_data = hook_data.replace("my_extension_id", self.extension_id)
            hook_data = hook_data.replace("dataset_year_of_ext", str(self.source_year))

            """ Removes all non-ascii characters here and the use of 'use-strict' that may interfere with the hooks. """
            script_data = open(script_path, 'r', errors='ignore').read()
            script_data = script_data.replace("use strict", '')
            script_data = script_data.encode('ascii', errors='ignore').decode()

            with open(script_path, "w") as fh:
                fh.write(hook_data)
                fh.write(script_data)
        except:
            logging.error("Error while injecting hook for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))

    def configure_csp(self, manifest_content):
        """ Checks for the CSP definition in the manifest and further parses the policy and inject the address of our local server to whitelist them in order to collect headers.
        Args:
            manifest_content (dict): manifest_content
        Returns:
            manifest_content (dict): The manifest data after CSP-based modifications, if any.
        """
        try:
            if manifest_content:
                if "content_security_policy" in manifest_content.keys():
                    csp_data = manifest_content["content_security_policy"]
                    parser_process = subprocess.Popen(["node", "./static/csp_parser.js", csp_data], stdout=subprocess.PIPE)
                    parser_output = parser_process.stdout.read()
                    modified_csp = parser_output.decode().strip()
                    if modified_csp is not None and modified_csp != "":
                        manifest_content["content_security_policy"] = modified_csp
                    else:
                        del manifest_content["content_security_policy"]
                if "sandbox" in manifest_content.keys() and "content_security_policy" in manifest_content["sandbox"]:
                    del manifest_content["sandbox"]["content_security_policy"]
        except:
            logging.error("Error while configuring CSP for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        finally:
            return manifest_content

    def check_host_injection(self, manifest_processed_urls, manifest_content, processed_hosts):
        """_summary_
        Args:
            manifest_processed_urls (list): The host permissions as specified in the ``permissions`` section of the manifest.
            manifest_content (dict): The manifest data of the extension.
            processed_hosts (list): The normalized hosts from the manifest.
        """        
        try:
            """ Check whether the test domain needs to be injected for extensions that operate only on 1) activeTab or b) specific hosts that are unreachable or unresolvable."""
            if "<all_urls>" not in manifest_processed_urls or not len(manifest_processed_urls):
                """ If the extension operate only on specific urls, on topSites, or on activeTab. """
                self.host_modified = True
            elif processed_hosts and  "<all_urls>" not in processed_hosts:
                """ If the extension has specific urls defined within their API. """
                self.host_modified = True
            
            """ If the hosts in the API could not be covered with the host permission in the manifest, add them in the manifest to trigger the API at runtime. """
            if "<all_urls>" not in manifest_processed_urls:
                for host in processed_hosts:
                    if host not in manifest_content["permissions"] and host != "<all_urls>":
                        manifest_content["permissions"].append(host)
        except:
            logging.error("Error while checking or injecting proxy hosts for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))

    def store_extension_hosts(self, hosts):
        """ Stores the extracted hosts for each extension later used for dynamic analysis.
        Args:
            hosts (list): List of hosts extracted from the manifest and/or code that the extensions opeartes on 
        """
        params = []
        try:
            if "<all_urls>" in hosts:
                params = [(self.extension_id, json.dumps(hosts), False, 0, self.source_year, datetime.now()),]
            else:
                params = [(self.extension_id + "_2", json.dumps([PROXY, FILE_PATH_SUBSTITUTE]), False, 1, self.source_year, datetime.now())]
            insert_query = "INSERT INTO canary_" + self.source_type + "extensions (extension_id, urls, is_processed, extension_type, year, timestamp) VALUES %s;"
            connection = psycopg2.connect(host=DB_HOST,
                                 database=DB_NAME,
                                 user=DB_USER,
                                 password=DB_PASS)
            cursor = connection.cursor()
            execute_values(cursor, insert_query, params)
            connection.commit()
            connection.close()
        except Exception as e:
            logging.error("Error while storing extracted hosts for extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))

    def start_processing(self):
        """ This is the starting point for the static analysis for each extension. It performs the following steps:
                1. Parses the manifest and detects relevant permissions to modify headers.
                2. Gathers all the associated background scripts for the extension.
                3. Instrument these background scripts by inject the hooks.
                4. Extract the inline host from the code as well as from the manifest and process them.
                5. Store the data and the instrumented extensions for dynamic analysis.  
        """
        try:
            """ Extract the extension package """
            if self.extract_package():
                if self.extension_id[-4] == '.':
                    self.extension_id = self.extension_id[:-4]
                
                """ Read the Manifest """
                manifest_content = self.get_manifest(self.unzip_target + self.extension_id + "/manifest.json")
                if manifest_content:
                    original_manifest = copy.deepcopy(manifest_content)
                    bg_scripts = None
                    
                    """ Checks for the relevant permissions """
                    if self.has_permissions(manifest_content):
                        """ Fetch background scripts declared in the manifest """
                        bg_scripts = self.get_background_scripts(manifest_content)
                        
                    if bg_scripts and len(bg_scripts):
                        """ Copy the unzipped directory to a separate folder for instrumentation """
                        self.copy_dir(self.unzip_target + self.extension_id, self.instrumented_dir + self.extension_id)
                        
                        """ Resolve absolute path for all the background scripts (also, from pages). """
                        scripts_absolute_path = self.absolute_path_of_scripts(bg_scripts)
                        if len(scripts_absolute_path):
                            """ collect host permisasion from the manifest and process them to remove wildcards. """
                            manifest_hosts = self.manifest_host_permissions(manifest_content)
                            manifest_processed_urls = list(self.preprocess_urls(manifest_hosts).values())
                            """ Extract inline hosts from the APIs within the code. """
                            processed_hosts = self.extract_inline_hosts(scripts_absolute_path)
                            
                            """ Inject API Hooks now. """
                            for script_path in scripts_absolute_path:
                                self.inject_hook(script_path)
                            os.remove(self.instrumented_dir + self.extension_id + '/instrumented_hooks.js')
                                
                            """ Check and fix the CSP policy defined in the manifest to allow header-collection. """
                            manifest_content = self.configure_csp(manifest_content)
                            """ Compare any modifications in the manifest during our analysis and write them on the disk. """
                            if json.dumps(manifest_content) != json.dumps(original_manifest):
                                with open(self.instrumented_dir + self.extension_id + "/manifest.json", "w") as fh:
                                    json.dump(manifest_content, fh)
                            
                            """ Check if the extension needs to be run on our test domain as per their host permissions. """
                            self.check_host_injection(manifest_processed_urls, manifest_content, processed_hosts)
                            if self.host_modified:
                                manifest_content["permissions"].extend([PROXY, FILE_PATH_SUBSTITUTE])
                                manifest_processed_urls.extend([PROXY, FILE_PATH_SUBSTITUTE])
                                self.copy_dir(self.instrumented_dir + self.extension_id, self.instrumented_dir + self.extension_id + "_2")
                                self.rewrite_inline_hosts(scripts_absolute_path)
                                with open(self.instrumented_dir + self.extension_id + "_2" + "/manifest.json", "w") as fh:
                                    json.dump(manifest_content, fh)
                                shutil.move(self.instrumented_dir + self.extension_id, self.instrumented_dir + self.extension_id + "_1")                    
                            
                            """ Total host permissions for an extensions. """
                            total_processed_hosts = list(set(manifest_processed_urls + processed_hosts))
                            if len(total_processed_hosts):
                                """ Store the host-related data for the extension used during dynamic analysis. """
                                self.store_extension_hosts(total_processed_hosts)
        except:
            logging.error("Error while processing extension: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))

def instantiate_worker(extension_id):
    """ Instantiates analyzer object and starts processing each of the given extension_id.
    Args:
        extension_id (str): extension_id
    """
    try:
        static_analyzer = StaticAnalyzer(extension_id, EXTENSION_TYPE, DATASET_YEAR)
        static_analyzer.start_processing()
    except:
        logging.error("Error while instantiating workers for extension:" + extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))

def initialize_dir():
    """ Create directories to store unzipped and instrumented extensions. """
    try:
        if os.path.exists(f"./unzipped_ext_{EXTENSION_TYPE}_{DATASET_YEAR}"):
            shutil.rmtree(f"./unzipped_ext_{EXTENSION_TYPE}_{DATASET_YEAR}")
        os.mkdir(f"./unzipped_ext_{EXTENSION_TYPE}_{DATASET_YEAR}")
        if os.path.exists(f"./instrumented_ext_{EXTENSION_TYPE}_{DATASET_YEAR}"):
            shutil.rmtree(f"./instrumented_ext_{EXTENSION_TYPE}_{DATASET_YEAR}")
        os.mkdir(f"./instrumented_ext_{EXTENSION_TYPE}_{DATASET_YEAR}")
    except:
        logging.error("Error while initializing directories - ", "; ".join(traceback.format_exc().split("\n")))

def parse_args():
    """ Parses the user arguments and sets the environmental and operational configuration for the static analysis. 
        Here, one must provide the extension type to successfully initiate the analysis.
        We omit the year specific analysis and thus, only take it as an optional argument here, to keep the demonstrable analysis compact.
        By default, the analytical script would utilize single process, but this could be configured by additionally passing the number of workers as an argument.
    """   
    try:
        global WORKERS
        global EXTENSION_TYPE
        global DATASET_YEAR
        parser = argparse.ArgumentParser(description='Static Analyzer for Browser Extensions')
        parser._action_groups.pop()
        required_args = parser.add_argument_group('Required arguments')
        required_args.add_argument("-s", "--store", help="Please provide the Browser/Store: 'chrome' or 'firefox'", required=True, type=str)
        optional_args = parser.add_argument_group('Optional arguments')
        optional_args.add_argument("-w", "--workers", help="Please provide number of workers to use.", required=False, type=int, default=1)
        optional_args.add_argument("-y", "--year", help="Please provide the year of dataset (only in case of chrome) to analyze.", required=False, type=int, default=2022)
        args = parser.parse_args()
        EXTENSION_TYPE = args.store
        DATASET_YEAR = args.year
        WORKERS = args.workers

        if EXTENSION_TYPE not in ['chrome', 'firefox']:
            print("Invalid Extension Type! Exiting Pre-processing...")
            sys.exit(1)
        if not (2019 < DATASET_YEAR <= 2022):
            DATASET_YEAR = 2022
        if not (0 < WORKERS < os.cpu_count()):
            print("Requested number of workers is invalid or higher than CPU count, defaulting to 1...")
            WORKERS = 1
    except:
        logging.error("Error while parsing arguments - " + "; ".join(traceback.format_exc().split("\n")))
        sys.exit(1)

def init(): 
    try:
        parse_args()
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            filename="./static/static_analysis_%s_%s.log" % (EXTENSION_TYPE, DATASET_YEAR),
            filemode="w"
        )
        logging.getLogger("urllib3").setLevel(logging.ERROR)
        
        """ Enumerate all the extension ids downloaded and available for the given extension type for analysis. """
        if EXTENSION_TYPE == "chrome": total_extensions = os.listdir(CHROME_EXTENSION_DIR)
        else: total_extensions = os.listdir(FIREFOX_EXTENSION_DIR)
        
        if len(total_extensions):
            logging.info("Static analysis started!")
            initialize_dir()
            with mp.Pool(processes=WORKERS) as pool:
                for _ in tqdm(pool.imap_unordered(instantiate_worker, total_extensions), total=len(total_extensions)):
                    continue
            logging.info("Analysis completed!")
    except:
        logging.error("Error at init() :( - " + "; ".join(traceback.format_exc().split("\n")))
        print("Error at init() :( - " + "; ".join(traceback.format_exc().split("\n")))

if __name__ == "__main__":
    init()