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
    This script is exclusively used to analyze the extensions with Manifest v3 stanadards and have static rulesets defined to modify headers.
    It analyze extensions in the following steps:
        1. It first checks the manifest version of the extension.
        2. If manifestv3, it then identifes the path to the rulesets defind for the "declarative_web_request" in the manifest.
        3. It then iteratively parses each of the files with rulesets and each of the rules to identify any "modifyHeader" actions.
        4. In the end, it collects all the headers for an extension anjd store it on the disk at the end of the analysis.
"""


from jsoncomment import JsonComment
from tqdm import tqdm

import multiprocessing as mp
import subprocess
import traceback
import jstyleson
import argparse
import logging
import shutil
import jsmin
import json
import ast
import sys
import os

WORKERS = 1
EXTENSION_TYPE = "chrome"
DATASET_YEAR = "2022"
EXTENSION_PATH = f"./unzipped_ext_{EXTENSION_TYPE}_{DATASET_YEAR}/"
RELEVANT_HEADERS = ['content-security-policy'
    		,'content-security-policy-report-only'
    		,'strict-transport-security'
    		,'x-frame-options'
    		,'referrer-policy'
    		,'origin'
    		,'referer'
			,'set-cookie'
    		,'access-control-allow-origin'
    		,'access-control-allow-headers'
    		,'access-control-allow-methods'
    		,'access-control-request-header'
    		,'access-control-request-method'
    		,'access-control-expose-headers'
    		,'x-content-type-options'
    		,'cross-origin-opener-policy'
    		,'cross-origin-embedder-policy'
    		,'cross-origin-resource-policy'
    		,'access-control-allow-credentials'
    		,'access-control-max-age'
    		,'sec-fetch-dest'
    		,'sec-fetch-user'
    		,'sec-fetch-site'
    		,'sec-fetch-mode'
    		,'upgrade-insecure-requests']

class ExtensionAnalyzer:
    def __init__(self, extension_id):
        """ Instantiates analytical environment for the given extensions used thoroughout its analysis.
        Args:
            extension_id (str): extension_id
        """
        self.extension_id = extension_id
    
    def list_of_files(self):
        """ Enumerates all the filenames with full path for a given extension directory.
        Args:
            directory_path (str): The extension directory to enumerate files.
        Returns:
            (List): The list of enumerated files.
        """
        self.file_list = []
        try:
            for root, _, file_names in os.walk(EXTENSION_PATH + self.extension_id):
                for file in file_names:
                    self.file_list.append(os.path.join(root, file))
        except:
            logging.error("Error while enumerating extension directory for: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
    
    def absolute_file_path_from_crx_dir(self, file):
        """ Finds the absolute path for a given background page or script used for instrumentation later.
        Args:
            file (str): filename to find its absolute path.
            extension_file_list (list): list of all the files with full path in an extension.
        Returns:
            (str): The absolute path of a given background script of an extension.
        """
        absolute_path = ""
        extension_name = self.extension_id
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
                if os.path.abspath(os.path.join(EXTENSION_PATH + extension_name, file_name)).lower() == os.path.abspath(file_path.lower()):
                    absolute_path = file_path
                    break
            if absolute_path == "":
                if file[0] == '/':
                    file_name = file[1:]
                    extension_name = self.extension_id
                elif file.startswith("./"):
                    file_name = file[2:]
                    extension_name = self.extension_id
                for file_path in self.file_list:
                    if os.path.join(EXTENSION_PATH + extension_name, file_name).lower() == file_path.lower():
                        absolute_path = file_path
                        break
        except:
            logging.error("Error while locating absolute path for ruleset path: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        finally:
            return absolute_path
  
    def read_manifest(self):
        """ Parses the manifest data (using multiple parsing libraries for error-handling among firefox extensions).
        Args:
            manifest_path (str): The absolute path of the manifest for the extension.
        Returns:
            manifest_data (dict): Parsed manifest data.
        """
        self.manifest_data = None
        manifest_path = EXTENSION_PATH + self.extension_id + "/manifest.json"
        try:
            if not os.path.exists(manifest_path):
                logging.error("Serious issues with: " + self.extension_id)
            try:
                manifest = open(manifest_path, "r", encoding='utf-8-sig').read()
            except:
                manifest = open(manifest_path, "rb").read()
            if manifest is not None and manifest != "":
                try:
                    self.manifest_data = json.loads(manifest)
                except:
                    try:
                        self.manifest_data = ast.literal_eval(manifest)
                    except:
                        try:
                            json_comment = JsonComment()
                            self.manifest_data = json_comment.loads(manifest)
                        except:
                            try:
                                self.manifest_data = jstyleson.loads(manifest)
                            except:
                                try:
                                    minified = jsmin(manifest)
                                    self.manifest_data = json.loads(minified)
                                except:
                                    try:
                                        manifest = open(manifest_path, "r", encoding='utf-8-sig', errors='ignore').read()
                                        self.manifest_data = json.loads(manifest)
                                    except:
                                        logging.error("Serious issues with the manifest: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        except:
            self.manifest_data = None

    def is_manifest_v3(self):
        """ Checks for the manifest version.
        Returns:
            (Bool): Whether or not the extension is of manifestv3 standard.
        """
        try:
            if self.manifest_data:
                if "manifest_version" in self.manifest_data.keys():
                    if self.manifest_data["manifest_version"] == 3:
                        return True
            else:
                logging.warning("Couldn't determine the manifest version for: " + self.extension_id)
        except:
            logging.error("Error while checking manifest version: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
    
    def has_permissions(self):
        """ Determines whether or not an extension adhering to MV3 also requests new API permissions to alter headers at runtime.
        Returns:
            (Bool): Whether or not the extension has ``declarativeNetRequest`` permission in its manifest.
        """        
        try:
            if self.manifest_data:
                if "permissions" in self.manifest_data.keys():
                    permissions = self.manifest_data["permissions"]
                    if "declarativeNetRequest" in permissions or "declarativeNetRequestWithHostAccess" in permissions or "declarativeNetRequestFeedback" in permissions:
                        return True
                if "optional_permissions" in self.manifest_data.keys():
                    is_perm_found = False
                    if "permissions" not in self.manifest_data:
                        self.manifest_data["permissions"] = []
                    optional_permissions = self.manifest_data["optional_permissions"]
                    for permission in optional_permissions:
                        if "declarativeNetRequest".lower() in permission.lower():
                            self.manifest_data["optional_permissions"].remove(permission)
                            self.manifest_data["permissions"].append(permission)
                            is_perm_found = True
                        
                    if not len(self.manifest_data["optional_permissions"]):
                        del self.manifest_data["optional_permissions"]
                    if not len(self.manifest_data["permissions"]):
                        del self.manifest_data["permissions"]
                    if is_perm_found: return True
            return False
        except:
            logging.error("Error while checking manifest permissions: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
    
    def grep_extension(self):
        """ Inspects the extension codebase to determine whetehr or not dynamic rules could be injected to alter headers at runtime.
        Returns:
            (Bool): Whether or not has the extension uses the ``updateDynamicRuleset`` API at code-level.
        """
        try:
            process = subprocess.Popen(["grep", "-irl", "updateDynamicRules\|updateSessionRules", EXTENSION_PATH + self.extension_id + "/"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.wait(120)
            output, err = process.stdout.read().decode().strip(), process.stderr.read().decode().strip()
            if err != "":
                logging.error("Error while grepping for extension: %s - %s" % (self.extension_id, err))
            elif output != "":
                return True
            return False
        except:
            logging.error("Error while grepping the file for Dynamic API in extensions:" + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
            
    def find_rulesets(self):
        """ Find all the rulesets related to "declarative_net_request" and header-modification. """
        self.extension_rulesets = []
        try:
            if "declarative_net_request" in self.manifest_data.keys():
                ruleset = self.manifest_data["declarative_net_request"]
                if len(ruleset.keys()):
                    if "rule_resources" in ruleset.keys():
                        for rule in ruleset["rule_resources"]:
                            if len(rule.keys()):
                                self.extension_rulesets.append(rule)
        except:
            logging.error("Error while locating rulesets for: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
            
    def parse_rules_files(self):
        """ Collect "modifyHeader" rules for requests and responses for all the rulesets.
        Returns:
            extension_header_rules (dict): All the header-modifying rulesets for an extension.
        """
        extension_header_rules = {}
        detected_header_rules = []
        try:
            if self.extension_rulesets:
                self.list_of_files()
                for rule_dict in self.extension_rulesets:
                    if "path" in rule_dict.keys():
                        absolute_path = self.absolute_file_path_from_crx_dir(rule_dict["path"])
                        try:
                            rule_data = json.loads(open(absolute_path, mode="r").read())
                        except:
                            rule_data = json.loads(open(absolute_path, mode="r", encoding="utf-8-sig").read())
                        if len(rule_data):
                            detected_header_rules.extend(self.check_header_rules(rule_data))
        except:
            logging.error("Error while parsing rule files for: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        finally:
            extension_header_rules[self.extension_id] = detected_header_rules
            return extension_header_rules
            
    def check_header_rules(self, parsed_rules):
        """ Collect "modifyHeader" rules for requests and responses for an individual ruleset.
        Args:
            parsed_rules (List): List of serialized rules parsed for an individual ruleset.
        Returns:
            detected_rulesets (List): Collected header-modifying rulesets.
        """
        detected_rulesets = []
        try:
            for rule in parsed_rules:
                if "action" in rule.keys() and "type" in rule["action"] and rule["action"]["type"] == "modifyHeaders":
                    detected_rulesets.append(rule)
        except:
            logging.error("Error while detecting header modification rules for: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        finally:
            return detected_rulesets
        
    def start_analysis(self):
        """ Instantiates the static analysis for extensions with manifestv3 standards.
        Returns:
            rules (dict or None): Detected static rulesets for each extension.
        """
        detected_header_rules, dynamic_apis_used = None, None
        try:
            self.read_manifest()
            if self.is_manifest_v3() and self.has_permissions():
                self.find_rulesets()
                if self.extension_rulesets:
                    detected_header_rules = self.parse_rules_files()
                if self.grep_extension():
                    dynamic_apis_used = self.extension_id
        except:
            logging.error("Couldn't initiate analysis for: " + self.extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))
        finally:
            return (detected_header_rules, dynamic_apis_used)

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
        logging.error("Error while parsing arguments - ", "; ".join(traceback.format_exc().split("\n")))
        sys.exit(1)
            
def instantiate_worker(extension_id):
    """ Instantiates analyzer object and starts processing each of the given extension_id.
    Args:
        extension_id (str): extension_id
    Returns:
        rules (dict or None): Detected static rulesets for each extension.
    """
    try:
        analyzer = ExtensionAnalyzer(extension_id)
        return analyzer.start_analysis()
    except:
        logging.error("Error while instantiating analysis for: " + extension_id + " - " + ", ".join(traceback.format_exc().split("\n")))

def init():
    try:
        parse_args()
        detected_rulsets, dynamic_api_usage = [], []
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s',
                            filename='./additional/manifest_v3_analysis.log', filemode='w')
        logging.getLogger("urllib3").setLevel(logging.ERROR)

        """ Start analysis for extensions with manifest v3 standards. """
        logging.info("Analysis started for Chrome extensions with Manifest v3 standards. ")
        total_extensions = os.listdir(EXTENSION_PATH)
        
        if len(total_extensions):
            with mp.Pool(processes=WORKERS) as pool:
                for (rules, is_dynamic_api_used) in tqdm(pool.imap_unordered(instantiate_worker, total_extensions), total=len(total_extensions)):
                    if rules: detected_rulsets.append(rules)
                    if is_dynamic_api_used: dynamic_api_usage.append(is_dynamic_api_used)
                    continue
        
        if len(detected_rulsets):
            with open("./additional/manifest_v3_static_rulesets.json", "w") as fh:
                json.dump({"static_rules": detected_rulsets}, fh, indent = 4)
        if len(dynamic_api_usage):
            with open("./additional/dynamic_api_usage.json", "w") as fh:
                json.dump({"dynamic_rules": dynamic_api_usage}, fh, indent = 4)
        logging.info("Analysis complete! ")
    except:
        logging.error("Error in init - ", "; ".join(traceback.format_exc().split("\n")))
   
if __name__ == '__main__':
    init()