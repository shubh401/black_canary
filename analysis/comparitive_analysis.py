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
    With this script, we compare all the collected headers for each of the extensions for which the interceting API was invoked during our dynamic analysis.
    We basically capture three forms of alterations here: dropped headers, injected headers and modified headers.
    Additionally, we also record the extension ids for those: 
        1. that drops all the headers entirely.
        2. that drops CSP headers entirely.
        3. that modifies specific CSP directives.
    Please file detailed runtime log at: ./comparitive_analysis/runtime_logger_*.log for debugging.
"""


from collections import defaultdict
from tqdm import tqdm

import multiprocessing as mp
import tldextract
import subprocess
import traceback
import argparse
import psycopg2
import logging
import json
import time
import sys
import os

DB_HOST = os.environ.get("SQL_HOST", "localhost")
DB_NAME = os.environ.get("SQL_DATABASE", "extension_headers")
DB_USER = os.environ.get("SQL_USER", "black_canary")
DB_PASS = os.environ.get("SQL_PASSWORD", "130e9548318bd85ac30c6b17e93efedc")

WORKERS = 1
YEAR_EXT = "2022"
EXT_TYPE = "chrome"
HEADER_TYPE = "request"

CSP_DROPPED = []
HEADER_DROPPED = []
MODIFIED_CSP_DIRECTIVES = []

REQ_SEC_HEADERS = {
    "sec-fetch-dest": " ",
    "sec-fetch-mode": " ",
    "sec-fetch-site": " ",
    "sec-fetch-user": " ",
    "dnt": "NoSplitChar",
    "referrer": "NoSplitChar",
    "referer": "NoSplitChar",
    "origin": "NoSplitChar",
    "user-agent": "NoSplitChar",
    "cache-control": ",",
    "access-control-request-method": ",",
    "access-control-request-headers": ",",
    "upgrade-insecure-requests": "NoSplitChar"
}
RESP_SEC_HEADERS = {
    "alt-svc": ";",
    "set-cookie": ";",
    "referrer-policy": ",",
    "x-frame-options": ",",
    "x-content-type-options": ",",
    "content-security-policy": ";",
    "strict-transport-security": ";",
    "content-security-policy-report-only": ";",
    "cross-origin-opener-policy": ",",
    "cross-origin-resource-policy": ",",
    "cross-origin-embedder-policy": ",",
    "access-control-max-age": " ",
    "access-control-allow-origin": " ",
    "access-control-allow-methods": ",",
    "access-control-allow-headers": ",",
    "access-control-expose-headers": ",",
    "access-control-allow-credentials": " ",
    "cache-control": ",",
    "clear-site-data": ",",
    "x-permitted-cross-domain-policies": ","
}

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    filename="./analysis/comparitive_analysis_%s_%s.log" % (EXT_TYPE, HEADER_TYPE),
    filemode="w"
)
logging.getLogger("urllib3").setLevel(logging.DEBUG)

class Analyser:
    def __init__(self, extension_id, ext_type, year_ext, header_type):
        """ Instantiates analytical environment for the given extensions used thoroughout its analysis.
        Args:
            extension_id (str): extension_id
            ext_type (str): chrome/firefox
            header_type (str): request/response
        """
        self.extension_id = extension_id
        if ext_type == "chrome":
            self.headers_table = "canary_chromeheaders"
        else:
            self.headers_table = "canary_firefoxheaders"
        self.year_ext = year_ext
        self.header_type = header_type
        self.ext_type = ext_type
        self.csp_mod = defaultdict(lambda: defaultdict(list))
        self.grouped_data = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        self.alterations = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))
        self.details = {"extension_id": extension_id, "dropped_headers": False, "dropped_csp": False, "modified_csp": False}

    def store_data(self):
        """ Stores all the diff data for a given extension into the database.
        Args:
            data (dict): The diff data for all the modified headers detecte during analysis for the given extension.
        """
        diff_list = []
        try:
            query = 'INSERT INTO canary_' + self.ext_type + 'results ("extension_id", "alter_type", "url_domain", "header_name", "orig_val", "orig_parsed_val", "new_val", "new_parsed_val", "source", "year", "timestamp") VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);'           
            connection = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
            cursor = connection.cursor()
            for ext_id, alter_data in self.alterations.items():
                for alter_type, mod_data in alter_data.items():
                    for domain, header_data in mod_data.items():
                        for header_name, header_values in header_data.items():
                            for [orig_val, orig_parsed_val, new_val, new_parsed_val] in header_values:
                                diff_list.append(
                                    (ext_id, alter_type, domain, header_name, json.dumps(orig_val),
                                        orig_parsed_val, json.dumps(new_val), new_parsed_val, 
                                        self.header_type, self.year_ext, time.ctime(),
                                    )
                                )
            if len(diff_list) > 0:
                cursor.executemany(query, diff_list)
                connection.commit()
            connection.close()
        except:
            logging.error("Error in store_data(): " + "; ".join(traceback.format_exc().split("\n")))

    def comparse_csp_data(self, header_name, data_before, parsed_data_before, data_after, parsed_data_after):
        """Compares the CSP header data for given domain and for extension under analysis.
        Args:
            header_name (str): The header name: CSP or CSP-RO
            data_before (str): Stringified ground-truth CSP data.
            parsed_data_before (dict): Parsed ground-truth CSP data.
            data_after (str): Stringified extension-processed CSP data.
            parsed_data_after (dict): Parsed extension-processed CSP data.
            reg_domain (str): The domain for which the CSP header data is to be compared.
        Returns:
            dict: The master alteration data with additionally CSP based modifications for the extension.
        """
        try:
            parsed_data_before = json.loads(parsed_data_before)
            while type(parsed_data_before) == type(""):
                if parsed_data_before == "":
                    parsed_data_before = {}
                    break
                parsed_data_before = json.loads(parsed_data_before)
            parsed_data_after = json.loads(parsed_data_after)
            while type(parsed_data_after) == type(""):
                if parsed_data_after == "":
                    parsed_data_after = {}
                    break
                parsed_data_after = json.loads(parsed_data_after)
            
            """ If the CSP data is nullified by the extension, this is counted as dropped. """
            if len(parsed_data_before.keys()) and not len(parsed_data_after.keys()):
                self.details["dropped_csp"] = True
                
            if (set(parsed_data_after.keys()) - set(parsed_data_before.keys())) or (
                set(parsed_data_before.keys()) - set(parsed_data_after.keys())
            ):
                """ If the certain CSP directives are dropped or injected by the extension, 
                    this captures the overall modifications to the CSP as well the individual directives 
                    seperately for each extension. 
                """
                for directive in set(parsed_data_after.keys()) - set(parsed_data_before.keys()):
                    self.csp_mod[self.extension_id]["injected"].append(directive)
                for directive in set(parsed_data_before.keys()) - set(parsed_data_after.keys()):
                    self.csp_mod[self.extension_id]["dropped"].append(directive)
                self.alterations[self.extension_id]["modified"][self.request_domain][header_name].append(
                    [data_before, json.dumps(parsed_data_before), data_after, json.dumps(parsed_data_after)]
                )
                return
            else:
                """ If the extension only modifies the CSP headers without dropping or injecting any directives. """
                for directive in parsed_data_after.keys():
                    if set(parsed_data_before[directive]) == set(parsed_data_after[directive]):
                        continue
                    else:
                        self.csp_mod[self.extension_id]["modified"].append(directive)
                        self.alterations[self.extension_id]["modified"][self.request_domain][header_name].append(
                            [data_before, json.dumps(parsed_data_before), data_after, json.dumps(parsed_data_after)]
                        )
                        return
        except:
            logging.error("Error in comparse_csp_data(): " + "; ".join(traceback.format_exc().split("\n")))
        return

    def parse_header_values(self, header_name, header_value):
        """Parses the values for the given header based on its property.
        Args:
            header_name (str): The header to be parsed.
            header_value (str): Stringified header value.
        Returns:
            dict: Parsed and consolidated values for the given header
        """
        parsed_values = ""
        try:
            if header_name.startswith("content-security-policy"):
                """ If the header is CSP or CSP-RO, we use an additional JS module to parse the values into JSON. """
                parser_process = subprocess.Popen(["node","./analysis/csp_parser.js", header_value], stdout=subprocess.PIPE)
                parser_output = parser_process.stdout.read()
                parsed_csp = parser_output.decode().strip()
                """ This returns directives and their respective values as deserialized JSON. """
                
                pre_procesed_csp = defaultdict(list)
                parsed_csp = json.loads(parsed_csp)
                while type(parsed_csp) == type(""):
                    parsed_csp = json.loads(parsed_csp)
                for key, values in parsed_csp.items():
                    for elem in values:
                        pre_procesed_csp[key].append(elem.strip())
                parsed_values = json.dumps(pre_procesed_csp)
            else:
                """ For other header, we split the values for each headers based on their known delimiters. """
                parsed_values = []
                if (self.header_type == "request" and header_name in REQ_SEC_HEADERS.keys()):
                    header_value = header_value.replace("\n", REQ_SEC_HEADERS[header_name])
                    parsed_values.extend(header_value.split(REQ_SEC_HEADERS[header_name]))
                elif (self.header_type == "response" and header_name in RESP_SEC_HEADERS.keys()):
                    header_value = header_value.replace("\n", RESP_SEC_HEADERS[header_name])
                    parsed_values.extend(header_value.split(RESP_SEC_HEADERS[header_name]))
                else:
                    header_value = header_value.replace("\n", ",")
                    parsed_values.extend(header_value.split(","))
                parsed_values = json.dumps(parsed_values)
        except:
            logging.error("Error in parse_header_values(): " + "; ".join(traceback.format_exc().split("\n")))
        return parsed_values

    def check_injections(self):
        """Compares the two sets of headers to find those headers which does not exist in ground-truth dataset and have been injected by the extension under analysis at runtime."""
        try:
            if len(self.headers_before) and self.headers_after - self.headers_before:
                """ For those headers which does not exist in the ground-truth headers set. """
                for diff_header in self.headers_after - self.headers_before:
                    while len(self.parsed_after[diff_header]):
                        new_val = ""
                        new_parsed_val = '""'
                        try:
                            new_val = self.parsed_after[diff_header].pop()
                            new_parsed_val = self.parse_header_values(diff_header, new_val)
                        except:
                            """ If the new header values is not parsed or is null, e.g. "upgarde-insecure-requests;" """
                            new_val = "*"
                            new_parsed_val = '"*"'
                        self.alterations[self.extension_id]["injected"][self.request_domain][diff_header].append(["", '""', new_val, new_parsed_val])
        except:
            logging.error("Error in check_injections(): " + "; ".join(traceback.format_exc().split("\n")))
        return

    def check_drops(self):
        """Compares the two sets of headers to find those headers which does not exist in extension-processed dataset and have been dropped by the extension under analysis at runtime."""
        try:
            if len(self.headers_after) and self.headers_before - self.headers_after:
                """ For those headers which exists in the ground-truth headers set but not in the post-processing headers set. """
                for diff_header in self.headers_before - self.headers_after:
                    if diff_header.lower() == "content-security-policy":
                        self.details["dropped_csp"] = True
                    while len(self.parsed_before[diff_header]):
                        original_val = ""
                        original_parsed_val = '""'
                        try:
                            original_val = self.parsed_before[diff_header].pop()
                            original_parsed_val = self.parse_header_values(diff_header, original_val)
                        except:
                            """ If the new header values is not parsed or is null, e.g. "upgarde-insecure-requests;" """
                            original_val = "*"
                            original_parsed_val = '"*"'
                        self.alterations[self.extension_id]["dropped"][self.request_domain][diff_header].append(
                            [original_val, original_parsed_val, "", '""']
                        )
        except:
            logging.error("Error in check_drops(): " + "; ".join(traceback.format_exc().split("\n")))
        return

    def check_modifications(self):
        """Compares the two sets of headers to find those headers which exist in both the datasets and have been modified by the extension under analysis at runtime."""
        try:
            for common_header in self.headers_after & self.headers_before:
                """ For common headers which exists in both the headers set and their values are not identical. """
                if (self.parsed_after[common_header] != self.parsed_before[common_header]):
                    while len(self.parsed_after[common_header]):
                        original_val = ""
                        original_parsed_val = '""'
                        new_val = ""
                        new_parsed_val = '""'
                        try:
                            original_val = self.parsed_before[common_header].pop()
                            original_parsed_val = self.parse_header_values(common_header, original_val)
                        except:
                            pass
                        try:
                            new_val = self.parsed_after[common_header].pop()
                            new_parsed_val = self.parse_header_values(common_header, new_val)
                        except:
                            pass
                        if original_val == "" and new_val != "" and common_header != 'upgrade-insecure-requests':
                            """ If the original header did not hold any value but the post-processed header did have a set value. """
                            self.alterations[self.extension_id]["injected"][self.request_domain][common_header].append(
                                [original_val, original_parsed_val, new_val, new_parsed_val]
                            )
                        elif original_val != "" and new_val == "":
                            """ If the original header had a set value but the post-processed header did not have any value. """
                            self.alterations[self.extension_id]["dropped"][self.request_domain][common_header].append(
                                [original_val, original_parsed_val, new_val, new_parsed_val]
                            )
                        else:
                            if common_header.startswith("content-security-policy"):
                                """ CSP(-RO)-based modifications are handled separately. """
                                self.comparse_csp_data(common_header, original_val, original_parsed_val, new_val, new_parsed_val)
                            else:
                                self.alterations[self.extension_id]["modified"][self.request_domain][common_header].append(
                                    [original_val, original_parsed_val, new_val, new_parsed_val]
                                )
        except:
            logging.error("Error in check_modifications(): " + "; ".join(traceback.format_exc().split("\n")))
        return

    def parse_json(self, data):
        """ Parse and returns the stringified header data as a serialized structure for analysis.
        Args:
            data (str): Deserialized header data
        Returns:
            dict: Serialized header data
        """
        result = defaultdict(set)
        try:
            entries = json.loads(data)
        except Exception:
            """ Invalid JSON """
            return {}

        """ Extracting header name and thir values, here."""
        for entry in entries:
            entry["name"] = str(entry["name"])
            if len(entry.keys()) > 1:
                result[entry["name"].lower()].add(str(entry.get("value")).lower())
            else:
                result[entry["name"].lower()]
        return result

    def start_comparison(self):
        """ This method parses all the header data for each domain and compare the ground-truth and extension-processed headers iteratively.
        Returns:
            dict: All forms of alterations identified for each headers by the extensions under analysis.
        """
        try:
            for request_id, request_dataset in self.grouped_data.items():
                for request_data in request_dataset[False]:
                    if request_data not in request_dataset[True]:
                        """ If there is no header at all after the extension processes them, this is counted as headers entirely dropped by the extension. """
                        self.details["dropped_headers"] = True
                        continue
                    for idx, _ in enumerate(request_dataset[False][request_data]):
                        """ 
                            If the extension does not modify any header at all for the given request, the flow continues to the next request. 
                            This is a comparison between the stringified header data.    
                        """
                        if (request_dataset[False][request_data][idx] == request_dataset[True][request_data][idx]):
                            continue
                        else:
                            """ If there is some modification detected. """
                            try:
                                """ Separately parses the hewader data before and after the modification for comparison. """
                                self.parsed_before = self.parse_json(request_dataset[False][request_data][idx])
                                self.parsed_after = self.parse_json(request_dataset[True][request_data][idx])
                                self.headers_before = set(self.parsed_before.keys())
                                self.headers_after = set(self.parsed_after.keys())
                            except:
                                logging.warning("Could not parse header data into JSON for extension: %s" % self.extension_id)
                                self.details["dropped_headers"] = True
                                continue
                            
                            """ The domain on which the alteration was carried out by the extensions. """
                            self.request_domain = tldextract.extract(request_data[0]).registered_domain
                            self.check_injections()
                            self.check_drops()
                            self.check_modifications()
        except:
            logging.error("Error in start_comparison() for extensions: " + str(self.extension_id) + " : " + "; ".join(traceback.format_exc().split("\n")))

    def get_ext_data(self):
        """ Retrieves all the header data from the database for a given extension Id.
        Returns:
            tuple: All the headers data for a particular extension id.
        """
        ext_data = ()
        try:
            query = """ SELECT request_url, request_id, frame_id, request_initiator, old_headers, new_headers, request_method, resource_type FROM %s WHERE extension_id = \'%s\' AND source = \'%s\' """ % (self.headers_table, self.extension_id, self.header_type,)
            connection = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
            cursor = connection.cursor()
            cursor.execute(query)
            ext_data = cursor.fetchall()
            connection.close()
        except:
            logging.error("Error in start_analysis(): " + "; ".join(traceback.format_exc().split("\n")))
        return ext_data

    def start_analysis(self):
        """ Starts the header-diff analysis for a given extension id. """
        try:
            """ Get extension-specific header data. """
            ext_data = self.get_ext_data()
            """ Group header-data encountered by the extension before and after processing it based on its request id. """
            for (request_url, request_id, frame_id, request_init, old_headers, new_headers, req_method, res_type,) in ext_data:
                self.grouped_data[request_id][False][(request_url, request_id, frame_id, request_init, req_method, res_type,)].append(old_headers)
                self.grouped_data[request_id][True][(request_url, request_id, frame_id, request_init, req_method, res_type,)].append(new_headers)
            """ Initiate comparison between grouped header data. """
            if self.grouped_data is not None and len(list(self.grouped_data.keys())):
                self.start_comparison()
            """ Store the alterations identified during analysis, if any. """
            if self.alterations and len(list(self.alterations.keys())):
                self.store_data()
            """ Store all the CSP-based directive-level modifications made by the extension, if any. """
            if self.csp_mod and self.csp_mod[self.extension_id] and len(self.csp_mod[self.extension_id].keys()):
                for alter_type in self.csp_mod[self.extension_id].keys():
                    self.csp_mod[self.extension_id][alter_type] = list(set(self.csp_mod[self.extension_id][alter_type]))
                self.details["modified_csp"] = True
                self.details["modified_csp_directives"] = {self.extension_id : self.csp_mod[self.extension_id]}
            return self.details
        except:
            logging.error("Error in start_analysis() for extensions: " + str(self.extension_id) + " : " + "; ".join(traceback.format_exc().split("\n")))

def store_auxilliary_data():
    try:
        if len(CSP_DROPPED):
            with open("./analysis/dropped_csp.json", "w") as fd:
                json.dump({"DROPPED_CSP": list(set(CSP_DROPPED))}, fd)
        if len(HEADER_DROPPED):
            with open("./analysis/dropped_headers.json", "w") as fd:
                json.dump({"DROPPED_HEADER": list(set(HEADER_DROPPED))}, fd)
        if len(MODIFIED_CSP_DIRECTIVES):
            with open("./analysis/modified_csp_directives.json", "w") as fd:
                json.dump({"MODIFIED_CSP": MODIFIED_CSP_DIRECTIVES}, fd)
    except:
        logging.error("Error in store_auxilliary_data(): " + "; ".join(traceback.format_exc().split("\n")))

def init_process(extension_id):
    """ Instantiates analyzer object and starts processing headers for given extension_id.
    Args:
        extension_id (str): extension_id
    """
    try:
        extension_analyzer = Analyser(extension_id, EXT_TYPE, YEAR_EXT, HEADER_TYPE)
        return extension_analyzer.start_analysis()
    except:
        logging.error("Error while spawning worker for: " + extension_id)

def get_ext_ids():
    """ Retrieves all the extension ids from the database used for dynamic analysis.
    Returns:
        list(str): List of all extension ids for which the dynamic analyzer collected given header type
    """
    ext_list = []
    try:
        query = (""" SELECT DISTINCT extension_id FROM %s WHERE source = \'%s\'; """ % ("canary_" + EXT_TYPE + "headers", HEADER_TYPE,))
        connection = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
        cursor = connection.cursor()
        cursor.execute(query)
        for (ext,) in cursor.fetchall():
            ext_list.append(ext)
    except:
        logging.error("Error in get_ext_ids(): " + "; ".join(traceback.format_exc().split("\n")))
    return ext_list

def parse_args():
    """ Parses the user arguments and sets the environmental and operational configuration for the analysis. 
        Here, one must provide the extension type and the header type to successfully initiate the analysis.
        We omit the year specific analysis and thus, do not take it as an argument here, to keep the demonstrable analysis compact.
        By default, the analytical script would utilize single process, but this could be configured by additionally passing the number of workers as an argument.
    """    
    global EXT_TYPE
    global HEADER_TYPE
    global WORKERS
    parser = argparse.ArgumentParser(description='Header Modification Analysis by Extensions')
    parser._action_groups.pop()
    required_args = parser.add_argument_group('Required arguments')
    required_args.add_argument("-s", "--store", help="Please provide the Browser/Store: 'chrome' or 'firefox'", required=True, type=str)
    required_args.add_argument("-t", "--headertype", help="Please specify which type of headers for analysis: 'request' or 'response'.", required=True, type=str)
    optional_args = parser.add_argument_group('Optional arguments')
    optional_args.add_argument("-y", "--year", help="Please provide the year od dataset to analyze.", required=False, type=int, default=2022)
    optional_args.add_argument("-w", "--workers", help="Please provide number of workers to use.", required=False, type=int, default=1)
    try:
        args = parser.parse_args()
        EXT_TYPE = args.store
        HEADER_TYPE = args.headertype
        WORKERS = args.workers
        if not (0 < WORKERS <= os.cpu_count()):
            print("Requested number of workers is invalid or higher than CPU count, defaulting to 1...")
            WORKERS = 1
    except:
        logging.error("Error while parsing arguments - " + "; ".join(traceback.format_exc().split("\n")))
        sys.exit(1)

def init():
    try:
        parse_args()
        logging.info("Analysis Started for %s : %s headers!" % (EXT_TYPE, HEADER_TYPE))
        extension_list = get_ext_ids()
        logging.info("Total %s extensions for analysis." % len(extension_list))
        if extension_list:
            with mp.Pool(processes=WORKERS) as pool:
                for details in tqdm(pool.imap_unordered(init_process, extension_list), total=len(extension_list)):
                    if details["dropped_csp"]:
                        CSP_DROPPED.append(details["extension_id"])
                    if details["modified_csp"]:
                        MODIFIED_CSP_DIRECTIVES.append(details["modified_csp_directives"])
                    if details["dropped_headers"]:
                        HEADER_DROPPED.append(details["extension_id"])
            store_auxilliary_data()     
        logging.info("Analysis Completed!")
    except:
        logging.error("Error in main() - " + "; ".join(traceback.format_exc().split("\n")))

if __name__ == "__main__":
    init()