# Black Canary
## The multi-stage pipeline to analyze and detect browser extensions that manipulate security-related headers on visited websites at runtime.

This repository contains the pipeline used in our research study - [**Helping or Hindering? How Browser Extensions Undermine Security**](https://swag.cispa.saarland/papers/agarwal2022helping.pdf)  - accepted at [_ACM CCS 2022_](https://www.sigsac.org/ccs/CCS2022/program/accepted-papers.html). We demonstrate the workflow of our pipeline with sample Chrome and Firefox extensions available in this repository.
***

## Components
The pipeline consists of three major stages of analysis:
 - Pre-filtering, URL extraction & instrumentation of browser extensions.
 - Dynamic analysis of instrumented extensions & header interception.
 - Comparative analysis between original and extension-processed headers.
***

## Runtime Environment & Setup:
The runtime environment for testing our pipeline could be easily setup by using our Docker by executing:

```console
    $ docker-compose create && docker-compose start
```

This creates an Ubuntu image, installs all the required packages and dependencies required by the pipeline, and instantiates a ``PostgreSQL`` database instance to store intermediary data and results from the analysis. Setting up the docker container may take some time (approx. 5 - 10 minutes).

To process ahead, open a bash window in the container by executing:

``` console
    $ docker exec -it black_canary-app-1 bash
```
**Note:** The container name in the above command may differ on different machines.

The project root directory is also the working directory where all the analysis scripts should be executed from.
``` console
    $ pwd
    ./black_canary
```

**Optional:** After connecting to the shell, one may need to restart the ``PostgreSQL`` service by executing the following command:

``` console
    $ /etc/init.d/postgresql restart
```
***

### **1. Static Analysis**:
The project root directory has ``chrome_ext/`` and ``firefox_ext/``directory, which contain extensions from respective stores in their native packaged form. Our static analyzer extracts, preprocesses, extract URLs, and instrument these extensions by executing the parent _Python_ script, which uses other multiple _NodeJS_ scripts, all located inside the ``static/`` directory. The following initiates static analysis:

``` console
    $ python3 ./static/preprocess_extensions.py --store='chrome' --year=2022
```
where ``-s, --store`` and ``-y, --year`` are mandatory flags that indicate the extension type for analysis, *, i.e.,* ``chrome`` or ``firefox`` as well as the dataset year to be used for analysis, *, i.e.,* ``2020, 2021, 2022``, respectively.

After this stage, the extensions are unzipped into the ``unzipped_ext_*store*_*year*/`` (e.g. ``unzipped_ext_chrome_2022/``) directory and their instrumented counterparts for the respective stores are stored and located at ``./instrumented_ext_*store*_*year*/`` (e.g. ``instrumented_ext_chrome_2022/``) directory.

Now, for each extension that adheres to MV2 standards and holds the permission to modify headers, their host permissions are extracted and stored at the ``canary_*store*extensions`` table in the database, used in the next stage of our pipeline.

While we only host a few extensions from respective stores in this repository, any other extension could be similarly analyzed using this pipeline.
***

### **2. Dynamic Analysis & Header Interception**
The dynamic analysis for browser extensions constitutes a Django server that could be run and hosted on the ``localhost`` as follows:

```console
    $ python3 ./dynamic/crawler/manage.py runserver 8000
```

While we use an additional tool, ``gunicorn``, on top of our Django server for large-scale analysis, to enable multiple workers and threads, this is not necessary for the demonstrative purpose here.

Now, after the logging server is correctly initiated, the crawler instances for respective stores could be executed as follows:

For Chrome:
```console
    $ xvfb-run --auto-servernum node ./dynamic/crawl_crx.js
```
For Firefox:
```console
    $ xvfb-run --auto-servernum node ./dynamic/crawl_xpi.js
```
 
 Although the underlying crawling framework and package for Chrome & Firefox differ, we use headless sessions in both cases to load extensions and visit domains. This is enabled by ``X11 Utility`` (``xvfb-run``, used as above).

 **Note**: While running the dynamic framework on a headful machine (i.e., with display), one may omit using the ``X11 Utility`` and run:

For Chrome:
```console
    $ node ./dynamic/crawl_crx.js
```
For Firefox:
```console
    $ node ./dynamic/crawl_xpi.js
```

The Tranco Top 100 URLs, as on [November 1<sup>st</sup> 2021](https://tranco-list.eu/list/Y3JG), is available in ``./dynamic/urls.json``. One can add URLs here or change the URL extraction point in the crawling script mentioned above to test on specific hosts.
***

### **3. Post-Processing & Comparative Analysis**
After the headers are collected for each extension, the header comparison and analysis are made by:

```console
    $ python3 ./analysis/comparitive_analysis.py --store=chrome --headertype=request --year 2022
```
where, ``-s, --store`` indicates the extension type used for analysis, *, i.e.,* ``chrome`` or ``firefox`` to fetch respective data, ``-t, --headertype`` could be either ``request`` or ``response`` headers to be analyzed and ``-y, --year`` directs to select the dataset (e.g. ``2020, 2021, 2022``). An optional argument, ``-w, --worker``, could be passed with a number of parallel workers to utilize as an integer (By default, it is 1).

The final results processed after the comparison for the respective type of extensions are stored and could be viewed in the database in the ``canary_chromeresults`` and ``canary_firefoxresults`` tables.

For instance, the following query fetches the data for specific security-related headers along with the count and list of extensions that modify them:

```SQL
SELECT "header_name"
	,COUNT(DISTINCT "extension_id") AS extensions_count
	,ARRAY_AGG(DISTINCT "extension_id") AS extensions
FROM canary_chromeresults
WHERE "header_name" IN (
		'content-security-policy'
		,'content-security-policy-report-only'
		,'strict-transport-security'
		,'x-frame-options'
		,'referrer-policy'
		,'origin'
		,'referer'
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
		,'upgrade-insecure-requests'
		,'set-cookie'
		)
GROUP BY "header_name";
```

**Note:** While the above query only includes the list of security-related headers potentially modified by the extensions, our pipeline nevertheless collects **all** the headers intercepted and/or modified by them and thus could be queried here.
***

## Additional Analysis:
We provide an additional script - ``./additional/manifest_v3_analyzer.py`` - to analyze the Chrome extensions that adhere to MV3 standards and hold necessary permissions to modify headers by using static rulesets or executing ``updateDynamicRules`` or ``updateSessionRules`` APIs at runtime. After the script execution completes, the results are stored in the ``additional`` directory.
***

## LICENSING
This repository is licensed under the GNU Affero General Public License 3.0 as indicated in the ``LICENSE`` file included with the repository and at the top of each of the source code files.
