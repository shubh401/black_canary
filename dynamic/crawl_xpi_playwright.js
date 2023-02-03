// Copyright (C) 2022 Shubham Agarwal

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import { readFileSync, writeFileSync } from 'fs';
import freeportAsync from 'freeport-async';
import { firefox } from 'playwright';
import { connect } from '../../node_modules/web-ext/lib/firefox/remote.js';

var EXT_YEAR = '2022';

let LAUNCH_ARGS = {
    headless: false,
    timeout: 10000,
    ignoreHTTPSErrors: true,
    args: [
        '--no-zygote',
        '--no-sandbox',
        '--disable-gpu',
        '--no-first-run',
        '--start-maximized',
        '--disable-infobars',
        '--disable-dev-shm-usage',
        '--disable-setuid-sandbox',
        '--ignore-certificate-errors',
        '--disable-software-rasterizer',
        '--allow-running-insecure-content',
        '--ignore-certificate-errors-spki-list',
    ],
    firefoxUserPrefs: {
        'devtools.debugger.remote-enabled': true,
        'devtools.debugger.prompt-connection': false,
    }
};

async function instrumentManifest(extensionId) {
    try {
        let manifestData = JSON.parse(readFileSync(`./instrumented_ext_firefox_2022/${extensionId}/manifest.json`, {
            encoding: "utf8",
        }))
        if (Object.keys(manifestData).includes("browser_specific_settings") && Object.keys(manifestData["browser_specific_settings"]).includes("gecko")) {
            if (Object.keys(manifestData["browser_specific_settings"]["gecko"]).includes("id")) return;
            else manifestData["browser_specific_settings"] = {"gecko": {"id": `${extensionId}@example.com`}};
        }
        else if (Object.keys(manifestData).includes("applications") && Object.keys(manifestData["applications"]).includes("gecko")) {
            if (Object.keys(manifestData["applications"]["gecko"]).includes("id")) return;
            else manifestData["applications"] = {"gecko": {"id": `${extensionId}@example.com`}};
        }
        else manifestData["applications"] = {"gecko": {"id": `${extensionId}@example.com`}};
        writeFileSync(`./instrumented_ext_firefox_2022/${extensionId}/manifest.json`, JSON.stringify(manifestData), {
            flag: "w",
            encoding: "utf-8",
        })
        return;
    } catch(e) {
        console.error("Error in instrumentManifest():", e.message);
    }
}

async function getExtension(year = EXT_YEAR) {
    try {
        let xmlHTTPRequest = new XMLHttpRequest();
        return new Promise(function (resolve, reject) {
            xmlHTTPRequest.onreadystatechange = function () {
                if (xmlHTTPRequest.readyState === 4) {
                    if (xmlHTTPRequest.status >= 300) {
                        reject(`Error, status code = ${xmlHTTPRequest.status}`);
                    } else {
                        resolve(JSON.parse(xmlHTTPRequest.responseText));
                    }
                }
            };
            xmlHTTPRequest.open("GET", `http://localhost:8000/extension?store=firefox&year=${year}`, true);
            xmlHTTPRequest.send();
        });
    } catch (e) {
        console.error("Error in getExtension():", e.message);
    }
}

async function getTrancoURLs() {
    try {
        return JSON.parse(readFileSync("./dynamic/urls.json", {
            encoding: "utf8",
        }))
    } catch (e) {
        console.error("Error in getTrancoURLs():", e.message);
        process.exit(1);
    }
}

async function getFreePort(extensionId) {
    try {
        let freePort = await freeportAsync(9000);
        return freePort;
    } catch(e) {
        console.error(`Error in getFreePort() for extension - ${extensionId} : ${e.message}`);
        process.exit(1);
    }
}

async function browse(browser, extensionId, url) {
    try {
        if (browser === undefined) {
            console.error(`Browser instance is dead!`);
            process.exit(1);
        }
        let page = await browser.newPage();
        page.setDefaultNavigationTimeout(60000);
        await page.goto(url, {
            waitUntil: 'networkidle',
            timeout: 30000,
        });
        console.log(`${extensionId} : ${url}`);
        await page.waitForTimeout(6500);
        await Promise.race([page.close(), page.close(), page.close(), page.close(), page.close(), page.close()]);
    } catch (e) {
        console.error(`Framework error while browsing for extension ${extensionId} : ${e.message}`);
    }
}

async function browserInstance(extensionId) {
    try {
        await instrumentManifest(extensionId);
        let rdp_port = await getFreePort(extensionId);
        let launchArgs = LAUNCH_ARGS;
        launchArgs["args"].push(`--start-debugger-server=${String(rdp_port)}`);
        const browser = await firefox.launch(launchArgs);
        const client = await connect(rdp_port);
        const resp = await client.installTemporaryAddon(`/Users/shubhamagarwal/black_canary/instrumented_ext_firefox_2022/${extensionId}/`);

        if (resp?.addon?.id) {
            console.log("Installed addon with ID", resp.addon.id);
        } else {
            console.error("Error while loading extension:", extensionId);
        }
        return browser;
    } catch (e) {
        console.error(`Error while creating browser instance for extension - ${extensionId} : ${e.message}.`);
    }
}

async function init() {
    try {
        let browsingUrls = await getTrancoURLs();
        while (true) {
            // let extensionData = await getExtension().then((result) => {
            //     return result;
            // });
            let extensionData = [["canvasblocker", '["<all_urls>"]']];
            if (extensionData === undefined || extensionData === "" || extensionData.length < 1) break;
            for (let [extensionId, urls] of extensionData) {
                urls = JSON.parse(urls);
                
                let browser = await browserInstance(extensionId);
                if (urls.length > 0) {
                    for (let index = 0; index < urls.length; index++) {
                        if (urls[index] === "<all_urls>") {
                            for (let idx = 0; idx < browsingUrls.length; idx++) {
                                try {
                                    await browse(browser, extensionId, "https://" + browsingUrls[idx]);
                                } catch (e) {
                                    console.error(`Error while browsing url - ${browsingUrls[idx]} for extension - ${extensionId} : ${e.message}`);                               }
                            }
                        } else {
                            try {
                                await browse(browser, extensionId, urls[index]);
                            } catch (e) {
                                console.error(`Error while browsing url - ${urls[index]} for extension - ${extensionId} : ${e.message}`);
                            }
                        }
                    }
                }
                await browser.close();
            }
        }
    } catch(e) {
        console.error(`Error in init() - ${e.message}.`);
        return;
    }
}

process.setMaxListeners(0);
init();