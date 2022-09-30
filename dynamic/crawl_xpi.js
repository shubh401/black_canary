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


import { readFileSync, appendFile } from "fs";
import { cmd } from "web-ext";
import { XMLHttpRequest } from "xmlhttprequest";

var EXT_YEAR = '2022';

function timeout(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
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
        appendFile(`./runtime_errors_firefox_${EXT_YEAR}.log`, `Error in getExtension(): ${e.message}\n`, function (err) {
            if (err) console.error(`File Write Error: ${url} : ${err.message}`);
        });
        console.error("Error in getExtension():", e.message);
    }
}

async function browse(extension, url) {
    try {
        if (url !== "") {
            const runningInfo = await cmd
                .run(
                    {
                        //Please provide absolute path for all ``web-ext`` components to avoid runtime issues and incompatibilities.
                        sourceDir: `./instrumented_ext_firefox_2022/${extension}/`,
                        firefox: "/usr/bin/firefox-trunk",
                        keepProfileChanges: false,
                        profileCreateIfMissing: false,
                        noInput: true,
                        startUrl: url,
                    },
                    {
                        shouldExitProgram: false,
                    }
                )
                .then((runner) => runner.extensionRunners[0].runningInfo);
            console.log(`${extension} : ${url}`);
            await timeout(6500);
            process.kill(runningInfo.firefox.pid);
            return;
        }
    } catch (e) {
        appendFile(`./runtime_errors_firefox_${EXT_YEAR}.log`, `Error in browse(): ${e.message} for extension: ${extension}\n`, function (err) {
            if (err) console.error(`File Write Error: ${url} : ${err.message}`);
        });
        return;
    }
}

async function init() {
    try {
        let browsingUrls = await getTrancoURLs();
        while (true) {
            let extensionData = await getExtension().then((result) => {
                return result;
            });
            if (extensionData === undefined || extensionData === "" || extensionData.length < 1) {
                break;
            }
            
            for (let [extensionId, urls] of extensionData) {
                urls = JSON.parse(urls);
                if (urls.length > 0) {
                    for (let index = 0; index < urls.length; index++) {
                        if (urls[index] === "<all_urls>") {
                            for (let idx = 0; idx < browsingUrls.length; idx++) {
                                try {
                                    await browse(extensionId, browsingUrls[idx]);
                                } catch (e) {
                                    appendFile(`./runtime_errors_firefox_${EXT_YEAR}.log`, `Error in opening url: - ${browsingUrls[idx]}" - for extension:", ${extensionId}\n`, function (err) {
                                        if (err) console.error(`File Write Error: ${err.message}`);
                                    })                               }
                            }
                        } else {
                            try {
                                await browse(extensionId, urls[index]);
                            } catch (e) {
                                appendFile(`./runtime_errors_firefox_${EXT_YEAR}.log`, `Error in opening url: - ${urls[index]}" - for extension:", ${extensionId}\n`, function (err) {
                                    if (err) console.error(`File Write Error: ${err.message}`);
                                })
                            }
                        }
                    }
                }
            }
        }
    } catch (e) {
        appendFile(`./runtime_errors_firefox_${EXT_YEAR}.log`, `Error in init(): ${e.message}\n`, function (err) {
            if (err) console.error(`File Write Error: ${url} : ${err.message}`);
        });
    }
}

process.setMaxListeners(0);
init();
