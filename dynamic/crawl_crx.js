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


const fs = require("fs");
const chalk = require("chalk");
const error = chalk.bold.red;
const success = chalk.bold.green;
const puppeteer = require("puppeteer");
const XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;

var EXT_YEAR = '2022';

async function getTrancoURLs() {
    try {
        return JSON.parse(fs.readFileSync("./dynamic/urls.json", {
            encoding: "utf8",
        }))
    } catch (e) {
        console.error(error("Error in getTrancoURLs():", e.message));
    }
}

async function getExtension(year=EXT_YEAR) {
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
            xmlHTTPRequest.open("GET", `http://localhost:8000/extension?store=chrome&year=${year}`, true);
            xmlHTTPRequest.send();
        });
    } catch (e) {
        fs.appendFile(`./runtime_errors_chrome_${EXT_YEAR}.log`, `Error in getExtension(): ${e}\n`, function (err) {
            if (err) console.error(error(`File Write Error: ${url} : ${err.message}`));
        });
        console.error(error("Error in getExtension():", e.message));
    }
}

async function browse(browser, url, extension) {
    try {
        if (url !== "") {
            const page = await browser.newPage();
            await page.setCacheEnabled(false);
            page.setDefaultNavigationTimeout(30000);
            await page
                .goto(url, {
                    waitUntil: ["load", "networkidle2"],
                })
                .catch(function (e) {
                    console.error(error(`Navigation Error: ${e.message} - ${extension}`));
                    fs.appendFile(`./runtime_errors_chrome_${EXT_YEAR}.log`, `Navigation Error: ${url} - ${extension} - ${e.message}\n`, function (err) {
                        if (err) console.error(error(`File Write Error: ${url} : ${err.message}`));
                    });
                    return;
                });
            console.log(success(`${extension} : ${page.url()}`));
            await page.waitForTimeout(6500);
            await Promise.race([page.close(), page.close(), page.close(), page.close(), page.close(), page.close()]);
        }
    } catch (e) {
        console.error(error(`Framework Error:${url} : ${e.message}`));
        fs.appendFile(`./runtime_errors_chrome_${EXT_YEAR}.log`, `Framework Error: ${url} - ${extension} - ${e}\n`, function (err) {
            if (err) console.error(error(`File Write Error: ${url} : ${err.message}`));
        });
        await Promise.race([page.close(), page.close(), page.close()]);
    }
}

async function init() {
    try {
        let browsingUrls = await getTrancoURLs().catch((err) => {
            fs.appendFile(`./runtime_errors_chrome_${EXT_YEAR}.log`, `Error while fetching Tranco URLs - ${err.message}\n`, function (err) {
                    if (err) console.error(error(`File Write Error: ${err.message}`));
            })
        });
        while (browsingUrls?.length && true) {
            let extensionData = await getExtension().then((result) => {
                return result
            }).catch((err) => {
                fs.appendFile(`./runtime_errors_chrome_${EXT_YEAR}.log`, `Error while fetching extension data - ${err.message}\n`, function (err) {
                    if (err) console.error(error(`File Write Error: ${err.message}`));
                })
            });
            if (extensionData === undefined || extensionData === "" || extensionData.length < 1) {
                break;
            }
            for (let [extensionId, urls] of extensionData) {
                let launchArgs = {
                    headless: false,
                    defaultViewport: null,
                    ignoreHTTPSErrors: true,
                    ignoreDefaultArgs: ["--disable-extensions", "--site-per-process"],
                    args: [
                        "--no-zygote",
                        "--no-sandbox",
                        "--disable-gpu",
                        "--no-first-run",
                        "--start-maximized",
                        "--disable-infobars",
                        "--disable-dev-shm-usage",
                        "--disable-setuid-sandbox",
                        "--ignore-certificate-errors",
                        "--disable-accelerated-2d-canvas",
                        "--disable-site-isolation-trials",
                        "--ignore-certificate-errors-skip-list",
                        "--disable-extensions-file-access-check",
                        "--enable-features=NetworkService,NetworkServiceInProcess",
                        `--load-extension=./instrumented_ext_chrome_${EXT_YEAR}/${extensionId}`
                    ],
                };
                urls = JSON.parse(urls);
                let browser = await puppeteer
                    .launch(launchArgs)
                    .catch(e => fs.appendFileSync(`./browser_errors.log`, `${extensionId}\n`));
                if (browser === undefined || browser === "") {
                    process.exit(1);
                } else {
                    if (urls.length > 0) {
                        for (let index = 0; index < urls.length; index++) {
                            if (urls[index] === "<all_urls>") {
                                for (let idx = 0; idx < browsingUrls.length; idx++) {
                                    try {
                                        await browse(browser, `http://${browsingUrls[idx]}`, extensionId);
                                    } catch (e) {
                                        fs.appendFile(`./runtime_errors_chrome_${EXT_YEAR}.log`, `Error in opening url: ${browsingUrls[index]} - for extension:${extensionId}\n`, function (err) {
                                            if (err) console.error(error(`File Write Error: ${browsingUrls[index]} : ${err.message}`));
                                        });
                                        console.error(error(`Error in opening url: ${browsingUrls[index]} - for extension:${extensionId}`));
                                    }
                                }
                            } else {
                                if (urls[index].startsWith("*://")) {
                                    urls[index] = urls[index].replace("*://", "https://")
                                }
                                try {
                                    await browse(browser, urls[index], extensionId);
                                } catch (e) {
                                    fs.appendFile(`./runtime_errors_chrome_${EXT_YEAR}.log`, `Error in opening url: ${browsingUrls[index]} - for extension:${extensionId}\n`, function (err) {
                                        if (err) console.error(error(`File Write Error: ${urls[index]} : ${err.message}`));
                                    });
                                    console.error(error(`Error in opening url: ${urls[index]} - for extension:${extensionId}`));
                                }
                            }
                        }
                    }
                }
                await browser.close();
            }
        }
        process.exit(0);
    } catch (e) {
        console.error(error("Error in init():", e));
        fs.appendFile(`./runtime_errors_chrome_${EXT_YEAR}.log`, `Error in init(): ${e}\n`, function (err) {
            if (err) console.error(error(`File Write Error: ${err.message}`));
        });
        process.exit(1);
    }
}

init();