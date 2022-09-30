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


var requestHookTrigerred = false;
var responseHookTriggerred = false;
var myExtensionId = "my_extension_id";
var datasetYear = "dataset_year_of_ext";

async function sendInterceptedData(interceptedData, data) {
	try {
		let xmlHTTPRequest = new XMLHttpRequest();
		return new Promise(function (resolve, reject) {
			xmlHTTPRequest.onreadystatechange = function () {
				if (xmlHTTPRequest.readyState === 4) {
					if (xmlHTTPRequest.status >= 300) {
						reject(`Error, status code = ${xmlHTTPRequest.status}`);
					} else {
						resolve(xmlHTTPRequest.responseText);
					}
				}
			};
			if (data === "request") {
				xmlHTTPRequest.open("POST", `http://127.0.0.1:8000/requestdata?store=firefox&year=${datasetYear}`, true);
			} else {
				xmlHTTPRequest.open("POST", `http://127.0.0.1:8000/responsedata?store=firefox&year=${datasetYear}`, true);
			}
			xmlHTTPRequest.send(JSON.stringify(interceptedData));
		}).catch((error) => {
			throw error;
		});
	} catch (e) {
		console.error(error("Error in sendInterceptedData: " + e.message));
	}
}

async function sendHookData(extensionId, hookData) {
	try {
		let xmlHTTPRequest = new XMLHttpRequest();
		xmlHTTPRequest.open(
			"GET",
			`http://127.0.0.1:8000/hookdata?extensionId=${extensionId}&${hookData}&store=firefox&year=${datasetYear}`,
			true
		);
		xmlHTTPRequest.send();
	} catch (e) {
		console.error(error(`Error in sendHookData: ${e.message}`));
	}
}

if (window.hooksInjected === undefined) {
	window.hooksInjected = true;

	(async function () {
		let _onBeforeSendHeaders_listener =
			browser.webRequest.onBeforeSendHeaders.addListener;

		async function _hookOnBeforeSendHeadersListener(callback, filters, opts) {
			console.log("onBeforeSendHeaders: registered");
			sendHookData(
				myExtensionId,
				"hookRegistered=True&hookRegistrationType=request"
			);

			async function _hooked() {
				if (!requestHookTrigerred) {
					console.log("onBeforeSendHeaders: triggered");
					sendHookData(
						myExtensionId,
						"hookTriggered=True&hookTriggerType=request"
					);
					requestHookTrigerred = true;
				}

				let header_data = JSON.parse(JSON.stringify(arguments[0]));
				header_data["extensionId"] = myExtensionId;

				let results = await callback(arguments[0]);

				header_data["newHeaders"] = JSON.parse(JSON.stringify(results));
				if (
					header_data.documentUrl === undefined ||
					!header_data.documentUrl.includes("moz-extension")
				) {
					console.log(header_data);
					sendInterceptedData([header_data], "request");
				}
				return results;
			}
			_onBeforeSendHeaders_listener.apply(this, [
				_hooked.bind(this),
				filters,
				opts,
			]);
		}
		try {
			browser.webRequest.onBeforeSendHeaders.addListener =
				_hookOnBeforeSendHeadersListener;
			console.log("Hook Injected");
			sendHookData(
				myExtensionId,
				"hookInjected=True&hookInjectionType=request"
			);
		} catch (e) {
			console.error(e);
			sendHookData(
				myExtensionId,
				"hookInjected=False&hookInjectionType=request"
			);
		}
	})();

	(async function () {
		let _onHeadersReceived_listener =
			browser.webRequest.onHeadersReceived.addListener;

		async function _hookOnHeadersReceivedListener(callback, filters, opts) {
			console.log("onHeadersReceived: registered");
			sendHookData(
				myExtensionId,
				"hookRegistered=True&hookRegistrationType=response"
			);

			async function _hooked() {
				if (!responseHookTriggerred) {
					console.log("onHeadersReceived: triggered");
					sendHookData(
						myExtensionId,
						"hookTriggered=True&hookTriggerType=response"
					);
					responseHookTriggerred = true;
				}

				let header_data = JSON.parse(JSON.stringify(arguments[0]));

				header_data["extensionId"] = myExtensionId;

				let results = await callback(arguments[0]);

				header_data["newHeaders"] = JSON.parse(JSON.stringify(results));
				if (
					header_data.documentUrl === undefined ||
					!header_data.documentUrl.includes("moz-extension")
				) {
					console.log(header_data);
					sendInterceptedData([header_data], "response");
				}

				return results;
			}
			_onHeadersReceived_listener.apply(this, [
				_hooked.bind(this),
				filters,
				opts,
			]);
		}
		try {
			browser.webRequest.onHeadersReceived.addListener =
				_hookOnHeadersReceivedListener;
			console.log("Response Hook Injected");
			sendHookData(
				myExtensionId,
				"hookInjected=True&hookInjectionType=response"
			);
		} catch (e) {
			console.error(e);
			sendHookData(
				myExtensionId,
				"hookInjected=False&hookInjectionType=response"
			);
		}
	})();

	(async function () {
		let _onBeforeRequest_listener =
			browser.webRequest.onBeforeRequest.addListener;

		async function _hookOnBeforeRequestListener(callback, filters, opts) {
			console.log("onBeforeRequest: registered");
			sendHookData(
				myExtensionId,
				"hookRegistered=True&hookRegistrationType=others"
			);

			async function _hooked() {
				let results = await callback(arguments[0]);
				return results;
			}
			_onBeforeRequest_listener.apply(this, [
				_hooked.bind(this),
				filters,
				opts,
			]);
		}
		try {
			browser.webRequest.onBeforeRequest.addListener =
				_hookOnBeforeRequestListener;
			console.log("Hook Injected");
			sendHookData(myExtensionId, "hookInjected=True&hookInjectionType=others");
		} catch (e) {
			console.error(e);
			sendHookData(
				myExtensionId,
				"hookInjected=False&hookInjectionType=others"
			);
		}
	})();

	(async function () {
		let _onAuthRequired_listener =
			browser.webRequest.onAuthRequired.addListener;

		async function _hookonAuthRequiredListener(callback, filters, opts) {
			console.log("onAuthRequired: registered");
			sendHookData(
				myExtensionId,
				"hookRegistered=True&hookRegistrationType=others"
			);

			async function _hooked() {
				let results = callback(arguments[0]);
				return results;
			}
			_onAuthRequired_listener.apply(this, [_hooked.bind(this), filters, opts]);
		}
		try {
			browser.webRequest.onAuthRequired.addListener =
				_hookonAuthRequiredListener;
			console.log("Hook Injected");
			sendHookData(myExtensionId, "hookInjected=True&hookInjectionType=others");
		} catch (e) {
			console.error(e);
			sendHookData(
				myExtensionId,
				"hookInjected=False&hookInjectionType=others"
			);
		}
	})();
}
