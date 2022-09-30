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


const ContentSecurityPolicy = require('csp-dev');

let csp_data = process.argv[2];


let parser = new ContentSecurityPolicy(csp_data);
let parsed_data = parser.share('json');

if (parsed_data !== undefined && Object.keys(parsed_data).length > 0  && parser.valid()) {
    if (Object.keys(parsed_data).indexOf("connect-src") > -1) {
        parsed_data["connect-src"].unshift("http://localhost:8000");
        parsed_data["connect-src"].unshift("http://127.0.0.1:8000");
    } else if (Object.keys(parsed_data).indexOf("default-src") > -1) {
        parsed_data["connect-src"] = ["http://localhost:8000", "http://127.0.0.1:8000"];
    }
    if (Object.keys(parsed_data).indexOf("script-src") > -1) {
        if (parsed_data["script-src"].indexOf("'self'") == -1)
            parsed_data["script-src"].unshift("'self'");
        if (parsed_data["script-src"].indexOf("'unsafe-inline'") > -1)
            parsed_data["script-src"].splice(parsed_data["script-src"].indexOf("'unsafe-inline'"), 1)
        if (parsed_data["script-src"].indexOf("'unsafe-eval'") > -1)
            parsed_data["script-src"].splice(parsed_data["script-src"].indexOf("'unsafe-eval'"), 1)
        if (parsed_data["script-src"].length == 0) {
            parsed_data["script-src"].unshift("'self'");
		}
    }		
    let builder = new ContentSecurityPolicy();
    builder.load(parsed_data);
    let modified_csp = builder.share('string');
    console.log(modified_csp);
    return modified_csp;
}
