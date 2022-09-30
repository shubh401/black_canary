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
const acorn = require("acorn-loose");
const walk = require("acorn-walk");


function get_function_name(callee_object) {
    try {
        if (callee_object !== undefined) {
            if (callee_object.type === "MemberExpression" && callee_object.object !== undefined && callee_object.object.type == "Identifier") {
                let name = callee_object.object.name !== undefined ? `${callee_object.object.name}.` : "";
                if (callee_object.property !== undefined && callee_object.property.name !== undefined) {
                    name = `${name + callee_object.property.name}.`;
                } else if (callee_object.property.value !== undefined) {
                    name = `${name.substring(0, name.length - 1)}[${callee_object.property.value}].`;
                } else if (name !== "" && name !== undefined) {
                    name += "";
                } else {
                    name = "";
                }
                return name;
            } else if (callee_object.type === "MemberExpression" && callee_object.object.type === "ThisExpression") {
                let name = "this.";
                name = callee_object.property !== undefined ? (callee_object.property.name !== undefined ? `${name + callee_object.property.name}.` : "") : "";
                return name;
            } else {
                let prop_name = ""
                if (callee_object.property !== undefined && callee_object.property.name !== undefined) {
                    prop_name = `${callee_object.property.name}.`;
                } else if (callee_object.property !== undefined && callee_object.property.value !== undefined) {
                    prop_name = `[${callee_object.property.value}].`;
                }
                return get_function_name(callee_object.object) + prop_name;
            }
        }
    } catch (e) {
        console.error("Error in get_function_name():", e);
        fs.writeFileSync("./static/static_error.log", `Error in get_function_name:${e}`, {
            flag: 'a+'
        });
    }
    return "";
}

function extract_urls(arg_object) {
    let url_list = [];
    try {
        if (arg_object.type === "ObjectExpression" && Object.keys(arg_object).includes("properties")) {
            for (let index = 0; index < arg_object.properties.length; index++) {
                if (arg_object.properties[index].key.name === "urls") {
                    for (let idx = 0; idx < arg_object.properties[index].value.elements.length; idx++) {
                        if (arg_object.properties[index].value.elements[idx].type === "Literal")
                            url_list.push(arg_object.properties[index].value.elements[idx].value);
                    }
                    break;
                }
            }
        }

    } catch (e) {
        console.error(error("Error in extract_urls(): " + e));
        fs.writeFileSync("./static/static_error.log", `Error in extract_urls: ${e}`, {
            flag: 'a+'
        });
    } finally {
        return url_list;
    }
}

function process_calls(call_node, process_args = true) {
    let call_data = {};
    try {
        call_data.name = "";
        if (call_node.callee !== undefined) {
            if (call_node.callee.object !== undefined) {
                if (call_node.callee.object.type === "Identifier" || call_node.callee.object.name !== undefined) {
                    call_data.name = `${call_node.callee.object.name}.`;
                } else if (call_node.callee.object.type === "MemberExpression") {
                    let object_name = get_function_name(call_node.callee.object)
                    call_data.name += object_name !== undefined ? object_name : "";
                } else if (call_node.callee.object.type === "Literal" && call_node.callee.object.value !== undefined) {
                    call_data.name = `${call_node.callee.object.value}.`;
                }
                if (call_node.callee.property !== undefined && call_node.callee.property.name !== undefined) {
                    call_data.name += call_node.callee.property.name;
                }
            } else if (call_node.callee.name !== undefined) {
                call_data.name = call_node.callee.name;
            }
            if (process_args && call_node.arguments !== undefined) {
                call_data.arguments = process_arguments(call_node.arguments);
            }
        }
    } catch (e) {
        console.error("Error in process_calls:", e);
        fs.writeFileSync("./static/static_error.log", `Error in process_calls:${e}`, {
            flag: 'a+'
        });
    }
    return call_data;
}

function tree_walker(ast_tree) {
    let url_list = [];
    walk.fullAncestor(ast_tree, (node) => {
        try {
            let call_data = {};
            let name = "";
            if (node.type === "CallExpression") {
                call_data = process_calls(node, false);
                if (call_data !== undefined && call_data.name !== undefined) {
                    name = call_data.name;
                }
                if (name !== "" &&
                    name !== "." &&
                    (name.includes("onBeforeSendHeaders") || name.includes("onHeadersReceived"))) {
                    if (node.arguments !== undefined) {
                        url_list = url_list.concat(extract_urls(node.arguments[1]));
                    }
                    // fs.writeFileSync("./static/detected_event_listener.log", process.argv[2] + "\n", {
                    //     flag: 'a+'
                    // });
                }
            }
        } catch (e) {
            console.error("Error in tree_walker():", e);
            fs.writeFileSync("./static/static_error.log", `Error in tree_walker:${e}`, {
                flag: 'a+'
            });
        }
    });
    return url_list;
}

function parse_js(file_path, parent_node = null) {
    return acorn.parse(fs.readFileSync(file_path), {
        allowImportExportEverywhere: true,
        allowAwaitOutsideFunction: true,
        allowReturnOutsideFunction: true,
        allowHashBang: true,
        allowReserved: true,
        program: parent_node,
    });
}

function init_process(script_path) {
    try {
        if (script_path !== undefined) {
            let ast_tree = null;
            let url_list = [];
            try {
                ast_tree = parse_js(script_path, ast_tree);
            } catch (e) {
                throw e;
            }
            if (ast_tree !== undefined && ast_tree !== null) {
                url_list = tree_walker(ast_tree);
            }
            if (url_list !== undefined && url_list.length > 0) {
                return [...new Set(url_list)];
            }
        }
        return []
    } catch (e) {
        fs.writeFileSync("./static/static_error.log", `Error in init_process:${e}`, {
            flag: 'a+'
        });
        throw e;
    }
}

function init() {
    try{
        let script_path = process.argv[2];
        if (script_path) {
            let url_data = init_process(script_path);
            if (url_data) {
                console.log(JSON.stringify(url_data));
            } else{
                console.error("Error!");
            }
        }
    } catch (e) {
        console.error("Error!");
    } finally {
        return;
    }
}

init();