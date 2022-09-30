let parse = require("content-security-policy-parser");
let csp_data = process.argv[2];
let parsed_data = parse(csp_data);
parsed_data = JSON.stringify(parsed_data);
console.log(parsed_data);
return JSON.stringify(parsed_data);