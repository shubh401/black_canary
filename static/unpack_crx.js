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


const unzip = require("unzip-crx-3");

/**
 * This method unzips the Chrome extension.crx package into its native source-code folder-structure, required for static analysis.
 */
function unzip_crx(extension_path, target_dir) {
    try {
        unzip(extension_path, target_dir).then(() => {
            console.log("Done!");
        });
    } catch (e) {
        console.log("Error!");
    } finally {
        return;
    }
}


if (process.argv.length == 4) {
    extension_path = process.argv[2];
    target_dir = process.argv[3];
    unzip_crx(extension_path, target_dir);
} else {
    console.log("Invalid arguments! Please provide appropriate arguments.")
}