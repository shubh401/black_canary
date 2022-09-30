-- Copyright (C) 2022 Shubham Agarwal
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as published
-- by the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.


DROP DATABASE IF EXISTS extension_headers;
DROP ROLE IF EXISTS black_canary;

CREATE DATABASE extension_headers;
CREATE USER "black_canary" WITH ENCRYPTED PASSWORD '130e9548318bd85ac30c6b17e93efedc';
GRANT ALL PRIVILEGES ON DATABASE extension_headers TO black_canary;