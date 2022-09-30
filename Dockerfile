# Copyright (C) 2022 Shubham Agarwal
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


FROM ubuntu:20.04

SHELL ["/bin/bash", "-c"]

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get -y install tzdata software-properties-common
RUN apt-get update && apt-get -y install gnupg wget curl libpq5 libpq-dev python3-dev ssdeep poppler-utils xvfb libxml2-utils python3 python3-distutils python3-pip python3-venv uwsgi 
RUN apt-get update && apt-get -y install postgresql python3-psycopg2 postgresql-client postgresql-contrib uwsgi-plugin-python3
RUN echo "host    all             all             0.0.0.0/0               trust" >> /etc/postgresql/12/main/pg_hba.conf
RUN echo "listen_addresses = '*'" >> /etc/postgresql/12/main/postgresql.conf

RUN add-apt-repository ppa:ubuntu-mozilla-daily/ppa
RUN apt-get update
RUN apt-get install -y firefox-trunk
RUN apt-get update && apt-get install -y yarn

RUN curl -sL https://deb.nodesource.com/setup_14.x | bash -
RUN apt-get install -y nodejs
RUN apt-get install -y gcc g++ make
RUN npm install --save content-security-policy-parser csp-dev unzip-crx-3 escodegen fs-extra acorn acorn-loose acorn-walk puppeteer chalk@4.0.0 xmlhttprequest web-ext

USER postgres
COPY ./setup/db_setup.sql /tmp/db_setup.sql
RUN /etc/init.d/postgresql start && psql < /tmp/db_setup.sql

USER root
COPY ./setup/requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

ENV DEBUG=1
ENV SECRET_KEY='django-insecure-xnri@ve31@8uqoz(was&^pa@p$yy%@k@5!bykamp(hdeiu9+xh'
ENV SQL_ENGINE=django.db.backends.postgresql
ENV SQL_DATABASE=extension_headers
ENV SQL_USER=black_canary
ENV SQL_PASSWORD=130e9548318bd85ac30c6b17e93efedc
ENV SQL_HOST=127.0.0.1
ENV SQL_PORT=5432

WORKDIR /home/root
RUN mkdir -p black_canary
COPY chrome_ext black_canary/chrome_ext
COPY firefox_ext black_canary/firefox_ext
COPY static black_canary/static
COPY dynamic black_canary/dynamic
COPY analysis black_canary/analysis
COPY additional black_canary/additional

WORKDIR /home/root/black_canary
RUN /etc/init.d/postgresql restart && python3 dynamic/manage.py makemigrations canary && python3 dynamic/manage.py migrate
