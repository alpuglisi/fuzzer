# bWAPP v2.2 lab fixture (CC-LAB-0300, FR-LAB-300). Lab-only, loopback-only.
#
# bWAPP is CC BY-NC-ND: its source is NEVER committed to this repository. The host
# fetches the pinned zip into the gitignored .cache/ (`python -m
# fuzzlab.lab_fixtures.external fetch bwapp`, verified there by sha256 and size), and
# this build verifies the sha256 AGAIN before extracting it. A mismatch fails the
# build. The build itself needs no network for bWAPP. The extracted tree is used
# byte-for-byte as downloaded: no file of it is modified (the DB connection is
# redirected by our own php ini to a shared unix socket instead of editing
# admin/settings.php).
#
# The fetch stage is busybox: the php:5.6 (Debian stretch) base has no unzip, and PHP
# 5.6's PharData wrote still-deflated bytes when extracting this archive.

FROM docker.io/library/busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e AS fetch
# Declared inside the stage: an ARG declared before the first FROM is empty here.
ARG BWAPP_SHA256=87b5363062b4be9d2aa91916f6396f0f7d56e8acca08b732440e863f8c9e4cd6
ENV ZIP=/tmp/bWAPP_latest.zip DEST=/src
COPY .cache/bWAPP_latest.zip /tmp/bWAPP_latest.zip
# tests/test_external_labs_static.py runs exactly this block (busybox sh) on temp files.
# VERIFY_BLOCK_BEGIN
RUN echo "${BWAPP_SHA256}  ${ZIP}" | sha256sum -c - \
 && mkdir -p "${DEST}" && cd "${DEST}" && unzip -q "${ZIP}" 'bWAPP/*' \
 && test -f "${DEST}/bWAPP/install.php"
# VERIFY_BLOCK_END

FROM mirror.gcr.io/library/php:5.6-apache@sha256:0a40fd273961b99d8afe69a61a68c73c04bc0caa9de384d3b2dd9e7986eec86d
# PA-0009: verify the extensions are usable in the same step.
RUN docker-php-ext-install mysql mysqli >/dev/null \
 && php -m | grep -qix mysqli && php -m | grep -qix mysql
COPY php-bwapp.ini /usr/local/etc/php/conf.d/zz-fuzzlab-bwapp.ini
COPY apache-root.conf /etc/apache2/conf-enabled/zz-fuzzlab-root.conf
RUN php -r 'exit(ini_get("mysqli.default_socket") === "/var/run/mysqld/mysqld.sock" && ini_get("mysql.default_socket") === "/var/run/mysqld/mysqld.sock" ? 0 : 1);'
COPY --from=fetch /src/bWAPP /var/www/html/bWAPP
# Runtime write locations (bWAPP source): passwords/, images/, documents/, logs/, db/
# (SQLite + journal), the app root (ssii.shtml) and its parent (crossdomain.xml).
RUN cd /var/www/html/bWAPP \
 && chown -R www-data:www-data passwords images documents logs db \
 && chown www-data:www-data /var/www/html/bWAPP /var/www/html
