# Target-lab web tier: PHP + Apache serving the Puppy Fort Factory app.
#
# Pinned per decision D7 so labels stay valid across rebuilds. The tag pins the
# PHP/Apache/libxml versions; for full reproducibility pin to the image DIGEST
# (see lab/README.md — `docker inspect` the pulled image and replace the tag with
# `@sha256:...`). The app itself is bind-mounted at runtime (compose.yaml) so
# edits are live and the image stays generic.
FROM php:8.3-apache-bookworm

# mysqli for the app's database access. libxml ships with the base image (its
# version is part of what the pinned tag/digest locks, relevant to XML/entity
# behavior that affects some labels).
RUN docker-php-ext-install mysqli \
    && a2enmod rewrite

# Grey-box line coverage (Phase 3 T3.1): pcov, enabled but idle. The shim
# (includes/cov.php) only calls \pcov\start()/collect() when a request carries the
# X-Fzl-Cov header, so instrumented runs are opt-in and the default app is unchanged.
RUN pecl install pcov \
    && docker-php-ext-enable pcov \
    && { echo 'pcov.enabled=1'; echo 'pcov.directory=/var/www/html'; } \
       > /usr/local/etc/php/conf.d/zz-pcov.ini

# Global auto_prepend chain (decision D16 WAF + Phase 3 coverage). `auto_prepend_file`
# is single-valued, so both are chained through includes/prepend.php rather than each
# setting its own line (the last would silently win). Both self-gate: the WAF is a
# no-op unless PFF_WAF is on, and the coverage shim is a no-op unless X-Fzl-Cov is
# sent — so the default app and every existing ground-truth label are unchanged.
RUN printf 'auto_prepend_file=/var/www/html/includes/prepend.php\n' \
    > /usr/local/etc/php/conf.d/zz-pff-waf.ini

# Apache serves /var/www/html, where compose bind-mounts the app.
EXPOSE 80
