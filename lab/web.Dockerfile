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

# Grey-box coverage (Phase 3) will add pcov/Xdebug here; left out for now so the
# base image is unchanged until instrumentation lands.

# Lab WAF (Phase 8 prerequisite, decision D16): a configurable, deliberately naive
# request prefilter wired globally via auto_prepend_file so no page needs editing.
# It is a no-op unless PFF_WAF is enabled at runtime, so the default app — and every
# existing ground-truth label — is unchanged. The file lives in the bind-mounted app.
RUN printf 'auto_prepend_file=/var/www/html/includes/waf.php\n' \
    > /usr/local/etc/php/conf.d/zz-pff-waf.ini

# Apache serves /var/www/html, where compose bind-mounts the app.
EXPOSE 80
