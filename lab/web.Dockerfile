# Target-lab web tier: PHP + Apache serving the generated Laravel (`php_laravel`)
# lab app (`L-P3.3c-CUT` -- the atomic cutover onto the generator as the single
# source of the PHP target lab; retires the hand-built `puppy-fort-factory/`).
#
# Two stages: `gen` runs the real generator (`fuzzlab.labgen.assemble`, the same
# manifest-derived cell set the cutover coverage gate proves covers every
# non-exempted `PFF-` case) to assemble the app tree; the final stage is the
# php:8.3-apache image that serves it, pinned per decision D7 so labels stay
# valid across rebuilds (for full reproducibility, pin to image DIGESTs -- see
# lab/README.md's `./labctl.sh pin`).
#
# Build context is the REPO ROOT (see lab/compose.yaml's `build.context: ..`),
# not lab/, so the `gen` stage can see fuzzlab/ and lab/manifests/.

FROM python:3.12-slim AS gen
# CC-LAB-0247 (Lane 7, §2b): optional split-app selector, passed through to
# `assemble.py`'s own `--app` flag. Empty (the default) is byte-for-byte
# today's behavior -- the merged PFF build with every cell. A caller sets
# `--build-arg APP=circlefeed` (or `huddlehub`/`booking`) to build that
# split-out app instead (`fuzzlab.labgen.emitters.php_laravel.app_site.
# APP_REGISTRY`'s keys).
ARG APP=""
WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir -e . \
    && python3 -m fuzzlab.labgen.assemble --out /app $( [ -n "$APP" ] && echo "--app $APP" )

FROM php:8.3-apache-bookworm

# mysqli for the app's legacy DB helpers plus pdo_mysql for Laravel's own query
# builder (the migrated controllers go through DB::table()/DB::select(), which
# uses pdo_mysql). libxml ships with the base image (its version is part of
# what the pinned tag/digest locks, relevant to XML/entity behavior that
# affects some labels).
RUN docker-php-ext-install mysqli pdo_mysql \
    && a2enmod rewrite \
    && php -m | grep -qi '^mysqli$' \
    && php -m | grep -qi '^pdo_mysql$'    # fail the build if the app's DB exts didn't load (PA-0009)

# Grey-box line coverage (Phase 3 T3.1): pcov, enabled but idle. The
# FzlCoverage middleware (app/Http/Middleware/FzlCoverage.php, registered
# globally in bootstrap/app.php) only calls \pcov\start()/collect() when a
# request carries the X-Fzl-Cov header, so instrumented runs are opt-in and
# the default app is unchanged. $PHPIZE_DEPS (autoconf/gcc/make) is required
# to compile the PECL extension; without it `pecl install pcov` can no-op/fail
# and pcov never loads. The build verifies the extension is actually loadable
# so a broken layer fails the build, not a live run.
RUN apt-get update \
    && apt-get install -y --no-install-recommends $PHPIZE_DEPS unzip git \
    && pecl install pcov \
    && docker-php-ext-enable pcov \
    && { echo 'pcov.enabled=1'; echo 'pcov.directory=/var/www/html'; } \
       > /usr/local/etc/php/conf.d/zz-pcov.ini \
    && php -m | grep -qi '^pcov$'

# Composer, for the generated app's real `composer install` (Laravel's own
# framework dependencies -- the migrated app is not vendor-free like the
# hand-built one was).
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Laravel's document root is public/, and its own public/.htaccess (shipped
# in the skeleton) needs AllowOverride to take effect -- the base image's
# default vhost points at /var/www/html with AllowOverride None.
RUN { \
      echo '<Directory /var/www/html/public>'; \
      echo '  AllowOverride All'; \
      echo '  Require all granted'; \
      echo '</Directory>'; \
    } > /etc/apache2/conf-available/pff-laravel.conf \
    && a2enconf pff-laravel \
    && sed -ri 's!/var/www/html!/var/www/html/public!g' /etc/apache2/sites-available/*.conf

# The generated app tree (`fuzzlab.labgen.assemble`'s output -- every
# php_laravel cell the cutover coverage gate proves covers every
# non-exempted PFF- case, plus the checked-in Laravel skeleton).
COPY --from=gen --chown=www-data:www-data /app /var/www/html

RUN cd /var/www/html \
    && composer install --no-dev --no-interaction --no-progress --prefer-dist \
    && chown -R www-data:www-data storage bootstrap/cache \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 80
