# secDevLabs Vinijr Blog at the pinned commit (CC-LAB-0307). Lab-only, loopback-only.
# The app and upstream's Apache/PHP configuration come from the gitignored .cache/app
# (`python -m fuzzlab.lab_fixtures.external fetch secdevlabs-vinijr-blog`); the build
# fetches nothing.
FROM mirror.gcr.io/library/php:8.3-apache@sha256:f8506a19d79cad7fcf0c8049f1ed2208824961018fdc10bd80f324094dcd36bd
COPY .cache/app/deployments/apache.conf /etc/apache2/sites-available/000-default.conf
COPY .cache/app/deployments/php.ini /usr/local/etc/php/
COPY .cache/app/app/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html && a2enmod rewrite
