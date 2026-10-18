# Google Security Crawl Maze at the pinned commit (CC-LAB-0302). Lab-only, loopback-only.
#
# Upstream's source (Apache-2.0) is never committed here: the host checks the pinned
# commit out into the gitignored .cache/src and downloads the Flask app's pinned wheels
# into .cache/wheels, each verified by sha256 (`python -m fuzzlab.lab_fixtures.external
# fetch security-crawl-maze`). The build needs no network: a build container may sit
# behind a TLS-intercepting proxy it does not trust.
#
# Upstream also builds three single-page-app test cases (Angular, Polymer, React) with
# 2021-era Node toolchains; they are not built here (CC-LAB-0302: 7 of the 91 expected
# resources, unreachable to every tool alike, `scripts/crawl_maze_score.py
# --exclude-prefix /javascript/frameworks`).

# Python 3.9: Flask 1.0.2 imports collections.MutableMapping (gone in 3.10); upstream ran 3.6.
FROM docker.io/library/python:3.9-slim@sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b
COPY .cache/wheels /tmp/wheels
RUN pip install --no-cache-dir --no-index --find-links /tmp/wheels Flask==1.0.2 \
        Werkzeug==1.0.1 Jinja2==2.11.3 MarkupSafe==2.0.1 itsdangerous==1.1.0 click==7.1.2 \
    && rm -rf /tmp/wheels
COPY .cache/src/app.py /usr/src/app/
COPY .cache/src/blueprints /usr/src/app/blueprints
COPY .cache/src/templates /usr/src/app/templates
COPY .cache/src/test-cases /usr/src/app/test-cases
USER nobody
CMD ["python", "/usr/src/app/app.py"]
