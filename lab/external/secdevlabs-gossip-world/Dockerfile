# secDevLabs Gossip World at the pinned commit (CC-LAB-0305). Lab-only, loopback-only.
#
# The app comes from the gitignored .cache/app and its pinned Python distributions from
# .cache/dists, both filled on the host (`python -m fuzzlab.lab_fixtures.external fetch
# secdevlabs-gossip-world`; each distribution verified against PyPI's published sha256
# and the repo's pin). The build needs no network: --no-index, and the sdists build with
# the base image's own setuptools (--no-build-isolation) and MySQL headers.
FROM docker.io/library/python:3.8@sha256:d411270700143fa2683cc8264d9fa5d3279fd3b6afff62ae81ea2f9d070e390c
COPY .cache/dists /tmp/dists
RUN pip install --no-cache-dir --no-index --no-build-isolation --find-links /tmp/dists \
        Click==7.0 dominate==2.3.4 Flask==1.0.2 Flask-Bootstrap==3.3.7.1 Flask-Cors==3.0.7 \
        itsdangerous==1.1.0 Jinja2==2.10 MarkupSafe==1.1.0 mysqlclient==1.3.13 six==1.11.0 \
        visitor==0.1.3 Werkzeug==0.14.1 \
    && rm -rf /tmp/dists
COPY .cache/app/app /app
WORKDIR /app
USER nobody
CMD ["python", "routes.py"]
