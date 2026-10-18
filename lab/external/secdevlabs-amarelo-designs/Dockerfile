# secDevLabs Amarelo Designs at the pinned commit (CC-LAB-0308). Lab-only,
# loopback-only. The app comes from the gitignored .cache/app and its pinned wheels
# from .cache/dists, both filled on the host (`python -m fuzzlab.lab_fixtures.external
# fetch secdevlabs-amarelo-designs`; each wheel verified against PyPI's published
# sha256 and the repo's pin). The build needs no network (--no-index).
FROM docker.io/library/python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
COPY .cache/dists /tmp/dists
RUN pip install --no-cache-dir --no-index --find-links /tmp/dists blinker==1.9.0 \
        click==8.5.0 flask==3.1.0 itsdangerous==2.2.0 jinja2==3.1.6 markupsafe==3.0.4 \
        werkzeug==3.1.9 \
    && rm -rf /tmp/dists
COPY .cache/app/app /app
WORKDIR /app
USER nobody
CMD ["python", "app.py"]
