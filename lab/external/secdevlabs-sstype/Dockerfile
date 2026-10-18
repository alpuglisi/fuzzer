# secDevLabs SSType at the pinned commit (CC-LAB-0306). Lab-only, loopback-only.
#
# The app comes from the gitignored .cache/app and its pinned wheel from .cache/dists,
# both filled on the host (`python -m fuzzlab.lab_fixtures.external fetch
# secdevlabs-sstype`; the wheel verified against PyPI's published sha256 and the
# repo's pin). The build needs no network (--no-index).
FROM docker.io/library/python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
COPY .cache/dists /tmp/dists
RUN pip install --no-cache-dir --no-index --find-links /tmp/dists tornado==6.4.2 \
    && rm -rf /tmp/dists
COPY .cache/app/src /usr/share/sstype/src
WORKDIR /usr/share/sstype
USER nobody
CMD ["python", "src/server.py"]
