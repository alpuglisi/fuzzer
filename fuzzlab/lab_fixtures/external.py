"""External lab fixtures: bWAPP and OWASP Juice Shop as loopback-only lab targets.

Component LAB (CC-LAB-0300, FR-LAB-300..304). The fixtures themselves are compose
projects under ``lab/external/<lab>/`` and are driven by ``lab/labctl.sh``, which hands
an external lab's lifecycle to ``lab/external/extctl.sh``. This module is the Python side
of that: the lab registry, the pinned upstream artefacts, the bWAPP download, the
compose pre-flight and the post-boot exposure check, and the bootstrap that brings a lab
to a usable state (bWAPP's installer, a Juice Shop account) and puts its lab identity in
the credential store.

Safety:

* **Loopback only.** A compose file whose resolved config publishes a port on anything
  but loopback, or uses the host's network/pid namespace, is refused before ``up``
  (:func:`config_problems`); after ``up`` every container of the project is inspected
  and the host's LISTEN table is read (:func:`exposure_problems`). Both fail closed.
* **Nothing is sent to a target without ``--authorized``** (D11). ``fetch`` downloads
  bWAPP's zip from its publisher and sends nothing to a lab.
* **Credentials** come from the credential store, the operator's gated env channel, or
  an interactive prompt -- never argv, logs or the repo -- and are written to the store
  only after a verified login (D12, PA-0007). The bootstrap client sends them only to
  the loopback base origin, follows no redirect and ignores proxy environment variables
  (PA-0082, PA-0098).
* **Licence.** bWAPP is CC BY-NC-ND: its zip is cached in a gitignored directory and
  never committed; the image build re-verifies its sha256.
"""

from __future__ import annotations

import argparse
import fcntl
import getpass
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urljoin, urlsplit

from fuzzlab.lab_fixtures.exclusions import CRAWL_EXCLUDE

REPO_ROOT = Path(__file__).resolve().parents[2]
EXTERNAL_DIR = REPO_ROOT / "lab" / "external"

# --- pinned upstream artefacts (the one source of truth; tests compare the Dockerfile and
# --- compose files against these, PA-0001) -------------------------------------------------
BUSYBOX_IMAGE = ("docker.io/library/busybox:1.37@sha256:"
                 "bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e")
PHP_IMAGE = ("mirror.gcr.io/library/php:5.6-apache@sha256:"
             "0a40fd273961b99d8afe69a61a68c73c04bc0caa9de384d3b2dd9e7986eec86d")
MYSQL_IMAGE = ("docker.io/library/mysql:5.7@sha256:"
               "4bc6bc963e6d8443453676cae56536f4b8156d78bae03c0145cbe47c2aad73bb")
JUICE_SHOP_IMAGE = ("docker.io/bkimminich/juice-shop:v20.3.0@sha256:"
                    "cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27")
CRAWL_MAZE_PYTHON_IMAGE = ("docker.io/library/python:3.9-slim@sha256:"
                           "2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b")
SECDEVLABS_GOLANG_IMAGE = ("docker.io/library/golang:1.14@sha256:"
                           "1a7173b5b9a3af3e29a5837e0b2027e1c438fd1b83bbee8f221355087ad416d6")
SECDEVLABS_MARIADB_IMAGE = ("docker.io/library/mariadb:10.6.3@sha256:"
                            "3b6f9fa1d406e168998d62501b2ee4f27d53138bebfcdac03540758996c5ff1d")
SECDEVLABS_PYTHON38_IMAGE = ("docker.io/library/python:3.8@sha256:"
                             "d411270700143fa2683cc8264d9fa5d3279fd3b6afff62ae81ea2f9d070e390c")
#: sstype's upstream Dockerfile says `python:3` and its requirements `tornado`, both
#: unpinned: pinned here to the releases current when the fixture was built.
SECDEVLABS_PYTHON312_IMAGE = ("docker.io/library/python:3.12-slim@sha256:"
                              "a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1")
#: vinijr-blog's upstream base is `php:apache` (unpinned): pinned to 8.3, from Google's
#: Docker Hub mirror (as bWAPP's PHP_IMAGE; Docker Hub rate-limits this host).
SECDEVLABS_PHP_IMAGE = ("mirror.gcr.io/library/php:8.3-apache@sha256:"
                        "f8506a19d79cad7fcf0c8049f1ed2208824961018fdc10bd80f324094dcd36bd")
#: mongection's upstream bases are `node` and `mongo` (unpinned): Node 20 and MongoDB
#: 4.4 (Mongoose 5's driver era), from Google's Docker Hub mirror.
SECDEVLABS_NODE20_IMAGE = ("mirror.gcr.io/library/node:20-alpine@sha256:"
                           "fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293")
SECDEVLABS_NODE13_IMAGE = ("docker.io/library/node:13.12.0-alpine@sha256:"
                           "cc85e728fab3827ada20a181ba280cae1f8b625f256e2c86b9094d9bfe834766")
SECDEVLABS_MONGO_IMAGE = ("mirror.gcr.io/library/mongo:4.4@sha256:"
                          "4be76f674fc4b27859816811b8baa3c51830eb1dbf4ca81a51e26b79edd662ef")
#: streaming's upstream bases: `maven:3.6.0-jdk-11-slim` builds the backend (and, here,
#: runs it: upstream's `openjdk:8-jdk-alpine` is not on Google's mirror; Spring Boot
#: 2.3 runs on Java 11) and `nginx:1.17.1-alpine` serves the page, both from the mirror.
SECDEVLABS_MAVEN_IMAGE = ("mirror.gcr.io/library/maven:3.6.0-jdk-11-slim@sha256:"
                          "4f0face24d2f79439a8fa394555b09be99c9ad537b9b19983fb8cc358818a42d")
SECDEVLABS_NGINX_IMAGE = ("mirror.gcr.io/library/nginx:1.17.1-alpine@sha256:"
                          "17bd1698318e9c0f9ba2c5ed49f53d690684dab7fe3e8019b855c352528d57be")
#: OWASP NodeGoat's upstream Dockerfile says `node:12-alpine` (unpinned): pinned here, from
#: Google's Docker Hub mirror (CC-LAB-0330). Its database is SECDEVLABS_MONGO_IMAGE
#: (upstream's compose says `mongo:4.4`).
NODEGOAT_NODE12_IMAGE = ("mirror.gcr.io/library/node:12-alpine@sha256:"
                         "d4b15b3d48f42059a15bd659be60afe21762aae9d6cbea6f124440895c27db68")
#: SasanLabs OWASP VulnerableApp 2.2.115 (Spring Boot, Java 17; CC-LAB-0350), built by
#: upstream from commit 821b347 (2026-11-19): pinned by the digest its tag resolved to.
VULNERABLEAPP_IMAGE = ("docker.io/sasanlabs/owasp-vulnerableapp:2.2.115@sha256:"
                       "160bdbdf0490e27a5904d496c4a13b5e1541957dc4df5d05c611b1caec3b0193")
#: OWASP Mutillidae II (CC-LAB-0340): upstream's own published images
#: (webpwnized/mutillidae-docker), the app 2.12.8 on PHP 8.5 / Apache, MariaDB 13 and
#: OpenLDAP 2.4, pinned by digest.
MUTILLIDAE_WWW_IMAGE = ("docker.io/webpwnized/mutillidae:www@sha256:"
                        "90d0cc2279e22592f993680775aff8da743a01191c73d2fabbf766f7ebde56b7")
MUTILLIDAE_DATABASE_IMAGE = ("docker.io/webpwnized/mutillidae:database@sha256:"
                             "5569286c0d4bc3436f28e91c2c029613910c02cd440ccd9e39dc11dddee9e6ec")
MUTILLIDAE_LDAP_IMAGE = ("docker.io/webpwnized/mutillidae:ldap@sha256:"
                         "bc98847a4cc53fff691b68e2e5b9358f00c3a2ef4ae4985e899ef8a7cf3116cf")
#: Damn Vulnerable GraphQL Application (dolevf, MIT), CC-LAB-0320: the `latest` build of
#: 2025-05-24 (its version.py says 2.1.2; the older `2.1.2` tag is another, 2022 build).
DVGA_IMAGE = ("docker.io/dolevf/dvga:latest@sha256:"
              "040aa33c199d99f3380c9ff9a1ee5d725e9abca7b189c63a35a2a73bda79c957")
PINNED_IMAGES = frozenset({BUSYBOX_IMAGE, MUTILLIDAE_WWW_IMAGE, MUTILLIDAE_DATABASE_IMAGE,
                           MUTILLIDAE_LDAP_IMAGE, PHP_IMAGE, MYSQL_IMAGE, JUICE_SHOP_IMAGE,
                           CRAWL_MAZE_PYTHON_IMAGE, SECDEVLABS_GOLANG_IMAGE,
                           SECDEVLABS_MARIADB_IMAGE, SECDEVLABS_PYTHON38_IMAGE,
                           SECDEVLABS_PYTHON312_IMAGE, SECDEVLABS_PHP_IMAGE,
                           SECDEVLABS_NODE20_IMAGE, SECDEVLABS_MONGO_IMAGE,
                           SECDEVLABS_NODE13_IMAGE, SECDEVLABS_MAVEN_IMAGE,
                           SECDEVLABS_NGINX_IMAGE, NODEGOAT_NODE12_IMAGE, DVGA_IMAGE,
                           VULNERABLEAPP_IMAGE})

BWAPP_ZIP_URL = "https://sourceforge.net/projects/bwapp/files/bWAPP/bWAPP_latest.zip/download"
BWAPP_ZIP_NAME = "bWAPP_latest.zip"
BWAPP_ZIP_SHA256 = "87b5363062b4be9d2aa91916f6396f0f7d56e8acca08b732440e863f8c9e4cd6"
BWAPP_ZIP_SIZE = 15_058_349

#: Google's Security Crawl Maze (a crawler-coverage testbed: each page links one
#: resource one way, ``*.found`` expected), built from this pinned commit.
CRAWL_MAZE_REPO = "https://github.com/google/security-crawl-maze"
CRAWL_MAZE_COMMIT = "2a0dd0a75e39925ded887bcd25016e8b3ce0f2b3"
#: Its Flask app's dependencies for the image's Python (3.9: Flask 1.0.2 needs a Python
#: before 3.10's `collections` change, as upstream's own 3.6), fetched on the host and
#: installed offline by the build (a build container may sit behind a TLS-intercepting
#: proxy it does not trust), each verified by sha256.
CRAWL_MAZE_WHEELS = {
    "Flask-1.0.2-py2.py3-none-any.whl":
        "a080b744b7e345ccfcbc77954861cb05b3c63786e93f2b3875e0913d44b43f05",
    "Werkzeug-1.0.1-py2.py3-none-any.whl":
        "2de2a5db0baeae7b2d2664949077c2ac63fbd16d98da0ff71837f7d1dea3fd43",
    "Jinja2-2.11.3-py2.py3-none-any.whl":
        "03e47ad063331dd6a3f04a43eddca8a966a26ba0c5b7207a9a9e4e08f1b29419",
    ("MarkupSafe-2.0.1-cp39-cp39-manylinux_2_5_x86_64.manylinux1_x86_64."
     "manylinux_2_12_x86_64.manylinux2010_x86_64.whl"):
        "1f2ade76b9903f39aa442b4aadd2177decb66525062db244b35d71d0ee8599b6",
    "itsdangerous-1.1.0-py2.py3-none-any.whl":
        "b12271b2047cb23eeb98c8b5622e2e5c5e9abd9784a153e9d8ef9cb4dd09d749",
    "click-7.1.2-py2.py3-none-any.whl":
        "dacca89f4bfadd5de3d7489b7c8a566eee0d3676333fbb50030263894c38c0dc",
}

#: Mutillidae's directory starts empty; upstream's README loads this LDIF (its rooms
#: and users) with ``ldapadd``. Fetched on the host from the pinned commit of
#: webpwnized/mutillidae-docker, verified by sha256 and size (CC-LAB-0340).
MUTILLIDAE_DOCKER_COMMIT = "b5920113ad30dd92c893b2f44230fb5bf99f3601"
MUTILLIDAE_LDIF_URL = ("https://raw.githubusercontent.com/webpwnized/mutillidae-docker/"
                       f"{MUTILLIDAE_DOCKER_COMMIT}/.build/ldap/configuration/ldif/"
                       "mutillidae.ldif")
MUTILLIDAE_LDIF_SHA256 = "82eb3b46b63463f978f887d5a427e96af7058d005e5449a1420bdd574c16d2e5"
MUTILLIDAE_LDIF_SIZE = 2165
#: The directory's admin bind: upstream's published default, baked into its LDAP image
#: (LDAP_ADMIN_PASSWORD) and its www image (includes/ldap-config.inc); not a secret of
#: ours (the directory is on an internal network and never published).
MUTILLIDAE_LDAP_BIND = ("cn=admin,dc=mutillidae,dc=localhost", "mutillidae")

LAB_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
PROJECT_LABEL = "com.docker.compose.project"


#: secDevLabs (globocom, BSD-3-Clause), CC-LAB-0303: a suite of small deliberately
#: vulnerable apps, one external lab per app. The source is checked out at this commit
#: on the host and each app's dependencies are fetched and verified there (the build
#: containers sit behind a TLS-intercepting proxy they do not trust); images build
#: offline.
SECDEVLABS_REPO = "https://github.com/globocom/secDevLabs"
SECDEVLABS_COMMIT = "10be438496e928c66567749f0aaf0bb976052bc9"
#: lab name -> the app's directory in the pinned checkout.
SECDEVLABS_APPS = {
    "secdevlabs-copy-n-paste": "owasp-top10-2021-apps/a3/copy-n-paste",
    "secdevlabs-gossip-world": "owasp-top10-2021-apps/a3/gossip-world",
    "secdevlabs-sstype": "owasp-top10-2021-apps/a3/sstype",
    "secdevlabs-vinijr-blog": "owasp-top10-2021-apps/a5/vinijr-blog",
    "secdevlabs-amarelo-designs": "owasp-top10-2021-apps/a8/amarelo-designs",
    "secdevlabs-mongection": "owasp-top10-2021-apps/a3/mongection",
    "secdevlabs-comment-killer": "owasp-top10-2021-apps/a3/comment-killer",
    "secdevlabs-streaming": "owasp-top10-2021-apps/a3/streaming",
    "secdevlabs-ecommerce-api": "owasp-top10-2021-apps/a1/ecommerce-api",
}
#: lab name -> why its npm lockfiles are not installed: the image serves the bundle the
#: repository ships, checked against the source it was built from (CC-LAB-0314).
SECDEVLABS_PREBUILT = {
    "secdevlabs-streaming": "serves app/frontend/dist (the repo's Angular build; its "
                            "chat sinks and API calls match src/app/lives)",
}
#: lab name -> the Python distributions its image installs offline (`fetch_pypi_dists`):
#: the app's own requirements.txt pins, each file's sha256 as PyPI publishes it.
SECDEVLABS_PYPI = {
    # upstream's requirements say `flask` (unpinned): Flask 3.1.0 and its dependencies
    "secdevlabs-amarelo-designs": {
        "blinker-1.9.0-py3-none-any.whl":
            "ba0efaa9080b619ff2f3459d1d500c57bddea4a6b424b60a91141db6fd2f08bc",
        "click-8.5.0-py3-none-any.whl":
            "255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360",
        "flask-3.1.0-py3-none-any.whl":
            "d667207822eb83f1c4b50949b1623c8fc8d51f2341d65f72e1a1815397551136",
        "itsdangerous-2.2.0-py3-none-any.whl":
            "c6242fc49e35958c8b15141343aa660db5fc54d4f13a1db01a3f5891b98700ef",
        "jinja2-3.1.6-py3-none-any.whl":
            "85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67",
        ("markupsafe-3.0.4-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64."
         "manylinux_2_28_x86_64.whl"):
            "8e124f974786f831d6043728e38296969d3579db8896fe004682f5758e613581",
        "werkzeug-3.1.9-py3-none-any.whl":
            "6392e50c78460ba618e5b21f08a71f59c99ce99cdc6cf6e3dd7e6ccca8754fab",
    },
    "secdevlabs-sstype": {
        ("tornado-6.4.2-cp38-abi3-manylinux_2_5_x86_64.manylinux1_x86_64."
         "manylinux_2_17_x86_64.manylinux2014_x86_64.whl"):
            "bca9eb02196e789c9cb5c3c7c0f04fb447dc2adffd95265b2c7223a8a615ccbf",
    },
    "secdevlabs-gossip-world": {
        "Click-7.0-py2.py3-none-any.whl":
            "2335065e6395b9e67ca716de5f7526736bfa6ceead690adf616d925bdc622b13",
        "dominate-2.3.4-py2.py3-none-any.whl":
            "59abf22fe4072a97978afece563155279b3c3d6f26cb9fbbca28d0acc318cb1b",
        "Flask-1.0.2-py2.py3-none-any.whl":
            "a080b744b7e345ccfcbc77954861cb05b3c63786e93f2b3875e0913d44b43f05",
        "Flask-Bootstrap-3.3.7.1.tar.gz":
            "cb08ed940183f6343a64e465e83b3a3f13c53e1baabb8d72b5da4545ef123ac8",
        "Flask_Cors-3.0.7-py2.py3-none-any.whl":
            "7ad56ee3b90d4955148fc25a2ecaa1124fc84298471e266a7fea59aeac4405a5",
        "itsdangerous-1.1.0-py2.py3-none-any.whl":
            "b12271b2047cb23eeb98c8b5622e2e5c5e9abd9784a153e9d8ef9cb4dd09d749",
        "Jinja2-2.10-py2.py3-none-any.whl":
            "74c935a1b8bb9a3947c50a54766a969d4846290e1e788ea44c1392163723c3bd",
        "MarkupSafe-1.1.0.tar.gz":
            "4e97332c9ce444b0c2c38dd22ddc61c743eb208d916e4265a2a3b575bdccb1d3",
        "mysqlclient-1.3.13.tar.gz":
            "ff8ee1be84215e6c30a746b728c41eb0701a46ca76e343af445b35ce6250644f",
        "six-1.11.0-py2.py3-none-any.whl":
            "832dc0e10feb1aa2c68dcc57dbb658f1c7e65b9b61af69048abc87a2db00a0eb",
        "visitor-0.1.3.tar.gz":
            "2c737903b2b6864ebc6167eef7cf3b997126f1aa94bdf590f90f1436d23e480a",
        "Werkzeug-0.14.1-py2.py3-none-any.whl":
            "d5da73735293558eb1651ee2fddc4d0dedcfa06538b8813a2e20011583c9e49b",
    },
}


#: OWASP NodeGoat (Apache-2.0), CC-LAB-0330: a Node.js / Express / MongoDB app with
#: server-side JavaScript injection (``eval`` of form inputs, a ``$where`` built from a
#: query value). Checked out at this commit on the host; the checkout's tracked files
#: must hash to NODEGOAT_TREE_SHA256 (`tree_sha256`); its production npm packages are
#: installed on the host by ``npm ci`` against the lockfile; the image builds offline.
NODEGOAT_REPO = "https://github.com/OWASP/NodeGoat"
NODEGOAT_COMMIT = "c5cb68a7084e4ae7dcc60e6a98768720a81841e8"
NODEGOAT_TREE_SHA256 = "78ac112b7bd5083bb065086c4642dcd8a3932a8d3052f9405503124c90a70fe3"

#: VAmPI, the Vulnerable API (erev0s/VAmPI, MIT; held out, lab/HOLDOUT.md): upstream's own
#: Docker Hub build, pinned by digest. Its /vampi tree is byte for byte VAMPI_COMMIT (the
#: image was created 39 s after that merge, by upstream's docker-image workflow).
VAMPI_IMAGE = ("docker.io/erev0s/vampi:latest@sha256:"
               "0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12")
VAMPI_COMMIT = "f16052dce83f05847133ec98f01c5193a41de7d8"
PINNED_IMAGES = PINNED_IMAGES | {VAMPI_IMAGE}

#: DVWS-node (snoopysecurity, MIT), a held-out lab (lab/HOLDOUT.md): Node 22 / Express
#: REST, SOAP, XML-RPC and GraphQL on one port over MongoDB and MySQL. Checked out at
#: this commit (its tracked files hashing to DVWS_NODE_TREE_SHA256), its locked npm
#: packages (backend production set, frontend build set) installed on the host by
#: ``npm ci``; the image builds its Svelte frontend and compiles bcrypt with no network.
#: Upstream's Dockerfile says `node:22` (unpinned): pinned here, from Google's mirror.
#: Its databases reuse SECDEVLABS_MONGO_IMAGE (upstream: mongo:4.0.4) and MYSQL_IMAGE
#: (upstream: mysql:8).
DVWS_NODE_REPO = "https://github.com/snoopysecurity/dvws-node"
DVWS_NODE_COMMIT = "4221c04f132960a0ccca4bf5aa5f3a9f53172778"
DVWS_NODE_TREE_SHA256 = "64de72b151f76eb598642bd7a0ed1e9f3413684ae725bda9f2e47a69216805f7"
DVWS_NODE22_IMAGE = ("mirror.gcr.io/library/node:22-bookworm@sha256:"
                     "e13726ca604184d7a91fcacab1fc09eefd642dc28e79ac34e85540dd93b78cfb")
PINNED_IMAGES = PINNED_IMAGES | {DVWS_NODE22_IMAGE}
#: OWASP RailsGoat (MIT), held out (lab/HOLDOUT.md): a Ruby on Rails 8 app. Checked out at
#: this commit on the host (tracked files hashing to RAILSGOAT_TREE_SHA256); every gem is
#: downloaded on the host and checked against its Gemfile.lock CHECKSUMS sha256
#: (`fetch_railsgoat_gems`), and the bundler the lock names against rubygems.org's
#: published sha256; the image installs them with no network. The base is the Ruby its
#: .ruby-version and upstream's Dockerfile name (`ruby:3.4.1`), pinned here.
RAILSGOAT_REPO = "https://github.com/OWASP/railsgoat"
RAILSGOAT_COMMIT = "f5951f13089d85c979de09e7da3c8c0fb982f94a"
RAILSGOAT_TREE_SHA256 = "fe89ec5d5dfec1075ae8bf1e72815e3def44d3d488c845b9ec4af184e1590e03"
RAILSGOAT_RUBY_IMAGE = ("mirror.gcr.io/library/ruby:3.4.1@sha256:"
                        "f78dc1bba60f85d40d6dc6d6722ca2cda0b5273fc179119badd0f7654d5d1d6e")
RAILSGOAT_BUNDLER_GEM = ("bundler-4.0.4.gem",
                         "d0f94b7ba176666896318e419f9a0cc55b698874bffec64cc33537611c61bd16")
#: the lock's platforms the image (x86_64 glibc) can install
RAILSGOAT_GEM_PLATFORMS = frozenset({"ruby", "x86_64-linux", "x86_64-linux-gnu"})
PINNED_IMAGES = PINNED_IMAGES | {RAILSGOAT_RUBY_IMAGE}


class ExternalLabError(RuntimeError):
    """A fixture operation failed; the message never carries a secret."""


@dataclass(frozen=True)
class LabMeta:
    """What compose cannot hold about a lab."""
    name: str
    #: The compose service that publishes the app's port.
    service: str
    port_env: str
    default_port: int
    container_port: int
    #: Where the app lives on its origin (bWAPP is served under a sub-path).
    app_path: str
    #: Any HTTP answer here means the web tier is up (PA-0050).
    ready_path: str
    #: None for a lab without a login (nothing to bootstrap).
    identity: str | None
    default_username: str
    #: A password may be generated when none is supplied (the account is ours to create).
    may_generate_password: bool
    #: More accounts the lab needs, ``(identity, default username)`` each, created and
    #: verified by the lab's own bootstrap like the first and stored under their own
    #: identity: a second user for a cross-account access check (FR-LAB-307).
    extra_identities: tuple[tuple[str, str], ...] = ()
    #: More published ports, ``(host port, container port)``, fixed because the app's own
    #: code names them (a page that calls its API at ``http://localhost:10017``): its
    #: second origin, still loopback only (FR-LAB-308).
    fixed_ports: tuple[tuple[int, int], ...] = ()
    #: URL path/query patterns (`core.urls.compile_exclusions`) a crawl of this lab
    #: must never load: GET routes that change the lab's state for everything after them
    #: and that no generic rule can tell apart (FR-LAB-410, `--exclude-lab`). Fixture
    #: knowledge, never detection logic (PA-0660).
    crawl_exclude: tuple[str, ...] = ()

    def accounts(self) -> list["LabMeta"]:
        """This lab's metadata once per account (the first, then each extra one)."""
        if self.identity is None:
            return []
        return [self] + [replace(self, identity=ident, default_username=user,
                                 extra_identities=())
                         for ident, user in self.extra_identities]


LAB_META: dict[str, LabMeta] = {
    "bwapp": LabMeta("bwapp", "web", "BWAPP_PORT", 8092, 80, "/bWAPP/", "/bWAPP/login.php",
                     "bwapp-bee", "bee", False),
    "juice-shop": LabMeta("juice-shop", "app", "JUICE_PORT", 3000, 3000, "/",
                          "/rest/admin/application-version", "juice-user",
                          "juice-user@fuzzlab.lab", True),
    "security-crawl-maze": LabMeta("security-crawl-maze", "app", "CRAWLMAZE_PORT", 3061,
                                   8080, "/", "/", None, "", False),
    "secdevlabs-copy-n-paste": LabMeta("secdevlabs-copy-n-paste", "api", "SDL_CNP_PORT",
                                       3071, 10001, "/", "/healthcheck", None, "", False),
    # its bundle calls the API at a hard-coded http://localhost:10017: a fixed second port
    "secdevlabs-comment-killer": LabMeta("secdevlabs-comment-killer", "app", "SDL_CK_PORT",
                                         3074, 3000, "/", "/", None, "", False,
                                         fixed_ports=((10017, 10017),)),
    # two accounts: `/ticket/:id` hands any caller the ticket of the account whose
    # userID is in the path (FR-LAB-309); its page logs in at a hard-coded
    # //localhost:10005: a fixed second port (FR-SESS-21)
    "secdevlabs-ecommerce-api": LabMeta("secdevlabs-ecommerce-api", "api",
                                        "SDL_ECOMMERCE_PORT", 3079, 10005, "/",
                                        "/healthcheck", "sdl-ecommerce-user", "fuzzlab_user",
                                        True, (("sdl-ecommerce-peer", "fuzzlab_peer"),),
                                        fixed_ports=((10005, 10005),)),
    # its bundle calls the backend at a hard-coded http://localhost:8080
    "secdevlabs-streaming": LabMeta("secdevlabs-streaming", "frontend", "SDL_STREAMING_PORT",
                                    3078, 80, "/", "/", None, "", False,
                                    fixed_ports=((8080, 8080),)),
    # one account: the flaw (`$ne` in both login fields) answers an account, so a fresh
    # lab (its database on tmpfs) needs one to be measurable (BUG-0640, FR-LAB-360)
    "secdevlabs-mongection": LabMeta("secdevlabs-mongection", "server", "SDL_MONGECTION_PORT",
                                     3077, 10001, "/", "/", "sdl-mongection-user",
                                     "fuzzlab_user@fuzzlab.lab", True),
    "secdevlabs-amarelo-designs": LabMeta("secdevlabs-amarelo-designs", "app",
                                          "SDL_AMARELO_PORT", 3076, 5000, "/", "/", None,
                                          "", False),
    "secdevlabs-vinijr-blog": LabMeta("secdevlabs-vinijr-blog", "app", "SDL_VINIJR_PORT",
                                      3075, 80, "/", "/", None, "", False),
    "secdevlabs-sstype": LabMeta("secdevlabs-sstype", "server", "SDL_SSTYPE_PORT", 3073,
                                 10001, "/", "/", None, "", False),
    # its pages are query-routed (index.php?page=...); an account of our own, registered
    # by the bootstrap (FR-LAB-341)
    "mutillidae": LabMeta("mutillidae", "www", "MUTILLIDAE_PORT", 3093, 80, "/",
                          "/index.php?page=login.php", "mutillidae-user", "fuzzlab_user",
                          True),
    "secdevlabs-gossip-world": LabMeta("secdevlabs-gossip-world", "app", "SDL_GOSSIP_PORT",
                                       3072, 10007, "/", "/login", "sdl-gossip-user",
                                       "fuzzlab_user", True,
                                       (("sdl-gossip-peer", "fuzzlab_peer"),)),
    # two of upstream's seeded accounts (artifacts/db-reset.js, re-seeded at every start;
    # their passwords are the ones NodeGoat's README publishes): `/allocations/:userId`
    # shows any caller the allocations of the userId in the path (FR-LAB-330)
    "nodegoat": LabMeta("nodegoat", "web", "NODEGOAT_PORT", 3091, 4000, "/", "/login",
                        "nodegoat-user", "user1", False, (("nodegoat-peer", "user2"),)),
    # GraphQL over one endpoint (FR-LAB-320); no account: its resolvers take no session
    # its crawl exclusions live in `lab_fixtures.exclusions` (FR-LAB-410)
    "dvga": LabMeta("dvga", "app", "DVGA_PORT", 5013, 5013, "/", "/", None, "", False,
                    crawl_exclude=CRAWL_EXCLUDE["dvga"]),
    # a Spring Boot app under the /VulnerableApp context path; no login (CC-LAB-0350);
    # 3095, not 3093, which lane PHPX's Mutillidae publishes (CC-LAB-0353)
    "vulnerableapp": LabMeta("vulnerableapp", "app", "VAPP_PORT", 3095, 9090,
                             "/VulnerableApp/", "/VulnerableApp/allEndPointJson", None, "",
                             False),
    # held out (lab/HOLDOUT.md): a JSON REST API with JWT bearer auth; two accounts of our
    # own, each owning one book: `/books/v1/{book_title}` shows any logged-in caller
    # another account's book secret
    "vampi": LabMeta("vampi", "app", "VAMPI_PORT", 3101, 5000, "/", "/", "vampi-user",
                     "fuzzlab_user", True, (("vampi-peer", "fuzzlab_peer"),)),
    # held out (lab/HOLDOUT.md): REST, SOAP, XML-RPC and GraphQL on one port; two
    # accounts of our own, registered by the bootstrap (a JWT from POST /api/v2/login)
    "dvws-node": LabMeta("dvws-node", "web", "DVWS_PORT", 3102, 8080, "/", "/",
                         "dvws-user", "fuzzlab_user", True, (("dvws-peer", "fuzzlab_peer"),)),
    # held out (lab/HOLDOUT.md): two of upstream's seeded accounts (db/seeds.rb, re-seeded
    # at every start; the app's own /tutorials/credentials page publishes their
    # passwords): `/users/:user_id/work_info` shows any caller the user_id in the path
    "railsgoat": LabMeta("railsgoat", "web", "RAILSGOAT_PORT", 3103, 3000, "/", "/login",
                         "railsgoat-user", "ken@metacorp.com", False,
                         (("railsgoat-peer", "mike@metacorp.com"),)),
}


# --- registry -------------------------------------------------------------------------

def discover_labs(root: Path = EXTERNAL_DIR) -> dict[str, Path]:
    """``{lab name: compose file}`` for every ``<root>/<name>/compose.yaml`` -- the
    registry is the directory layout (PA-0059(2)); ``extctl.sh`` derives it the same way."""
    out: dict[str, Path] = {}
    if not root.is_dir():
        return out
    for d in sorted(root.iterdir()):
        compose = d / "compose.yaml"
        if d.is_dir() and LAB_NAME_RE.match(d.name) and compose.is_file():
            out[d.name] = compose
    return out


def compose_project(compose_file: Path) -> str:
    """The compose file's top-level ``name:`` (the project name)."""
    for line in compose_file.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^name:\s*([A-Za-z0-9_-]+)\s*$", line)
        if m:
            return m.group(1)
    raise ExternalLabError(f"{compose_file}: no top-level `name:`")


def lab_meta(name: str, root: Path = EXTERNAL_DIR) -> LabMeta:
    if not LAB_NAME_RE.match(name or "") or name not in discover_labs(root):
        raise ExternalLabError(f"unknown external lab {name!r} (known: "
                               f"{', '.join(discover_labs(root)) or 'none'})")
    if name not in LAB_META:
        raise ExternalLabError(f"external lab {name!r} has no LAB_META entry")
    return LAB_META[name]


def lab_port(meta: LabMeta, environ: Mapping[str, str] | None = None) -> int:
    env = os.environ if environ is None else environ
    raw = env.get(meta.port_env, "") or str(meta.default_port)
    if not raw.isdigit() or not 0 < int(raw) < 65536:
        raise ExternalLabError(f"{meta.port_env} must be a port number, got {raw!r}")
    return int(raw)


def base_url(meta: LabMeta, environ: Mapping[str, str] | None = None) -> str:
    """The lab's origin. Always ``127.0.0.1`` (the credential store keys by bare host;
    ``localhost`` would miss the stored identity)."""
    return f"http://127.0.0.1:{lab_port(meta, environ)}"


# --- bWAPP download -------------------------------------------------------------------

def cache_path(root: Path = EXTERNAL_DIR) -> Path:
    return root / "bwapp" / ".cache" / BWAPP_ZIP_NAME


def _sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def fetch_bwapp(*, session: Any = None, dest: Path | None = None, timeout: float = 120.0,
                max_hops: int = 5, url: str = BWAPP_ZIP_URL,
                sha256: str = BWAPP_ZIP_SHA256, size: int = BWAPP_ZIP_SIZE) -> Path:
    """Download bWAPP's zip to the gitignored cache, verified by sha256 and size.

    An existing cached file is re-hashed, never trusted. Redirects (SourceForge hands
    the download to a mirror) are followed by hand, https only, at most ``max_hops``.
    This is an anonymous public download, so the host's own proxy/CA environment
    applies. On any mismatch the partial file is removed and ``ExternalLabError``
    raised -- never a substitute.

    One fetch runs at a time per cache directory (an exclusive ``flock`` on the
    directory itself): the stale-part sweep and the cache check would otherwise race a
    concurrent fetch, e.g. an operator's ``up bwapp`` beside a live test."""
    dest = cache_path() if dest is None else dest
    if dest.exists() and not dest.is_file():
        raise ExternalLabError(f"{dest} exists and is not a file")
    dest.parent.mkdir(parents=True, exist_ok=True)
    lock = os.open(dest.parent, os.O_RDONLY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _fetch_locked(session=session, dest=dest, timeout=timeout,
                             max_hops=max_hops, url=url, sha256=sha256, size=size)
    finally:
        os.close(lock)                          # releases the lock


def crawl_maze_source(root: Path = EXTERNAL_DIR) -> Path:
    """Where the Crawl Maze's pinned source is checked out (gitignored)."""
    return root / "security-crawl-maze" / ".cache" / "src"


def dist_project(filename: str) -> tuple[str, str]:
    """``(project, version)`` of a wheel or sdist file name (PEP 427 / sdist naming)."""
    if filename.endswith(".whl"):
        parts = filename.split("-")
        return parts[0], parts[1]
    for ext_ in (".tar.gz", ".zip", ".tar.bz2"):
        if filename.endswith(ext_):
            project, _, version = filename[:-len(ext_)].rpartition("-")
            return project, version
    raise ExternalLabError(f"{filename}: not a wheel or sdist name")


def _pypi_get(url: str, timeout: float) -> bytes:
    import urllib.request
    with urllib.request.urlopen(url, timeout=timeout) as resp:      # verified TLS
        return resp.read()


def fetch_pypi_dists(pins: Mapping[str, str], dest: Path, *, timeout: float = 600.0,
                     get=_pypi_get) -> Path:
    """Download each pinned distribution (``{file name: sha256}``) from PyPI into
    ``dest`` on the host (the host's proxy and CA environment apply), so an image can
    install them with no network. PyPI's own published digest must equal the pin, and
    the bytes must hash to it; a cached file is re-hashed, never trusted; a mismatch
    leaves nothing behind and raises."""
    import hashlib
    import json as _json
    dest.mkdir(parents=True, exist_ok=True)

    def ok(name: str) -> bool:
        path = dest / name
        return path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == pins[name]

    for name, digest in pins.items():
        if ok(name):
            continue
        (dest / name).unlink(missing_ok=True)       # a mismatched copy never stays
        project, version = dist_project(name)
        try:
            meta = _json.loads(get(f"https://pypi.org/pypi/{project}/{version}/json",
                                   timeout))
            entry = next(u for u in meta.get("urls", []) if u.get("filename") == name)
            if entry.get("digests", {}).get("sha256") != digest:
                raise ExternalLabError(f"{name}: PyPI publishes another sha256 than the pin")
            data = get(entry["url"], timeout)
        except ExternalLabError:
            raise
        except (OSError, ValueError, StopIteration, KeyError) as exc:
            raise ExternalLabError(f"{name}: download failed ({type(exc).__name__})") from None
        if hashlib.sha256(data).hexdigest() != digest:
            raise ExternalLabError(f"{name}: sha256 mismatch after download")
        tmp = dest / (name + ".part")
        tmp.write_bytes(data)
        tmp.replace(dest / name)
    for name in pins:
        if not ok(name):
            (dest / name).unlink(missing_ok=True)
            raise ExternalLabError(f"{name}: sha256 mismatch or missing after download")
    return dest


def fetch_crawl_maze_wheels(*, dest: Path | None = None, timeout: float = 600.0,
                            wheels: Mapping[str, str] | None = None, get=_pypi_get) -> Path:
    """The Crawl Maze image's pinned wheels in the gitignored cache (`fetch_pypi_dists`)."""
    return fetch_pypi_dists(CRAWL_MAZE_WHEELS if wheels is None else wheels,
                            crawl_maze_source().parent / "wheels" if dest is None else dest,
                            timeout=timeout, get=get)


def checkout_pinned(dest: Path, repo: str, commit: str, *, timeout: float = 600.0,
                    label: str = "checkout") -> Path:
    """Check ``repo`` out at ``commit`` into ``dest`` (gitignored cache). A checkout
    already at ``commit`` is kept; anything else there is replaced. The checkout's HEAD
    is verified -- never a substitute."""
    import shutil
    import subprocess

    from fuzzlab.procutil import run_bounded

    def git(*args: str) -> str:
        res = run_bounded(["git", "-C", str(dest), *args], timeout=timeout)
        if res.returncode != 0:
            raise ExternalLabError(f"git {args[0]} failed: {(res.stderr or '').strip()[:200]}")
        return res.stdout.strip()

    if (dest / ".git").is_dir():
        try:
            if git("rev-parse", "HEAD") == commit:
                return dest
        except ExternalLabError:
            pass
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    try:
        git("init", "-q")
        git("remote", "add", "origin", repo)
        git("fetch", "-q", "--depth", "1", "origin", commit)
        git("checkout", "-q", "--detach", "FETCH_HEAD")
        head = git("rev-parse", "HEAD")
    except (ExternalLabError, subprocess.TimeoutExpired, OSError):
        shutil.rmtree(dest, ignore_errors=True)
        raise
    if head != commit:
        shutil.rmtree(dest, ignore_errors=True)
        raise ExternalLabError(f"{label} checkout is {head}, not {commit}")
    return dest


def fetch_crawl_maze(*, dest: Path | None = None, repo: str = CRAWL_MAZE_REPO,
                     commit: str = CRAWL_MAZE_COMMIT, timeout: float = 600.0) -> Path:
    """Check the Crawl Maze's source out at ``commit`` into the gitignored cache (its
    compose file builds from there; `checkout_pinned`)."""
    return checkout_pinned(crawl_maze_source() if dest is None else dest, repo, commit,
                           timeout=timeout, label="crawl maze")


def secdevlabs_checkout(root: Path = EXTERNAL_DIR) -> Path:
    """The one pinned secDevLabs checkout every app lab copies from (gitignored)."""
    return root / ".cache" / "secdevlabs" / "src"


def go_vendor(moddir: Path, *, timeout: float = 900.0) -> None:
    """Fetch a Go module's dependencies with the host's Go, verify every one against
    the module's own ``go.sum`` (``go mod verify``), and vendor them, so its image
    builds offline. Raises when Go is missing or any module fails verification."""
    import shutil

    from fuzzlab.procutil import run_bounded
    go = shutil.which("go")
    if go is None:
        raise ExternalLabError("Go is not installed on this host: needed to vendor the "
                               "app's modules (they are verified against its go.sum)")
    env = {**os.environ, "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local"}
    for args in (["mod", "download"], ["mod", "verify"], ["mod", "vendor"]):
        res = run_bounded([go, *args], timeout=timeout, cwd=str(moddir), env=env)
        if res.returncode != 0:
            raise ExternalLabError(f"go {' '.join(args)} failed: "
                                   f"{(res.stderr or res.stdout or '').strip()[-200:]}")
        if args[1] == "verify" and "all modules verified" not in (res.stdout or ""):
            raise ExternalLabError("go mod verify did not verify every module")


def maven_offline(pomdir: Path, repo: Path, *, timeout: float = 900.0) -> None:
    """Resolve a Maven project's dependencies and build plugins into ``repo`` with the
    host's Maven, each artifact checked against the checksum its repository publishes
    (``--strict-checksums``), by building it once here; the build output is removed.
    The image then builds offline from ``repo`` (``mvn -o``). Raises when Maven is
    missing or the build fails (a checksum mismatch fails it)."""
    import shutil

    from fuzzlab.procutil import run_bounded
    mvn = shutil.which("mvn")
    if mvn is None:
        raise ExternalLabError("Maven is not installed on this host: needed to resolve "
                               "the app's dependencies (checked against their checksums)")
    res = run_bounded([mvn, "-B", "-q", "--strict-checksums", f"-Dmaven.repo.local={repo}",
                       "-Dmaven.test.skip=true", "package"], timeout=timeout,
                      cwd=str(pomdir))
    shutil.rmtree(pomdir / "target", ignore_errors=True)
    if res.returncode != 0:
        raise ExternalLabError(f"mvn package failed: "
                               f"{(res.stderr or res.stdout or '').strip()[-200:]}")


def npm_install(pkgdir: Path, *, timeout: float = 900.0, production: bool = False) -> None:
    """Install a Node package's locked dependencies with the host's npm (``npm ci``:
    exactly the lockfile, each package checked against its ``integrity`` hash; no
    install scripts), so its image needs no registry. Raises when npm is missing or
    the install fails (an integrity mismatch fails it). ``production`` leaves the
    development packages out (``--omit=dev``: NodeGoat's test tooling, CC-LAB-0330)."""
    import shutil

    from fuzzlab.procutil import run_bounded
    npm = shutil.which("npm")
    if npm is None:
        raise ExternalLabError("npm is not installed on this host: needed to install the "
                               "app's locked packages (checked against its lockfile)")
    res = run_bounded([npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund",
                       *(["--omit=dev"] if production else [])],
                      timeout=timeout, cwd=str(pkgdir))
    if res.returncode != 0 or not (pkgdir / "node_modules").is_dir():
        raise ExternalLabError(f"npm ci failed: {(res.stderr or res.stdout or '').strip()[-200:]}")


def fetch_secdevlabs_app(lab: str, *, root: Path = EXTERNAL_DIR, repo: str = SECDEVLABS_REPO,
                         commit: str = SECDEVLABS_COMMIT, timeout: float = 900.0) -> Path:
    """The app of secDevLabs lab ``lab``, copied from the pinned checkout into
    ``<lab>/.cache/app`` with its dependencies fetched and verified on the host (Go:
    `go_vendor`). The image builds from there with no network."""
    import shutil
    if lab not in SECDEVLABS_APPS:
        raise ExternalLabError(f"{lab!r} is not a secDevLabs app lab")
    src = checkout_pinned(secdevlabs_checkout(root), repo, commit, timeout=timeout,
                          label="secDevLabs")
    dest = root / lab / ".cache" / "app"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src / SECDEVLABS_APPS[lab], dest, symlinks=True)
    for gomod in sorted(dest.rglob("go.mod")):
        go_vendor(gomod.parent, timeout=timeout)
    for lock in sorted(dest.rglob("package-lock.json")):
        if "node_modules" not in lock.parts and lab not in SECDEVLABS_PREBUILT:
            npm_install(lock.parent, timeout=timeout)
    for pom in sorted(dest.rglob("pom.xml")):
        maven_offline(pom.parent, root / lab / ".cache" / "m2", timeout=timeout)
    if lab in SECDEVLABS_PYPI:
        fetch_pypi_dists(SECDEVLABS_PYPI[lab], root / lab / ".cache" / "dists",
                         timeout=timeout)
    return dest


def mutillidae_ldif_path(root: Path = EXTERNAL_DIR) -> Path:
    return root / "mutillidae" / ".cache" / "mutillidae.ldif"


def fetch_mutillidae_ldif(*, dest: Path | None = None, timeout: float = 60.0,
                          get: Callable[[str, float], bytes] | None = None,
                          url: str = MUTILLIDAE_LDIF_URL,
                          sha256: str = MUTILLIDAE_LDIF_SHA256,
                          size: int = MUTILLIDAE_LDIF_SIZE) -> Path:
    """Mutillidae's LDIF in the gitignored cache, verified by sha256 and size. A cached
    file is re-hashed, never trusted; a mismatch leaves nothing behind and raises --
    never a substitute. An anonymous public download (the host's proxy/CA apply)."""
    dest = mutillidae_ldif_path() if dest is None else dest
    if dest.is_file():
        data = dest.read_bytes()
        if len(data) == size and hashlib.sha256(data).hexdigest() == sha256:
            return dest
        dest.unlink()
    try:
        data = (get or _pypi_get)(url, timeout)
    except (OSError, ValueError) as exc:
        raise ExternalLabError(f"mutillidae.ldif: download failed "
                               f"({type(exc).__name__})") from None
    if len(data) != size or hashlib.sha256(data).hexdigest() != sha256:
        raise ExternalLabError(f"mutillidae.ldif does not match the pin (sha256 "
                               f"{hashlib.sha256(data).hexdigest()}, {len(data)} bytes)")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".part")
    tmp.write_bytes(data)
    tmp.replace(dest)
    return dest


def tree_sha256(checkout: Path, *, timeout: float = 120.0) -> str:
    """One sha256 over a git checkout's tracked files: each path (sorted, bytes) with
    the sha256 of its content. Independent of git's own object format, of the
    checkout's file times and of the git version (CC-LAB-0330)."""
    from fuzzlab.procutil import run_bounded
    res = run_bounded(["git", "-C", str(checkout), "ls-files", "-z"], timeout=timeout,
                      text=False)
    if res.returncode != 0:
        raise ExternalLabError("git ls-files failed on the checkout")
    out = res.stdout if isinstance(res.stdout, bytes) else res.stdout.encode("utf-8")
    digest = hashlib.sha256()
    for name in sorted(n for n in out.split(b"\0") if n):
        content = (checkout / os.fsdecode(name)).read_bytes()
        digest.update(name + b"\0" + hashlib.sha256(content).hexdigest().encode() + b"\n")
    return digest.hexdigest()


def nodegoat_checkout(root: Path = EXTERNAL_DIR) -> Path:
    """The pinned NodeGoat checkout (gitignored)."""
    return root / "nodegoat" / ".cache" / "src"


def fetch_nodegoat(*, root: Path = EXTERNAL_DIR, repo: str = NODEGOAT_REPO,
                   commit: str = NODEGOAT_COMMIT, tree: str = NODEGOAT_TREE_SHA256,
                   timeout: float = 900.0) -> Path:
    """NodeGoat at ``commit`` (its tracked files hashing to ``tree``), copied into
    ``nodegoat/.cache/app`` without its git directory, with its production packages
    installed on the host (`npm_install`). The image builds from there offline."""
    import shutil
    src = checkout_pinned(nodegoat_checkout(root), repo, commit, timeout=timeout,
                          label="NodeGoat")
    got = tree_sha256(src)
    if got != tree:
        raise ExternalLabError(f"NodeGoat checkout's files hash to {got}, not {tree}")
    dest = root / "nodegoat" / ".cache" / "app"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    npm_install(dest, timeout=timeout, production=True)
    return dest


def fetch_dvws_node(*, root: Path = EXTERNAL_DIR, repo: str = DVWS_NODE_REPO,
                    commit: str = DVWS_NODE_COMMIT, tree: str = DVWS_NODE_TREE_SHA256,
                    timeout: float = 900.0) -> Path:
    """DVWS-node at ``commit`` (its tracked files hashing to ``tree``), copied into
    ``dvws-node/.cache/app`` without its git directory, with the frontend's locked
    build packages and the backend's production packages installed on the host
    (`npm_install`: lockfile integrity, no install scripts). Nothing upstream runs on
    the host: the image builds the frontend and compiles bcrypt offline."""
    import shutil
    src = checkout_pinned(root / "dvws-node" / ".cache" / "src", repo, commit,
                          timeout=timeout, label="DVWS-node")
    got = tree_sha256(src)
    if got != tree:
        raise ExternalLabError(f"DVWS-node checkout's files hash to {got}, not {tree}")
    dest = root / "dvws-node" / ".cache" / "app"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    npm_install(dest / "frontend", timeout=timeout)
    npm_install(dest, timeout=timeout, production=True)
    return dest


_LOCK_CHECKSUM = re.compile(r"^  (\S+) \(([^)\s]+)\)(?: sha256=([0-9a-f]{64}))?\s*$")


def gemfile_lock_checksums(text: str, platforms: Iterable[str] = RAILSGOAT_GEM_PLATFORMS
                           ) -> dict[str, str]:
    """``{gem file name: sha256}`` from a Gemfile.lock's CHECKSUMS section, for the gems
    of ``platforms``. Fails closed: no section, or a selected gem without a sha256."""
    lines = text.splitlines()
    if "CHECKSUMS" not in lines:
        raise ExternalLabError("Gemfile.lock has no CHECKSUMS section")
    platforms = set(platforms)
    pins: dict[str, str] = {}
    for line in lines[lines.index("CHECKSUMS") + 1:]:
        if not line.strip():
            break
        m = _LOCK_CHECKSUM.match(line)
        if m is None:
            raise ExternalLabError(f"unreadable CHECKSUMS line: {line.strip()[:80]!r}")
        name, version, digest = m.groups()
        platform = version.split("-", 1)[1] if "-" in version else "ruby"
        if platform not in platforms:
            continue
        if digest is None:
            raise ExternalLabError(f"{name} ({version}) has no sha256 in the lock")
        pins[f"{name}-{version}.gem"] = digest
    if not pins:
        raise ExternalLabError("Gemfile.lock's CHECKSUMS names no gem for this platform")
    return pins


def fetch_rubygems(pins: Mapping[str, str], dest: Path, *, timeout: float = 600.0,
                   get=_pypi_get, prune: bool = True) -> Path:
    """Download each pinned gem (``{file name: sha256}``) from rubygems.org into ``dest``
    on the host, so an image installs them offline (``bundle install --local``). The
    bytes must hash to the pin; a cached file is re-hashed, never trusted; a mismatch
    leaves nothing behind and raises. ``prune`` removes any other ``.gem`` there."""
    from concurrent.futures import ThreadPoolExecutor
    dest.mkdir(parents=True, exist_ok=True)
    if prune:
        for stale in dest.glob("*.gem"):
            if stale.name not in pins:
                stale.unlink()

    def one(name: str) -> None:
        path = dest / name
        if path.is_file() and _sha256_file(path)[0] == pins[name]:
            return
        path.unlink(missing_ok=True)
        try:
            data = get(f"https://rubygems.org/gems/{name}", timeout)
        except (OSError, ValueError) as exc:
            raise ExternalLabError(f"{name}: download failed ({type(exc).__name__})") from None
        if hashlib.sha256(data).hexdigest() != pins[name]:
            raise ExternalLabError(f"{name}: sha256 differs from the pin")
        tmp = dest / (name + ".part")
        tmp.write_bytes(data)
        tmp.replace(path)

    with ThreadPoolExecutor(max_workers=8) as pool:
        for fut in [pool.submit(one, n) for n in sorted(pins)]:
            fut.result()
    return dest


def railsgoat_checkout(root: Path = EXTERNAL_DIR) -> Path:
    """The pinned RailsGoat checkout (gitignored)."""
    return root / "railsgoat" / ".cache" / "src"


def fetch_railsgoat(*, root: Path = EXTERNAL_DIR, repo: str = RAILSGOAT_REPO,
                    commit: str = RAILSGOAT_COMMIT, tree: str = RAILSGOAT_TREE_SHA256,
                    bundler: tuple[str, str] = RAILSGOAT_BUNDLER_GEM,
                    timeout: float = 900.0, get=_pypi_get) -> Path:
    """RailsGoat at ``commit`` (its tracked files hashing to ``tree``), copied into
    ``railsgoat/.cache/app`` without its git directory, with every gem its lock pins for
    this platform in ``vendor/cache`` (`fetch_rubygems`, against the lock's CHECKSUMS)
    and the lock's bundler in ``.cache/bundler``. The image builds from there offline."""
    import shutil
    src = checkout_pinned(railsgoat_checkout(root), repo, commit, timeout=timeout,
                          label="RailsGoat")
    got = tree_sha256(src)
    if got != tree:
        raise ExternalLabError(f"RailsGoat checkout's files hash to {got}, not {tree}")
    pins = gemfile_lock_checksums((src / "Gemfile.lock").read_text("utf-8"))
    gems = root / "railsgoat" / ".cache" / "gems"
    fetch_rubygems(pins, gems, timeout=timeout, get=get)
    fetch_rubygems(dict([bundler]), root / "railsgoat" / ".cache" / "bundler",
                   timeout=timeout, get=get)
    dest = root / "railsgoat" / ".cache" / "app"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    shutil.copytree(gems, dest / "vendor" / "cache")
    return dest


def _fetch_locked(*, session: Any, dest: Path, timeout: float, max_hops: int, url: str,
                  sha256: str, size: int) -> Path:
    for stale in dest.parent.glob(".bwapp-*.part"):     # a killed download's leftovers
        stale.unlink()
    if dest.is_file():
        digest, got = _sha256_file(dest)
        if digest == sha256 and got == size:
            return dest
        dest.unlink()
    if session is None:
        import requests
        session = requests.Session()
    fd, tmp_name = tempfile.mkstemp(prefix=".bwapp-", suffix=".part", dir=dest.parent)
    tmp = Path(tmp_name)
    try:
        current = url
        for _ in range(max_hops + 1):
            if urlsplit(current).scheme != "https":
                raise ExternalLabError(f"refusing a non-https download hop: {current}")
            resp = session.get(current, stream=True, timeout=timeout, allow_redirects=False)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                resp.close()
                if not location:
                    raise ExternalLabError("a download redirect without a Location")
                current = urljoin(current, location)
                continue
            if resp.status_code != 200:
                resp.close()
                raise ExternalLabError(f"bWAPP download failed: HTTP {resp.status_code}")
            h = hashlib.sha256()
            got = 0
            with os.fdopen(fd, "wb") as fh:
                fd = -1
                for chunk in resp.iter_content(1 << 20):
                    if not chunk:
                        continue
                    got += len(chunk)
                    if got > size:
                        raise ExternalLabError("bWAPP download is larger than the pinned size")
                    h.update(chunk)
                    fh.write(chunk)
                fh.flush()
                os.fsync(fh.fileno())
            resp.close()
            if got != size or h.hexdigest() != sha256:
                raise ExternalLabError(
                    f"bWAPP download does not match the pin (sha256 {h.hexdigest()}, "
                    f"{got} bytes; expected {sha256}, {size} bytes)")
            os.replace(tmp, dest)
            dfd = os.open(dest.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            return dest
        raise ExternalLabError(f"too many redirects fetching {url}")
    finally:
        if fd != -1:
            os.close(fd)
        if tmp.exists():
            tmp.unlink()


# --- compose pre-flight -----------------------------------------------------------------

_PORT_SPLIT = re.compile(r"^(?:\[(?P<ip6>[^\]]*)\]|(?P<ip>[^:\[\]]*)):(?P<rest>.+)$")


def port_binding_problems(service: str, binding: Any) -> list[str]:
    """Problems with one ``ports:`` entry: it must name an explicit, literal loopback
    host IP. Handles the short (``"127.0.0.1:8092:80"``, ranges, ``/tcp``) and the long
    syntax (``{host_ip, published, target}``) and a rendered config's dicts."""
    if isinstance(binding, Mapping):
        host_ip = binding.get("host_ip")
        if host_ip in (None, ""):
            return [f"{service}: port {binding!r} has no host_ip (binds every interface)"]
        return _host_ip_problems(service, str(host_ip), binding)
    if isinstance(binding, int):
        return [f"{service}: port {binding!r} has no host IP (binds every interface)"]
    text = str(binding).strip().split("/", 1)[0]
    parts = text.count(":")
    if text.startswith("["):
        m = _PORT_SPLIT.match(text)
        if not m or m.group("rest").count(":") != 1:
            return [f"{service}: cannot parse port binding {binding!r}"]
        return _host_ip_problems(service, m.group("ip6"), binding)
    if parts < 2:
        return [f"{service}: port {binding!r} has no host IP (binds every interface)"]
    host_ip = text.split(":", 1)[0]
    return _host_ip_problems(service, host_ip, binding)


def _host_ip_problems(service: str, host_ip: str, binding: Any) -> list[str]:
    from fuzzlab.core.net import is_loopback_host
    if "$" in host_ip:
        return [f"{service}: port {binding!r} takes its host IP from interpolation"]
    if host_ip.strip().lower() == "localhost":
        return [f"{service}: port {binding!r}: name the address (127.0.0.1), not localhost"]
    if not is_loopback_host(host_ip):
        return [f"{service}: port {binding!r} is published on {host_ip!r}, not loopback"]
    return []


#: ``network_mode`` values a fixture may use: anything else (``host``, podman's
#: ``ns:<path>``, ``slirp4netns``/``pasta`` options, ``container:<id>``) can join the
#: host's namespace or reach its loopback, so it is refused (an allowlist, review A1).
ALLOWED_NETWORK_MODES = frozenset({"", "none", "bridge", "default"})


def config_problems(doc: Mapping[str, Any]) -> list[str]:
    """Safety problems in a compose document (raw file or rendered ``config``): every
    published port on a literal loopback IP; ``network_mode`` only from an allowlist (or
    ``service:`` another service of this project); no external or host-driver network;
    no host pid namespace and no privileged container."""
    problems: list[str] = []
    services = doc.get("services") or {}
    if not isinstance(services, Mapping):
        return ["compose document has no services mapping"]
    networks = doc.get("networks") or {}
    if not isinstance(networks, Mapping):
        problems.append("top-level networks is not a mapping")
        networks = {}
    for net_name, net in networks.items():
        net = net if isinstance(net, Mapping) else {}
        if net.get("external") not in (None, False, "false", "False"):
            problems.append(f"network {net_name}: external (not owned by the project)")
        if str(net.get("name") or "") == "host" or str(net.get("driver") or "") == "host":
            problems.append(f"network {net_name}: the host network")
    for name, svc in services.items():
        if not isinstance(svc, Mapping):
            problems.append(f"{name}: not a mapping")
            continue
        mode = str(svc.get("network_mode") or "")
        if mode.startswith("service:"):
            if mode.split(":", 1)[1] not in services:
                problems.append(f"{name}: network_mode {mode!r} names no service of this project")
        elif mode not in ALLOWED_NETWORK_MODES:
            problems.append(f"{name}: network_mode {mode!r} is not allowed")
        if str(svc.get("pid") or "") == "host":
            problems.append(f"{name}: pid: host")
        if svc.get("privileged") in (True, "true", "True"):
            problems.append(f"{name}: privileged")
        for binding in svc.get("ports") or []:
            problems += port_binding_problems(str(name), binding)
    return problems


def load_compose_document(text: str) -> Mapping[str, Any]:
    """A rendered ``config`` output: JSON when the provider supports it, else YAML."""
    try:
        doc = json.loads(text)
    except ValueError:
        import yaml
        doc = yaml.safe_load(text)
    if not isinstance(doc, Mapping):
        raise ExternalLabError("compose config is not a mapping")
    return doc


# --- post-boot exposure check -----------------------------------------------------------

def exposure_problems(inspects: list[Mapping[str, Any]], host_listeners: Iterable[Any],
                      project: str | None = None,
                      netns_of: Callable[[int], str | None] | None = None,
                      host_netns: str | None = None) -> tuple[list[str], list[str]]:
    """``(problems, notes)`` for a project's containers (engine ``inspect`` output) and
    the host's LISTEN table. Fails closed: no container, host networking, a binding with
    an empty (= every interface) or non-loopback ``HostIp``, or a non-loopback host
    listener on a published port. ``NetworkMode`` must be ``bridge``/``default``/``none``,
    a network of the project (``<project>_...``) or another project container's
    namespace; and, where it can be read, a container's network namespace must not be
    the host's (``netns_of(State.Pid)`` vs ``host_netns``) -- whatever the engine calls
    its mode (review A1). A published port with no host listener is a note (an engine
    without a userland proxy publishes through NAT only); ``inspect`` is the
    authoritative check (PA-0130(4))."""
    from fuzzlab.core.net import is_loopback_host
    problems: list[str] = []
    notes: list[str] = []
    if not inspects:
        return ["no container of the project was found (cannot prove it is loopback-only)"], notes
    published: set[int] = set()
    ids = {str(c.get("Id") or "") for c in inspects} - {""}
    for c in inspects:
        cname = str(c.get("Name") or c.get("Id") or "?").lstrip("/")
        hc = c.get("HostConfig") or {}
        mode = str(hc.get("NetworkMode") or "")
        joined = mode.split(":", 1)[1] if mode.startswith("container:") else None
        if not (mode in ("bridge", "default", "none")
                or (project and mode.startswith(project + "_"))
                or (joined and any(i.startswith(joined) for i in ids))):
            problems.append(f"{cname}: network mode {mode!r} is not a project network")
        pid = (c.get("State") or {}).get("Pid")
        if netns_of is not None and host_netns and isinstance(pid, int) and pid > 0:
            ns = netns_of(pid)
            if ns and ns == host_netns:
                problems.append(f"{cname}: runs in the host's network namespace")
        if hc.get("Privileged"):
            problems.append(f"{cname}: privileged")
        bindings: dict[str, list[Any]] = {}
        for source in (hc.get("PortBindings") or {},
                       (c.get("NetworkSettings") or {}).get("Ports") or {}):
            for key, val in source.items():
                bindings.setdefault(key, []).extend(val or [])
        for cport, binds in bindings.items():
            for b in binds:
                host_ip = str((b or {}).get("HostIp") or "")
                host_port = str((b or {}).get("HostPort") or "")
                if not host_ip:
                    problems.append(f"{cname}: {cport} published on every interface "
                                    f"(empty HostIp)")
                elif not is_loopback_host(host_ip):
                    problems.append(f"{cname}: {cport} published on {host_ip}")
                if host_port.isdigit():
                    published.add(int(host_port))
    seen: set[int] = set()
    for lst in host_listeners:
        if lst.port in published:
            seen.add(lst.port)
            if not lst.is_loopback():
                problems.append(f"host listens on {lst.address}:{lst.port} (a published port)")
    for port in sorted(published - seen):
        notes.append(f"port {port} is published with no host listener (NAT-only publish); "
                     f"inspect is authoritative")
    return problems, notes


def published_port(meta: LabMeta, project: str, engine: str, *,
                   runner: Callable[..., Any] | None = None) -> tuple[str, int]:
    """``(host, port)``: the loopback address the running project actually publishes for
    the lab's app (review A9: the bootstrap must target the running lab, not whatever
    the port variable says now), host as the binding names it (``127.0.0.1``, ``::1``).
    Raises on any engine error, when there is none, or when it is not on loopback."""
    import subprocess

    from fuzzlab.core.net import is_loopback_host
    from fuzzlab.procutil import ProcUtilError
    if runner is None:
        from fuzzlab.procutil import run_bounded as runner
    try:
        ids = _engine_json(engine, ["ps", "-q", "--no-trunc", "--filter",
                                    f"label={PROJECT_LABEL}={project}", "--filter",
                                    f"label=com.docker.compose.service={meta.service}"],
                           runner).split()
        inspects = json.loads(_engine_json(engine, ["inspect", *ids], runner)) if ids else []
    except (ExternalLabError, ValueError, OSError, subprocess.TimeoutExpired,
            ProcUtilError) as exc:
        raise ExternalLabError(f"cannot read the published port of {project}: "
                               f"{type(exc).__name__}: {exc}") from None
    for c in inspects if isinstance(inspects, list) else []:
        sources = ((c.get("HostConfig") or {}).get("PortBindings") or {},
                   (c.get("NetworkSettings") or {}).get("Ports") or {})
        for source in sources:
            for b in source.get(f"{meta.container_port}/tcp") or []:
                port = str((b or {}).get("HostPort") or "")
                host = str((b or {}).get("HostIp") or "")
                if port.isdigit() and is_loopback_host(host):
                    return host, int(port)
    raise ExternalLabError(f"{project}: no running {meta.service} container publishes "
                           f"{meta.container_port} on loopback (is the lab up?)")


def _engine_json(engine: str, args: list[str], runner: Callable[..., Any]) -> Any:
    res = runner([engine, *args], timeout=60)
    if res.returncode != 0:
        raise ExternalLabError(f"`{engine} {args[0]}` failed (exit {res.returncode})")
    return res.stdout


def check_exposure(project: str, engine: str, *, runner: Callable[..., Any] | None = None,
                   listeners: Callable[[], list[Any]] | None = None
                   ) -> tuple[list[str], list[str]]:
    """Inspect every container carrying the project's compose label and the host's
    LISTEN table. Any engine error is a problem (fail closed)."""
    if engine not in ("docker", "podman"):
        raise ExternalLabError(f"unknown engine {engine!r}")
    import subprocess

    from fuzzlab.procutil import ProcUtilError, host_netns, netns_of
    if runner is None:
        from fuzzlab.procutil import run_bounded as runner
    if listeners is None:
        from fuzzlab.procutil import host_listen_sockets as listeners
    try:
        ids = _engine_json(engine, ["ps", "-a", "-q", "--no-trunc", "--filter",
                                    f"label={PROJECT_LABEL}={project}"], runner).split()
        inspects = json.loads(_engine_json(engine, ["inspect", *ids], runner)) if ids else []
        host_listeners = listeners()
    except (ExternalLabError, ValueError, OSError, subprocess.TimeoutExpired,
            ProcUtilError) as exc:
        return [f"exposure check could not inspect the project: {type(exc).__name__}: "
                f"{exc}"], []
    if not isinstance(inspects, list):
        return ["exposure check could not inspect the project: unexpected inspect output"], []
    return exposure_problems(inspects, host_listeners, project=project,
                             netns_of=lambda pid: netns_of(pid) or None,
                             host_netns=host_netns())


# --- bWAPP security-level log (BUG-0311) --------------------------------------------

#: The prefix of the line `lab/external/bwapp/apache-level-log.conf` writes per request.
LEVEL_LOG_PREFIX = "fuzzlab-level "
_LEVEL_LINE = re.compile(r'^fuzzlab-level (\S+) "(.*)"$')
#: The level cookie values a scored bWAPP run may carry: bWAPP's own level 0, or no
#: cookie (bWAPP redirects such a request to its login or level page). An allowlist
#: (PA-0310(1)): PHP compares the cookie loosely (``"01"``, ``"1.0"`` select level 1)
#: and URL-decodes it, so naming the bad values cannot be complete.
LEVEL_LOG_ALLOWED = frozenset({"0", "-"})


def bwapp_level_problems(log_text: str, controls: Iterable[str], *,
                         min_requests: int = 1000) -> list[str]:
    """Problems in a bWAPP container's level log (its ``docker logs`` stdout).

    ``controls`` are markers of requests the caller sent with ``security_level=1``. Each
    must appear with level ``1``, which shows the log carries the violation the check
    looks for. Every other logged request must carry an allowed level, there must be at
    least ``min_requests`` of them, and every level line must parse (none is dropped
    silently).

    Stated limit: Apache's ``%{security_level}C`` matches the cookie name without regard
    to case, while PHP's ``$_COOKIE`` is case-sensitive, so a request carrying
    ``SECURITY_LEVEL=0; security_level=1`` would log ``0`` and run at level 1. No pass
    injects the cookie."""
    controls = list(controls)
    problems: list[str] = []
    entries: list[tuple[str, str]] = []
    for line in log_text.splitlines():
        line = line.strip()
        if not line.startswith(LEVEL_LOG_PREFIX):
            continue
        m = _LEVEL_LINE.match(line)
        if m is None:
            problems.append(f"unparsed level line: {line[:200]!r}")
            continue
        entries.append((m.group(1), m.group(2)))
    for marker in controls:
        seen = [lvl for lvl, req in entries if marker in req]
        if "1" not in seen:
            problems.append(f"control {marker!r} not logged with level 1 (seen: {seen})")
    sent = [(lvl, req) for lvl, req in entries if not any(m in req for m in controls)]
    if len(sent) < min_requests:
        problems.append(f"the level log saw only {len(sent)} requests (< {min_requests})")
    bad = [(lvl, req) for lvl, req in sent if lvl not in LEVEL_LOG_ALLOWED]
    if bad:
        counts: dict[str, int] = {}
        for lvl, _req in bad:
            counts[lvl] = counts.get(lvl, 0) + 1
        problems.append(f"{len(bad)} requests carried a level outside "
                        f"{sorted(LEVEL_LOG_ALLOWED)}: {counts}; e.g. {bad[:3]}")
    return problems


# --- bootstrap HTTP client --------------------------------------------------------------

def _default_session() -> Any:
    import requests

    from fuzzlab.core.http import DEFAULT_BROWSER_HEADERS
    s = requests.Session()
    s.headers.update(DEFAULT_BROWSER_HEADERS)
    return s


class _LabClient:
    """A credential-sending client for one loopback origin: no proxies (``trust_env``
    off), no automatic redirects, a timeout on every request, browser headers
    (PA-0061/0062), and a refusal of any URL outside the origin (PA-0082/0098)."""

    def __init__(self, origin: str, *, session_factory: Callable[[], Any] | None = None,
                 timeout: float = 15.0):
        from fuzzlab.core.net import is_loopback_host
        parts = urlsplit(origin)
        if parts.scheme != "http" or not parts.hostname or not is_loopback_host(parts.hostname):
            raise ExternalLabError(f"refusing a non-loopback lab origin: {origin!r}")
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ExternalLabError(f"the lab origin must be scheme://host:port, got {origin!r}")
        self.origin = f"{parts.scheme}://{parts.netloc}"
        self._factory = session_factory or _default_session
        self.session = self._new_session()
        self.timeout = timeout

    def _new_session(self) -> Any:
        s = self._factory()
        s.trust_env = False
        s.proxies = {}
        return s

    def url(self, path: str) -> str:
        if not path.startswith("/") or path.startswith("//"):
            raise ExternalLabError(f"not an origin-relative path: {path!r}")
        return self.origin + path

    def request(self, method: str, path: str, *, anonymous: bool = False, **kw: Any) -> Any:
        """``anonymous``: on a fresh session with no cookies (a differential's control)."""
        kw["allow_redirects"] = False
        kw.setdefault("timeout", self.timeout)
        session = self._new_session() if anonymous else self.session
        return session.request(method, self.url(path), **kw)

    def location(self, resp: Any, path: str) -> str:
        """A redirect's target, resolved against the request's own URL (``path``) --
        read, never followed."""
        return urljoin(self.url(path), resp.headers.get("Location", ""))


def wait_ready(client: _LabClient, path: str, *, deadline: float = 180.0,
               clock: Callable[[], float] = time.monotonic,
               sleep: Callable[[float], None] = time.sleep) -> None:
    """Return once ``path`` gives any HTTP answer (PA-0050); raise at the deadline."""
    end = clock() + deadline
    while True:
        try:
            client.request("GET", path).close()
            return
        except ExternalLabError:
            raise
        except Exception:  # noqa: BLE001 - connection refused/reset while the lab boots
            if clock() >= end:
                raise ExternalLabError(f"{client.origin}{path} gave no answer within "
                                       f"{deadline:.0f}s") from None
            sleep(1.0)


# --- credentials -------------------------------------------------------------------------

@dataclass(frozen=True)
class ResolvedCredential:
    username: str
    password: str
    #: keyring | env | prompt | generated
    source: str

    def __repr__(self) -> str:  # never leak the password
        return f"ResolvedCredential(username={self.username!r}, source={self.source!r})"


def resolve_credential(meta: LabMeta, *, host: str, keyring_store: Any, opened_store: Any,
                       prompt: Callable[[str], str] | None, generate: bool
                       ) -> ResolvedCredential:
    """Keyring first (a store with the env channel off), then the operator's opened store
    (whose gated ``FUZZLAB_CRED_<HOST>_<IDENTITY>`` channel follows the operator's own
    ``allow_env_credentials`` switch), then an interactive prompt (TTY only; an empty
    answer is refused), then -- with no prompt, for a lab whose account we create -- a
    fresh random password."""
    cred = keyring_store.get(host, meta.identity)
    if cred is not None:
        return ResolvedCredential(cred.username, cred.password, "keyring")
    cred = opened_store.get(host, meta.identity)
    if cred is not None:
        return ResolvedCredential(cred.username, cred.password, "env")
    if prompt is not None:
        pw = prompt(f"password for {meta.identity} ({meta.default_username}): ")
        if pw:
            return ResolvedCredential(meta.default_username, pw, "prompt")
        raise ExternalLabError("no password entered")
    if generate and meta.may_generate_password:
        return ResolvedCredential(meta.default_username, secrets.token_urlsafe(24), "generated")
    raise ExternalLabError(
        f"no credential for {meta.identity!r} on {host}: run `fuzzlab session set-credential "
        f"--host {host} --identity {meta.identity} --username {meta.default_username}`, or run "
        f"this from a terminal to be prompted")


def _tty_prompt() -> Callable[[str], str] | None:
    return getpass.getpass if sys.stdin.isatty() else None


# --- bootstrap ---------------------------------------------------------------------------

BWAPP_INSTALLED = "bWAPP has been installed successfully!"
BWAPP_ALREADY = "The bWAPP database already exists..."


@dataclass
class BootstrapResult:
    lab: str
    identity: str | None
    credential_source: str
    stored: bool
    notes: list[str]
    #: The lab's extra accounts (`LabMeta.extra_identities`), one result each.
    peers: list["BootstrapResult"] = field(default_factory=list)


def _bwapp_install(client: _LabClient, *, deadline: float, clock: Callable[[], float],
                   sleep: Callable[[float], None]) -> str:
    end = clock() + deadline
    while True:
        try:
            resp = client.request("GET", "/bWAPP/install.php", params={"install": "yes"})
            text = resp.text
        except Exception:  # noqa: BLE001 - the DB may still be initialising
            text = ""
        for marker in (BWAPP_INSTALLED, BWAPP_ALREADY):
            if marker in text:
                return marker
        if clock() >= end:
            raise ExternalLabError("bWAPP's installer did not report success within "
                                   f"{deadline:.0f}s")
        sleep(2.0)


def bootstrap_bwapp(client: _LabClient, cred: ResolvedCredential, *, deadline: float = 180.0,
                    clock: Callable[[], float] = time.monotonic,
                    sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Install bWAPP's database (idempotent) and verify a level-0 login for ``cred`` by a
    positive differential (PA-0007): ``portal.php`` redirects to ``login.php`` without
    the session and answers 200 with it."""
    meta = LAB_META["bwapp"]
    wait_ready(client, meta.ready_path, deadline=deadline, clock=clock, sleep=sleep)
    notes = [_bwapp_install(client, deadline=deadline, clock=clock, sleep=sleep)]
    anon = client.request("GET", "/bWAPP/portal.php", anonymous=True)
    login_url, portal_url = client.url("/bWAPP/login.php"), client.url("/bWAPP/portal.php")
    if anon.status_code != 302 or client.location(anon, "/bWAPP/portal.php") != login_url:
        raise ExternalLabError(f"bWAPP portal.php does not require a login "
                               f"(HTTP {anon.status_code})")
    login = client.request("POST", "/bWAPP/login.php", data={
        "login": cred.username, "password": cred.password,
        "security_level": "0", "form": "submit"})
    if login.status_code != 302 or client.location(login, "/bWAPP/login.php") != portal_url:
        raise ExternalLabError(
            "bWAPP login failed for the stored identity; if a run changed its password, "
            "run `./labctl.sh reset bwapp --authorized`")
    level = client.session.cookies.get("security_level")
    if level != "0":
        raise ExternalLabError(f"bWAPP security level is {level!r}, not 0")
    portal = client.request("GET", "/bWAPP/portal.php")
    if portal.status_code != 200:
        raise ExternalLabError(f"bWAPP portal.php with the session: HTTP {portal.status_code}")
    notes.append("level-0 login verified")
    return notes


def bootstrap_juice_shop(client: _LabClient, cred: ResolvedCredential, *,
                         deadline: float = 180.0,
                         clock: Callable[[], float] = time.monotonic,
                         sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Check the label environment (``safetyMode: disabled``), then log in -- registering
    the account through Juice Shop's own API when the login fails -- and verify it by a
    positive differential: ``whoami`` names the account, and ``/profile`` answers 200
    with the ``token`` cookie and not without it. Both read the cookie the app's own JS
    sets, not the bearer header."""
    meta = LAB_META["juice-shop"]
    wait_ready(client, meta.ready_path, deadline=deadline, clock=clock, sleep=sleep)
    notes: list[str] = []
    cfg = client.request("GET", "/rest/admin/application-configuration")
    try:
        mode = cfg.json()["config"]["challenges"]["safetyMode"]
    except (ValueError, KeyError, TypeError):
        raise ExternalLabError("cannot read Juice Shop's challenges.safetyMode") from None
    if mode != "disabled":
        raise ExternalLabError(f"Juice Shop challenges.safetyMode is {mode!r}, not 'disabled' "
                               f"(the fixture sets NODE_ENV=unsafe); its ground truth assumes it")
    notes.append("safetyMode disabled")

    def login() -> str | None:
        r = client.request("POST", "/rest/user/login",
                           json={"email": cred.username, "password": cred.password})
        if r.status_code != 200:
            return None
        try:
            return r.json()["authentication"]["token"]
        except (ValueError, KeyError, TypeError):
            return None

    token = login()
    if token is None:
        reg = client.request("POST", "/api/Users", json={
            "email": cred.username, "password": cred.password,
            "passwordRepeat": cred.password})
        if reg.status_code != 201:
            if "unique" in reg.text:
                raise ExternalLabError(
                    "Juice Shop already has this account and the stored password does not "
                    "log in; run `./labctl.sh reset juice-shop --authorized`")
            raise ExternalLabError(f"Juice Shop registration failed: HTTP {reg.status_code}")
        notes.append("account registered")
        token = login()
        if token is None:
            raise ExternalLabError("Juice Shop login failed right after registration")
    # whoami (like /profile) reads the `token` cookie the app's own JS sets.
    who = client.request("GET", "/rest/user/whoami", anonymous=True, cookies={"token": token})
    try:
        email = who.json()["user"]["email"]
    except (ValueError, KeyError, TypeError):
        email = None
    if email != cred.username:
        raise ExternalLabError("Juice Shop whoami does not name the logged-in account")
    anon = client.request("GET", "/profile", anonymous=True)
    authed = client.request("GET", "/profile", anonymous=True, cookies={"token": token})
    if authed.status_code != 200 or anon.status_code == 200:
        raise ExternalLabError(f"Juice Shop /profile: {anon.status_code} anonymous, "
                               f"{authed.status_code} with the token (want non-200 / 200)")
    notes.append("login verified")
    return notes


_CSRF_FIELD = re.compile(r'name="_csrf_token"[^>]*value="([^"]+)"')


def bootstrap_secdevlabs_gossip_world(client: _LabClient, cred: ResolvedCredential, *,
                                      deadline: float = 180.0,
                                      clock: Callable[[], float] = time.monotonic,
                                      sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Log in through the app's own form (its session-bound ``_csrf_token`` read from the
    form first), registering the account the same way when the login fails, and verify
    it by a positive differential: ``/gossip`` answers 200 with the session and
    redirects to ``/login`` without it."""
    meta = LAB_META["secdevlabs-gossip-world"]
    wait_ready(client, meta.ready_path, deadline=deadline, clock=clock, sleep=sleep)
    notes: list[str] = []

    def post_form(path: str, fields: dict[str, str]) -> Any:
        m = _CSRF_FIELD.search(client.request("GET", path).text or "")
        if m is None:
            raise ExternalLabError(f"gossip-world {path}: no _csrf_token in the form")
        return client.request("POST", path, data={**fields, "_csrf_token": m.group(1)})

    def logged_in() -> bool:
        r = post_form("/login", {"username": cred.username, "password": cred.password})
        return r.status_code == 302 and r.headers.get("Location", "").endswith("/gossip")

    if not logged_in():
        reg = post_form("/register", {"username": cred.username, "password1": cred.password,
                                      "password2": cred.password})
        if reg.status_code != 302 or not reg.headers.get("Location", "").endswith("/login"):
            raise ExternalLabError(f"gossip-world registration failed: HTTP {reg.status_code}")
        notes.append("account registered")
        if not logged_in():
            raise ExternalLabError(
                "gossip-world login failed after registration (an account of that name with "
                "another password? run `./labctl.sh reset secdevlabs-gossip-world --authorized`)")
    authed = client.request("GET", "/gossip")
    anon = client.request("GET", "/gossip", anonymous=True)
    if authed.status_code != 200 or anon.status_code != 302:
        raise ExternalLabError(f"gossip-world /gossip: {anon.status_code} anonymous, "
                               f"{authed.status_code} logged in (want 302 / 200)")
    notes.append("login verified")
    # the comment form lives on a gossip's own page: a fresh lab has none, so one is
    # seeded (once), and /gossip/1 -- the ground truth's comment point -- exists
    if 'href="/gossip/1"' not in (authed.text or ""):
        post_form("/newgossip", {"title": "Welcome", "subtitle": "a seeded gossip",
                                 "text": "The lab's first gossip (bootstrap)."})
        if 'href="/gossip/1"' not in (client.request("GET", "/gossip").text or ""):
            raise ExternalLabError("gossip-world: the seeded gossip is not /gossip/1 "
                                   "(reset the lab: ./labctl.sh reset ... --authorized)")
        notes.append("gossip 1 seeded")
    return notes


def _ecommerce_login(client: _LabClient, username: str, password: str) -> Any:
    return client.request("POST", "/login", params={"format": "json"},
                          json={"username": username, "password": password})


def bootstrap_secdevlabs_ecommerce_api(client: _LabClient, cred: ResolvedCredential, *,
                                       deadline: float = 180.0,
                                       clock: Callable[[], float] = time.monotonic,
                                       sleep: Callable[[float], None] = time.sleep
                                       ) -> list[str]:
    """Log in through the API's JSON ``/login``, registering the account through
    ``/register`` when the login fails, and verify it by a positive differential: the
    password logs in with the account's ``user_id``, a wrong one is refused."""
    meta = LAB_META["secdevlabs-ecommerce-api"]
    wait_ready(client, meta.ready_path, deadline=deadline, clock=clock, sleep=sleep)
    notes: list[str] = []
    if _ecommerce_login(client, cred.username, cred.password).status_code != 200:
        reg = client.request("POST", "/register",
                             json={"username": cred.username, "password": cred.password})
        if reg.status_code != 201:
            raise ExternalLabError(
                f"ecommerce-api registration failed: HTTP {reg.status_code} (an account of "
                f"that name with another password? run `./labctl.sh reset "
                f"secdevlabs-ecommerce-api --authorized`)")
        notes.append("account registered")
    good = _ecommerce_login(client, cred.username, cred.password)
    bad = _ecommerce_login(client, cred.username, cred.password + "-wrong")
    if good.status_code != 200 or bad.status_code != 400 or \
            not _ecommerce_user_id(good):
        raise ExternalLabError(
            f"ecommerce-api login: {good.status_code} with the password, {bad.status_code} "
            f"without (want 200 with a user_id / 400; an account of that name with another "
            f"password? run `./labctl.sh reset secdevlabs-ecommerce-api --authorized`)")
    notes.append("login verified")
    return notes


def _ecommerce_user_id(resp: Any) -> str | None:
    try:
        value = resp.json().get("user_id")
    except (ValueError, AttributeError):
        return None
    return value if isinstance(value, str) and value else None


def ecommerce_account_attributes(client: _LabClient, cred: ResolvedCredential
                                 ) -> dict[str, str]:
    """The account's ``user_id``, which its login names (FR-LAB-309)."""
    user_id = _ecommerce_user_id(_ecommerce_login(client, cred.username, cred.password))
    if user_id is None:
        raise ExternalLabError("ecommerce-api login named no user_id")
    return {"user_id": user_id}


def _mongection_login(client: _LabClient, email: str, password: str) -> str:
    return client.request("POST", "/login",
                          json={"email": email, "password": password}).text or ""


def bootstrap_secdevlabs_mongection(client: _LabClient, cred: ResolvedCredential, *,
                                    deadline: float = 180.0,
                                    clock: Callable[[], float] = time.monotonic,
                                    sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Register the account through the app's JSON ``/register`` when its JSON ``/login``
    fails, and verify it by a positive differential: the password answers the welcome
    page naming the account, a wrong one ``Bad Credentials``. A fresh lab has no
    account, and its NoSQL injection (an operator in both login fields) answers one:
    without it the ground truth's positives cannot be observed (BUG-0640)."""
    meta = LAB_META["secdevlabs-mongection"]
    wait_ready(client, meta.ready_path, deadline=deadline, clock=clock, sleep=sleep)
    notes: list[str] = []
    welcome = "Hello, Welcome Again!"
    if welcome not in _mongection_login(client, cred.username, cred.password):
        reg = client.request("POST", "/register", json={
            "name": "fuzzlab", "email": cred.username, "password": cred.password})
        if "Welcome to Mongection System" not in (reg.text or ""):
            raise ExternalLabError(
                f"mongection registration failed: HTTP {reg.status_code} "
                f"{(reg.text or '')[:60]!r} (an account of that email with another "
                f"password? run `./labctl.sh reset secdevlabs-mongection --authorized`)")
        notes.append("account registered")
    good = _mongection_login(client, cred.username, cred.password)
    bad = _mongection_login(client, cred.username, cred.password + "-wrong")
    if welcome not in good or cred.username not in good or "Bad Credentials" not in bad:
        raise ExternalLabError("mongection login: the password does not answer the welcome "
                               "page naming the account, or a wrong one is not refused")
    notes.append("login verified")
    return notes


def _mutillidae_login(client: _LabClient, cred: ResolvedCredential) -> bool:
    """Mutillidae's own login form: a 302 to ``popUpNotificationCode=AU1`` is a
    success, a 200 a failure. The form page is read first: a login on a request with no
    session cookie yet is not kept (measured, CC-LAB-0340)."""
    client.request("GET", "/index.php?page=login.php")
    r = client.request("POST", "/index.php?page=login.php",
                       data={"username": cred.username, "password": cred.password,
                             "login-php-submit-button": "Login"})
    return r.status_code == 302 and "popUpNotificationCode=AU1" in r.headers.get(
        "Location", "")


def bootstrap_mutillidae(client: _LabClient, cred: ResolvedCredential, *,
                         deadline: float = 180.0,
                         clock: Callable[[], float] = time.monotonic,
                         sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Build Mutillidae's database when the app says it is offline (its own
    ``set-up-database.php``; the database is on tmpfs, so after every start), then log
    in through its form, registering the account the same way when the login fails, and
    verify it by a positive differential: an authenticated page (``user-info.php``)
    answers 200 with the session and redirects to the login without it. Last, the
    directory is checked through the app: the conference-room lookup lists ``1F104``
    (loaded by `load_mutillidae_directory`)."""
    meta = LAB_META["mutillidae"]
    wait_ready(client, meta.ready_path, deadline=deadline, clock=clock, sleep=sleep)
    notes: list[str] = []
    home = client.request("GET", "/")
    if "database-offline.php" in client.location(home, "/"):
        # the database starts after the web tier: retried until the script connects
        end = clock() + deadline
        while True:
            setup = client.request("GET", "/set-up-database.php", timeout=120.0)
            if setup.status_code == 200 and "Connected to MySQL server" in (setup.text or ""):
                break
            if clock() >= end:
                raise ExternalLabError(f"mutillidae set-up-database.php did not connect to "
                                       f"the database within {deadline:.0f}s (HTTP "
                                       f"{setup.status_code})")
            sleep(2.0)
        notes.append("database built")
    if not _mutillidae_login(client, cred):
        reg = client.request("POST", "/index.php?page=register.php",
                             data={"username": cred.username, "password": cred.password,
                                   "confirm_password": cred.password,
                                   "my_signature": "fuzzlab lab account",
                                   "firstname": "Fuzz", "lastname": "Lab",
                                   "register-php-submit-button": "Create Account"})
        if f"Account created for {cred.username}" not in (reg.text or ""):
            raise ExternalLabError(f"mutillidae registration failed: HTTP {reg.status_code}")
        notes.append("account registered")
        if not _mutillidae_login(client, cred):
            raise ExternalLabError(
                "mutillidae login failed after registration (an account of that name with "
                "another password? run `./labctl.sh reset mutillidae --authorized`)")
    page = "/index.php?page=user-info.php"
    authed = client.request("GET", page)
    anon = client.request("GET", page, anonymous=True)
    if authed.status_code != 200 or anon.status_code != 302:
        raise ExternalLabError(f"mutillidae {page}: {anon.status_code} anonymous, "
                               f"{authed.status_code} logged in (want 302 / 200)")
    notes.append("login verified")
    rooms = client.request("POST", "/index.php?page=conference-room-lookup.php",
                           data={"default_room_common_name": "1F104"})
    if ">1F104<" not in (rooms.text or ""):
        raise ExternalLabError("mutillidae: the directory has no room 1F104 (load it: "
                               "`./labctl.sh bootstrap mutillidae --authorized`)")
    notes.append("directory verified")
    return notes


def load_mutillidae_directory(engine: str, project: str, *,
                              runner: Callable[..., Any] | None = None,
                              ldif: Path | None = None, deadline: float = 120.0,
                              clock: Callable[[], float] = time.monotonic,
                              sleep: Callable[[float], None] = time.sleep) -> str:
    """Load Mutillidae's LDIF into the project's directory container, as upstream's
    README does (``ldapadd -c``, the admin bind, over the container's own loopback):
    the file is re-verified against its pin and sent on stdin, so nothing is mounted.
    Entries already there are kept (``-c``: exit 68, "already exists"); an exit 255
    (slapd not answering yet) is retried until ``deadline``. The container
    is found by the exact compose project and service labels. Sends nothing over the
    network from this host; run only under ``--authorized`` (it changes the lab)."""
    from fuzzlab.procutil import run_bounded
    run = runner or run_bounded
    path = fetch_mutillidae_ldif(dest=ldif) if ldif is None else ldif
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != MUTILLIDAE_LDIF_SHA256:
        raise ExternalLabError("mutillidae.ldif does not match its pin")
    res = run([engine, "ps", "-q", "--filter", f"label={PROJECT_LABEL}={project}",
               "--filter", "label=com.docker.compose.service=directory"], timeout=30)
    ids = (res.stdout or "").split()
    if res.returncode != 0 or len(ids) != 1:
        raise ExternalLabError(f"mutillidae: want one running directory container of "
                               f"{project}, found {len(ids)}")
    dn, password = MUTILLIDAE_LDAP_BIND
    end = clock() + deadline
    while True:
        res = run([engine, "exec", "-i", ids[0], "ldapadd", "-c", "-x", "-H",
                   "ldap://localhost", "-D", dn, "-w", password], timeout=60,
                  input=data.decode("utf-8"))
        # 255: slapd is not answering yet (it starts after the container does)
        if res.returncode != 255 or clock() >= end:
            break
        sleep(2.0)
    if res.returncode not in (0, 68):
        raise ExternalLabError(f"mutillidae: ldapadd exited {res.returncode}: "
                               f"{(res.stderr or '').strip()[-200:]}")
    added = (res.stdout or "").count("adding new entry")
    return f"directory loaded ({added} entries sent)"


_NODEGOAT_ALLOCATIONS_LINK = re.compile(r'href="/allocations/(\d+)"')


def _nodegoat_login(client: _LabClient, cred: ResolvedCredential) -> Any:
    return client.request("POST", "/login",
                          data={"userName": cred.username, "password": cred.password})


def bootstrap_nodegoat(client: _LabClient, cred: ResolvedCredential, *,
                       deadline: float = 180.0, clock: Callable[[], float] = time.monotonic,
                       sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Log in through the app's own form (no CSRF token: upstream's csurf is commented
    out) and verify it by a positive differential: the login redirects to
    ``/dashboard``, which answers 200 with the session and redirects to ``/login``
    without it. The accounts are upstream's seed (re-created at every start), never
    registered here."""
    meta = LAB_META["nodegoat"]
    wait_ready(client, meta.ready_path, deadline=deadline, clock=clock, sleep=sleep)
    r = _nodegoat_login(client, cred)
    if r.status_code != 302 or not r.headers.get("Location", "").endswith("/dashboard"):
        raise ExternalLabError(
            f"NodeGoat login of {cred.username!r} failed: HTTP {r.status_code} (the seeded "
            f"accounts are re-created at every start with the README's passwords)")
    authed = client.request("GET", "/dashboard")
    anon = client.request("GET", "/dashboard", anonymous=True)
    if authed.status_code != 200 or anon.status_code != 302:
        raise ExternalLabError(f"NodeGoat /dashboard: {anon.status_code} anonymous, "
                               f"{authed.status_code} logged in (want 302 / 200)")
    return ["login verified"]


def nodegoat_account_attributes(client: _LabClient, cred: ResolvedCredential
                                ) -> dict[str, str]:
    """The account's ``user_id``: the one ``/allocations/<id>`` link its own dashboard
    shows (FR-LAB-330)."""
    _nodegoat_login(client, cred)
    ids = set(_NODEGOAT_ALLOCATIONS_LINK.findall(client.request("GET", "/dashboard").text
                                                 or ""))
    if len(ids) != 1:
        raise ExternalLabError("NodeGoat's dashboard names no single allocations link")
    return {"user_id": ids.pop()}


def _vampi_login(client: _LabClient, cred: ResolvedCredential) -> str | None:
    """The ``auth_token`` of a JSON login, or None (VAmPI answers a failed login 200
    with ``status: fail``)."""
    r = client.request("POST", "/users/v1/login",
                       json={"username": cred.username, "password": cred.password})
    try:
        token = r.json().get("auth_token") if r.status_code == 200 else None
    except (ValueError, AttributeError):
        return None
    return token if isinstance(token, str) and token else None


def _vampi_book(cred: ResolvedCredential) -> str:
    """The title of the one book the bootstrap gives each account (titles are unique)."""
    return f"{cred.username}-book"


def bootstrap_vampi(client: _LabClient, cred: ResolvedCredential, *, deadline: float = 180.0,
                    clock: Callable[[], float] = time.monotonic,
                    sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Create VAmPI's tables when they are missing (``/createdb`` drops and re-creates
    them, so it is never called on a populated database), log in through the JSON
    ``/users/v1/login`` -- registering the account (never as admin) through
    ``/users/v1/register`` when the login fails -- give the account one book of its own,
    and verify by a positive differential: ``/me`` answers 200 naming the account, not
    an admin, with ``Authorization: Bearer <auth_token>`` and 401 without it."""
    wait_ready(client, LAB_META["vampi"].ready_path, deadline=deadline, clock=clock,
               sleep=sleep)
    notes: list[str] = []
    if client.request("GET", "/users/v1").status_code != 200:     # no tables yet
        if client.request("GET", "/createdb").status_code != 200:
            raise ExternalLabError("VAmPI /createdb failed")
        notes.append("database created")
    token = _vampi_login(client, cred)
    if token is None:
        reg = client.request("POST", "/users/v1/register", json={
            "username": cred.username, "password": cred.password,
            "email": f"{cred.username}@fuzzlab.lab"})
        if reg.status_code != 200 or "Successfully registered" not in reg.text:
            raise ExternalLabError(
                f"VAmPI registration failed: HTTP {reg.status_code} (an account of that "
                f"name with another password? run `./labctl.sh reset vampi --authorized`)")
        notes.append("account registered")
        token = _vampi_login(client, cred)
        if token is None:
            raise ExternalLabError("VAmPI login failed right after registration")
    auth = {"Authorization": f"Bearer {token}"}
    authed = client.request("GET", "/me", anonymous=True, headers=auth)
    anon = client.request("GET", "/me", anonymous=True)
    try:
        data = authed.json().get("data") or {}
    except (ValueError, AttributeError):
        data = {}
    # a positive differential: refused anonymously (a client error), 200 with the token
    if authed.status_code != 200 or not 400 <= anon.status_code < 500 or \
            data.get("username") != cred.username or data.get("admin") is not False:
        raise ExternalLabError(f"VAmPI /me: {anon.status_code} anonymous, "
                               f"{authed.status_code} with the token (want 4xx / 200 naming "
                               f"the account, not an admin)")
    notes.append("login verified")
    title = _vampi_book(cred)
    book = client.request("POST", "/books/v1", anonymous=True, headers=auth,
                          json={"book_title": title, "secret": f"secret of {cred.username}"})
    if book.status_code == 200:
        notes.append("book added")
    elif not (book.status_code == 400 and "Already exists" in book.text):
        raise ExternalLabError(f"VAmPI could not add the account's book: HTTP "
                               f"{book.status_code}")
    return notes


def vampi_account_attributes(client: _LabClient, cred: ResolvedCredential
                             ) -> dict[str, str]:
    """The account's ``username`` (``/users/v1/{username}/...`` names it) and the title
    of its own book, which ``/books/v1/{book_title}`` answers to its owner with the
    owner's username."""
    token = _vampi_login(client, cred)
    title = _vampi_book(cred)
    if token is None:
        raise ExternalLabError("VAmPI login failed")
    r = client.request("GET", f"/books/v1/{title}", anonymous=True,
                       headers={"Authorization": f"Bearer {token}"})
    try:
        owner = r.json().get("owner") if r.status_code == 200 else None
    except (ValueError, AttributeError):
        owner = None
    if owner != cred.username:
        raise ExternalLabError("VAmPI does not answer the account's own book to it")
    return {"book_title": title, "username": cred.username}
def _dvws_login(client: _LabClient, cred: ResolvedCredential) -> tuple[Any, str | None]:
    """POST /api/v2/login (JSON); the answer's ``token`` is the Bearer JWT."""
    r = client.request("POST", "/api/v2/login",
                       json={"username": cred.username, "password": cred.password})
    try:
        token = r.json().get("token") if r.status_code == 200 else None
    except (ValueError, AttributeError):
        token = None
    return r, token if isinstance(token, str) and token else None


def bootstrap_dvws_node(client: _LabClient, cred: ResolvedCredential, *,
                        deadline: float = 180.0, clock: Callable[[], float] = time.monotonic,
                        sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Log in through the JSON login, registering the account through
    ``POST /api/v2/users`` (username and password only) when the login says it does not
    exist (upstream's seed drops every account at each start), and verify it by a
    positive differential: ``/api/v2/notes`` answers 200 with the Bearer token and 401
    without it."""
    meta = LAB_META["dvws-node"]
    wait_ready(client, meta.ready_path, deadline=deadline, clock=clock, sleep=sleep)
    notes: list[str] = []
    r, token = _dvws_login(client, cred)
    if r.status_code == 404:
        reg = client.request("POST", "/api/v2/users",
                             json={"username": cred.username, "password": cred.password})
        if reg.status_code != 201:
            raise ExternalLabError(f"DVWS-node registration of {cred.username!r} failed: "
                                   f"HTTP {reg.status_code}")
        notes.append("account registered")
        r, token = _dvws_login(client, cred)
    if token is None:
        raise ExternalLabError(
            f"DVWS-node login of {cred.username!r} failed: HTTP {r.status_code} (an account "
            f"of that name with another password? restart the lab: its seed drops every "
            f"account)")
    authed = client.request("GET", "/api/v2/notes", headers={"Authorization": f"Bearer {token}"})
    anon = client.request("GET", "/api/v2/notes", anonymous=True)
    # a positive differential: refused anonymously (a client error), 200 with the token
    if authed.status_code != 200 or not 400 <= anon.status_code < 500:
        raise ExternalLabError(f"DVWS-node /api/v2/notes: {anon.status_code} anonymous, "
                               f"{authed.status_code} with the token (want 4xx / 200)")
    notes.append("login verified")
    return notes


def dvws_node_account_attributes(client: _LabClient, cred: ResolvedCredential
                                 ) -> dict[str, str]:
    """The account's ``note_id``: the numeric id of a private note of its own (created
    once, named after the account), which ``/api/v2/notes/{noteId}`` hands any caller."""
    _r, token = _dvws_login(client, cred)
    if token is None:
        raise ExternalLabError("DVWS-node login failed while reading the account's note")
    auth = {"Authorization": f"Bearer {token}"}
    name = f"fuzzlab-{cred.username}"
    try:
        mine = [n for n in client.request("GET", "/api/v2/notes", headers=auth).json()
                if isinstance(n, dict) and n.get("name") == name]
        if not mine:
            mine = [client.request("POST", "/api/v2/notes", headers=auth,
                                   json={"name": name, "body": "fuzzlab account note",
                                         "type": "secret"}).json()]
        note_id = mine[0].get("_id")
    except (ValueError, AttributeError, TypeError):
        note_id = None
    if not isinstance(note_id, int):
        raise ExternalLabError("DVWS-node named no numeric id for the account's note")
    return {"note_id": str(note_id)}
_RAILSGOAT_USER_LINK = re.compile(r'href="/users/(\d+)/')


def _railsgoat_login(client: _LabClient, cred: ResolvedCredential) -> Any:
    # upstream's ApplicationController has protect_from_forgery commented out: the
    # form's authenticity_token is not needed
    return client.request("POST", "/sessions",
                          data={"email": cred.username, "password": cred.password})


def bootstrap_railsgoat(client: _LabClient, cred: ResolvedCredential, *,
                        deadline: float = 180.0, clock: Callable[[], float] = time.monotonic,
                        sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Log in through the app's own form (POST /sessions: email, password) and verify it
    by a positive differential: the login redirects to ``/dashboard/home``, which answers
    200 with the session cookie and redirects to the login page without it. The accounts
    are upstream's seed (re-created at every start), never registered here."""
    meta = LAB_META["railsgoat"]
    wait_ready(client, meta.ready_path, deadline=deadline, clock=clock, sleep=sleep)
    r = _railsgoat_login(client, cred)
    if r.status_code != 302 or not r.headers.get("Location", "").endswith("/dashboard/home"):
        raise ExternalLabError(
            f"RailsGoat login of {cred.username!r} failed: HTTP {r.status_code} (the seeded "
            f"accounts are re-created at every start with db/seeds.rb's passwords)")
    authed = client.request("GET", "/dashboard/home")
    anon = client.request("GET", "/dashboard/home", anonymous=True)
    if authed.status_code != 200 or anon.status_code != 302:
        raise ExternalLabError(f"RailsGoat /dashboard/home: {anon.status_code} anonymous, "
                               f"{authed.status_code} logged in (want 302 / 200)")
    return ["login verified"]


def railsgoat_account_attributes(client: _LabClient, cred: ResolvedCredential
                                 ) -> dict[str, str]:
    """The account's ``user_id``: the one ``/users/<id>/`` its own dashboard links to."""
    _railsgoat_login(client, cred)
    ids = set(_RAILSGOAT_USER_LINK.findall(client.request("GET", "/dashboard/home").text
                                           or ""))
    if len(ids) != 1:
        raise ExternalLabError("RailsGoat's dashboard names no single /users/<id>/ link")
    return {"user_id": ids.pop()}


_RAILSGOAT_CREDENTIAL_ROW = re.compile(
    r"<tr>\s*<td[^>]*>\s*([^<\s]+@[^<\s]+)\s*</td>\s*<td[^>]*>\s*([^<]+?)\s*</td>")


def railsgoat_published_credentials(client: _LabClient) -> dict[str, str]:
    """``{email: password}`` of the seeded accounts, from the app's own
    ``/tutorials/credentials`` table (upstream publishes them there, as NodeGoat's README
    publishes its seed passwords)."""
    r = client.request("GET", "/tutorials/credentials", anonymous=True)
    if r.status_code != 200:
        raise ExternalLabError(f"RailsGoat /tutorials/credentials: HTTP {r.status_code}")
    return dict(_RAILSGOAT_CREDENTIAL_ROW.findall(r.text or ""))


#: Labs whose accounts are the app's own seed (``may_generate_password=False``) and whose
#: running app publishes their passwords: read from it into the keyring by
#: `seed_published_credentials` (FR-LAB-425), so an unattended run (the held-out
#: benchmark, a fresh keyring, no TTY) can bootstrap without a prompt.
_PUBLISHED_CREDENTIALS = {"railsgoat": railsgoat_published_credentials}


def seed_published_credentials(name: str, *, environ: Mapping[str, str] | None = None,
                               host: str = "127.0.0.1", keyring_store: Any = None,
                               session_factory: Callable[[], Any] | None = None,
                               deadline: float = 180.0) -> list[str]:
    """Store, for each of ``name``'s accounts the keyring has no credential for, the
    password the running lab publishes for its default username. Returns the identities
    stored. Refuses a lab that publishes none, and an account it does not list."""
    meta = lab_meta(name)
    reader = _PUBLISHED_CREDENTIALS.get(meta.name)
    if reader is None:
        raise ExternalLabError(f"{meta.name} publishes no seeded credentials")
    if keyring_store is None:
        from fuzzlab.core.credentials import CredentialStore
        keyring_store = CredentialStore(allow_env=False)
    client = _LabClient(base_url(meta, environ), session_factory=session_factory)
    wait_ready(client, meta.ready_path, deadline=deadline)
    published = None
    stored = []
    for account in meta.accounts():
        if keyring_store.get(host, account.identity) is not None:
            continue
        if published is None:
            published = reader(client)
        pw = published.get(account.default_username)
        if not pw:
            raise ExternalLabError(f"{meta.name} publishes no password for "
                                   f"{account.default_username!r}")
        keyring_store.set(host, account.identity, account.default_username, pw)
        stored.append(account.identity)
    return stored


_BOOTSTRAPS = {"bwapp": bootstrap_bwapp, "juice-shop": bootstrap_juice_shop,
               "mutillidae": bootstrap_mutillidae,
               "secdevlabs-gossip-world": bootstrap_secdevlabs_gossip_world,
               "secdevlabs-ecommerce-api": bootstrap_secdevlabs_ecommerce_api,
               "secdevlabs-mongection": bootstrap_secdevlabs_mongection,
               "nodegoat": bootstrap_nodegoat,
               "vampi": bootstrap_vampi}
#: Labs whose accounts have values of their own a ground truth names (`account_value`,
#: FR-LAB-309): read after the verified login, stored with the credential.
_ACCOUNT_ATTRIBUTES = {"secdevlabs-ecommerce-api": ecommerce_account_attributes,
                       "nodegoat": nodegoat_account_attributes,
                       "vampi": vampi_account_attributes}
_BOOTSTRAPS["dvws-node"] = bootstrap_dvws_node
_ACCOUNT_ATTRIBUTES["dvws-node"] = dvws_node_account_attributes
_BOOTSTRAPS["railsgoat"] = bootstrap_railsgoat
_ACCOUNT_ATTRIBUTES["railsgoat"] = railsgoat_account_attributes


def bootstrap(name: str, *, environ: Mapping[str, str] | None = None,
              port: int | None = None, host: str = "127.0.0.1",
              keyring_store: Any = None, opened_store: Any = None,
              prompt: Callable[[str], str] | None = None, generate: bool = True,
              session_factory: Callable[[], Any] | None = None,
              deadline: float = 180.0) -> BootstrapResult:
    """Bring ``name`` to a usable state and store its lab identity (only after a verified
    login). ``host``/``port`` name the running lab's published address (default: the
    port variable's ``127.0.0.1`` base)."""
    meta = lab_meta(name)
    if meta.identity is None:
        return BootstrapResult(name, None, "none", False, ["no login: nothing to bootstrap"])
    shown = f"[{host}]" if ":" in host else host
    origin = f"http://{shown}:{port}" if port else base_url(meta, environ)
    client = _LabClient(origin, session_factory=session_factory)
    host = urlsplit(client.origin).hostname or "127.0.0.1"
    if keyring_store is None or opened_store is None:
        from fuzzlab.core.config import load_config
        from fuzzlab.core.credentials import CredentialStore
        if keyring_store is None:
            keyring_store = CredentialStore(allow_env=False)
        if opened_store is None:
            opened_store = CredentialStore.open(load_config())
    results = []
    for account in meta.accounts():
        # each account on a fresh client: its cookies never meet another account's
        client = _LabClient(origin, session_factory=session_factory) if results else client
        cred = resolve_credential(account, host=host, keyring_store=keyring_store,
                                  opened_store=opened_store, prompt=prompt,
                                  generate=generate)
        notes = _BOOTSTRAPS[name](client, cred, deadline=deadline)
        stored = False
        if cred.source != "keyring":
            keyring_store.set(host, account.identity, cred.username, cred.password)
            stored = True
        if name in _ACCOUNT_ATTRIBUTES:          # after `set`, which drops old ones
            attrs = _ACCOUNT_ATTRIBUTES[name](client, cred)
            keyring_store.set_attributes(host, account.identity, attrs)
            notes.append(f"account values stored: {', '.join(sorted(attrs))}")
        results.append(BootstrapResult(name, account.identity, cred.source, stored, notes))
    first, *peers = results
    first.peers = peers
    return first


# --- CLI ----------------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m fuzzlab.lab_fixtures.external",
                                description="External lab fixtures (run via lab/labctl.sh).")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("info", help="print `<project> <port> <url>` for a lab")
    s.add_argument("lab")
    s = sub.add_parser("fetch", help="fetch and verify a lab's pinned source (bWAPP's zip, "
                                     "the Crawl Maze's commit) into the cache")
    s.add_argument("lab")
    s = sub.add_parser("check-config", help="refuse a rendered compose config that is not "
                                            "loopback-only (reads the file or stdin)")
    s.add_argument("lab")
    s.add_argument("--file", default="-")
    s = sub.add_parser("check-exposure", help="inspect the running project (fail closed)")
    s.add_argument("lab")
    s.add_argument("--engine", required=True, choices=["docker", "podman"])
    s.add_argument("--project", required=True)
    s = sub.add_parser("seed-credentials", help="store the seeded accounts' passwords the "
                                                "running lab publishes (sends traffic: needs "
                                                "--authorized)")
    s.add_argument("lab")
    s.add_argument("--authorized", action="store_true")
    s = sub.add_parser("bootstrap", help="install / register the lab identity "
                                         "(sends traffic: needs --authorized)")
    s.add_argument("lab")
    s.add_argument("--authorized", action="store_true")
    s.add_argument("--engine", choices=["docker", "podman"],
                   help="with --project: target the port the running project publishes")
    s.add_argument("--project")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        meta = lab_meta(args.lab)
        if args.cmd == "info":
            project = compose_project(discover_labs()[meta.name])
            print(f"{project} {lab_port(meta)} {base_url(meta)}{meta.app_path}")
            return 0
        if args.cmd == "fetch":
            if meta.name in SECDEVLABS_APPS:
                print(f"secDevLabs at {SECDEVLABS_COMMIT[:12]}, {meta.name}'s app and its "
                      f"verified dependencies: {fetch_secdevlabs_app(meta.name)}")
                return 0
            if meta.name == "mutillidae":
                print(f"mutillidae.ldif verified: {fetch_mutillidae_ldif()}")
                return 0
            if meta.name == "nodegoat":
                print(f"NodeGoat at {NODEGOAT_COMMIT[:12]} (files sha256 "
                      f"{NODEGOAT_TREE_SHA256[:12]}) and its verified packages: "
                      f"{fetch_nodegoat()}")
                return 0
            if meta.name == "dvws-node":
                print(f"DVWS-node at {DVWS_NODE_COMMIT[:12]} (files sha256 "
                      f"{DVWS_NODE_TREE_SHA256[:12]}) and its verified packages: "
                      f"{fetch_dvws_node()}")
                return 0
            if meta.name == "railsgoat":
                print(f"RailsGoat at {RAILSGOAT_COMMIT[:12]} (files sha256 "
                      f"{RAILSGOAT_TREE_SHA256[:12]}) and its lock-verified gems: "
                      f"{fetch_railsgoat()}")
                return 0
            if meta.name == "security-crawl-maze":
                print(f"crawl maze source at {CRAWL_MAZE_COMMIT[:12]}: {fetch_crawl_maze()}")
                print(f"crawl maze wheels verified: {fetch_crawl_maze_wheels()}")
                return 0
            if meta.name != "bwapp":
                print(f"{meta.name}: nothing to fetch (pinned image)")
                return 0
            print(f"bWAPP zip verified: {fetch_bwapp()}")
            return 0
        if args.cmd == "check-config":
            text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text("utf-8")
            problems = config_problems(load_compose_document(text))
            for line in problems:
                print(f"REFUSED: {line}", file=sys.stderr)
            return 1 if problems else 0
        if args.cmd == "check-exposure":
            problems, notes = check_exposure(args.project, args.engine)
            for line in notes:
                print(f"note: {line}")
            for line in problems:
                print(f"EXPOSED: {line}", file=sys.stderr)
            return 3 if problems else 0
        if args.cmd == "seed-credentials":
            if not args.authorized:
                print("seed-credentials sends traffic to the lab: pass --authorized",
                      file=sys.stderr)
                return 2
            stored = seed_published_credentials(meta.name)
            print(f"{meta.name}: published credentials stored for "
                  f"{', '.join(stored) or 'no account (all already in the keyring)'}")
            return 0
        if args.cmd == "bootstrap":
            if not args.authorized:
                print("bootstrap sends traffic to the lab: pass --authorized "
                      "(lab-only, your own loopback lab)", file=sys.stderr)
                return 2
            host, port = "127.0.0.1", None
            if args.project and args.engine:
                host, port = published_port(meta, args.project, args.engine)
                if meta.name == "mutillidae":           # FR-LAB-341: before the login
                    print(f"{meta.name}: "
                          + load_mutillidae_directory(args.engine, args.project))
            res = bootstrap(meta.name, port=port, host=host, prompt=_tty_prompt())
            if res.identity is None:
                print(f"{res.lab}: " + "; ".join(res.notes))
                return 0
            for one in [res, *res.peers]:
                print(f"{one.lab}: identity {one.identity!r} ready "
                      f"({one.credential_source}{', stored' if one.stored else ''}); "
                      + "; ".join(one.notes))
            return 0
    except ExternalLabError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - credential/keyring/HTTP/OS errors: one line
        from fuzzlab.core.credentials import CredentialError
        import requests
        if not isinstance(exc, (CredentialError, requests.RequestException, OSError)):
            raise
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())



def crawl_exclusions(name: str) -> tuple[str, ...]:
    """A bundled lab's crawl exclusions (`LabMeta.crawl_exclude`, FR-LAB-410); raises
    `ExternalLabError` for a lab with no entry."""
    if name not in LAB_META:
        raise ExternalLabError(f"external lab {name!r} has no LAB_META entry")
    return LAB_META[name].crawl_exclude
