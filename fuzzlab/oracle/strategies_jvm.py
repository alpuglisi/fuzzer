"""Confirmation strategies for read sinks of JVM web stacks (CC-FUZZ-0630,
FR-FUZZ-630/631). Black-box: nothing here names a lab's paths, parameters or values;
each target behaviour relied on is measured on two independent targets or cited
(CC-FUZZ-0630's evidence):

* **Classpath resource traversal.** A handler that reads
  ``getClass().getResourceAsStream(BASE + value)`` resolves ``..`` inside a *directory*
  classpath, never above its root (so ``/etc/passwd``, what
  `PathTraversalFsPathReadStrategy` looks for, is out of reach), while the root's own
  ``application.properties`` is not. Measured on (1) SasanLabs VulnerableApp 2.2.115
  (a Jib image: a directory classpath) and (2) a standalone JDK 11 program
  (``/scripts/pt/../../application.properties`` read; ``../../../etc/passwd`` null);
  Spring Boot loads ``application.properties`` from "the classpath root" (Spring Boot
  reference, Externalized Configuration). **Limit (measured on JDK 11):** inside a jar
  classpath (a packaged fat jar) the class loader does not resolve ``..``, so such a
  read is out of this strategy's reach: a false negative, never a false positive.
* **A URL fetcher that takes ``file:``.** Measured on JDK 11 (``new URL(u).openStream()``)
  and CPython 3.13 (``urllib.request.urlopen``): ``file:///etc/passwd`` and
  ``file:/etc/passwd`` read the file, a bare ``/etc/passwd`` is refused (the control);
  listed as an SSRF payload by PayloadsAllTheThings (Server Side Request Forgery, "File").
  It proves the read in-band, so it decides where the target cannot reach the scanner's
  loopback callback.

Each confirms on a file-content marker present for the payload and absent from a
compared control carrying the same file name without the read primitive (no ``..``; no
``file:`` scheme), so an app that always shows such text is never confirmed
(BUG-0117's control rule)."""

from __future__ import annotations

import re

from fuzzlab.core import trace
from fuzzlab.oracle.probe import Verdict
from fuzzlab.oracle.strategies import (_PASSWD_MARKER, _observed, ConfirmationStrategy)

#: A Spring Boot ``application.properties`` read back: a key from Spring Boot's own
#: "Common Application Properties" list, then ``=``. A handler that reads line by line
#: may join the lines with no separator, so the marker is not line-anchored; a dotted
#: Spring key followed by ``=`` is not text a page carries by chance.
_SPRING_PROPERTIES_MARKER = re.compile(
    r"(?<![\w.])(?:server\.(?:port|servlet\.context-path)|spring\.(?:application\.name|"
    r"datasource\.[\w.-]+|profiles\.active|jpa\.[\w.-]+|h2\.console\.[\w.-]+))\s*=")
#: (classpath-root file, marker): what a classpath resource read can reach. One entry:
#: a servlet ``WEB-INF/web.xml`` sits above ``WEB-INF/classes`` (the classpath root),
#: where such a read cannot go (measured), so it is not probed.
CLASSPATH_FILES = (("application.properties", _SPRING_PROPERTIES_MARKER),)
#: How many directories up a resource base may sit below the classpath root.
CLASSPATH_DEPTHS = (1, 2, 3, 4)


class PathTraversalClasspathResourceStrategy(ConfirmationStrategy):
    """M7 for a classpath-confined read (FR-FUZZ-630): ``../`` * depth + the file a
    Spring Boot application carries at its classpath root, confirmed when that file's
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
