"""pytest plugin: install the AU-SESS403 revision-2 prototype before any test runs
(``-p proto_plugin`` with this directory on ``PYTHONPATH``). ``REVERT=<name>`` undoes one
decision of the design (``proto.REVERTS``)."""

import proto

proto.install()
