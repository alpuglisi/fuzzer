"""Session manager (component #3): detection-only auth, per-host credentials.

Detects each host's login/session mechanism dynamically (D13) and keeps every
tool authenticated, drawing credentials saved per host (D12). No hand-written
per-host profiles; logins detection can't parse fail loudly.
"""

from fuzzlab.session.state import SessionState
from fuzzlab.session.manager import SessionManager, SessionAuthError

__all__ = ["SessionState", "SessionManager", "SessionAuthError"]
