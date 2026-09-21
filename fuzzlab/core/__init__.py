"""Shared library imported by every tool and component (decision D6).

Provides the project store and migrations, layered config, structured logging,
the request budget + per-host timing mutex, a session-aware HTTP seam, and the
versioned feature extractor. Nothing in ``core`` sends traffic to a target on
import; the tools do that, and only when explicitly run.
"""

from fuzzlab.core.config import Config, load_config
from fuzzlab.core.store import Store, connect
from fuzzlab.core import migrations
from fuzzlab.core.obs import get_logger
from fuzzlab.core.budget import RequestBudget, BudgetExceeded

__all__ = [
    "Config",
    "load_config",
    "Store",
    "connect",
    "migrations",
    "get_logger",
    "RequestBudget",
    "BudgetExceeded",
]
