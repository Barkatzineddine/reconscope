"""Protocol-specific probes.

Each module exposes a small async ``probe`` coroutine that is handed an open, authorized
``host:port`` and returns a :class:`~reconscope.models.ServiceInfo` plus any
:class:`~reconscope.models.Finding` objects. Probes are read-only: they identify the service
and report hygiene issues (deprecated protocol versions, weak algorithms, missing security
headers), they never authenticate, change state or transfer files.
"""

from __future__ import annotations

__all__ = ["dns", "http", "smb", "ssh", "tls"]
