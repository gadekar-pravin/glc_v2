"""Short-lived credential package.

Only the dependency-light client is exported here because this package is
copied into adapter images. Gateway-only issuer/verifier code is imported
from its concrete modules and never becomes an adapter dependency.
"""

from glc.creds.client import Token, get_token

__all__ = ["Token", "get_token"]
