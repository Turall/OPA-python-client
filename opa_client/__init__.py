"""Initialize the OpaClient package."""

from .opa import OpaClient
from .opa_async import AsyncOpaClient


def create_opa_client(async_mode=False, *args, **kwargs):
	if async_mode:
		return AsyncOpaClient(*args, **kwargs)
	else:
		return OpaClient(*args, **kwargs)


__version__ = "2.0.2"
__author__ = "Tural Muradov"
__license__ = "MIT"

__all__ = ["OpaClient", "create_opa_client", "AsyncOpaClient"]
