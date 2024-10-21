import os
from typing import Dict, Optional, Union
from urllib.parse import urlencode

from .errors import (
	FileError,
	PathNotFoundError,
)


class BaseClient:
	"""
	Base class for OpaClient implementations.

	This class contains common logic shared between synchronous and asynchronous clients.
	"""

	def __init__(
		self,
		host: str = "localhost",
		port: int = 8181,
		version: str = "v1",
		ssl: bool = False,
		cert: Optional[Union[str, tuple]] = None,
		headers: Optional[dict] = None,
		timeout: float = 1.5,
	):
		if not isinstance(port, int):
			raise TypeError("The port must be an integer")

		self.host = host.strip()
		self.port = port
		self.version = version
		self.ssl = ssl
		self.cert = cert
		self.timeout = timeout

		self.schema = "https://" if ssl else "http://"
		self.root_url = f"{self.schema}{self.host}:{self.port}/{self.version}"

		self.headers = headers

		self._session = None  # Will be initialized in the subclass
		self.retries = 2
		self.timeout = 1.5

	def _build_url(
		self, path: str, query_params: Dict[str, str] = None
	) -> str:
		url = f"{self.root_url}/{path.lstrip('/')}"
		if query_params:
			url = f"{url}?{urlencode(query_params)}"
		return url

	def _load_policy_from_file(self, filepath: str) -> str:
		if not os.path.isfile(filepath):
			raise FileError(f"'{filepath}' is not a valid file")
		with open(filepath, "r", encoding="utf-8") as file:
			return file.read()

	def _save_policy_to_file(
		self, policy_raw: str, path: Optional[str], filename: str
	) -> bool:
		full_path = os.path.join(path or "", filename)
		try:
			with open(full_path, "w", encoding="utf-8") as file:
				file.write(policy_raw)
			return True
		except OSError as e:
			raise PathNotFoundError(f"Failed to write to '{full_path}'") from e

	# Abstract methods to be implemented in subclasses
	def close_connection(self):
		raise NotImplementedError

	def check_connection(self) -> str:
		raise NotImplementedError

	def _init_session(self):
		raise NotImplementedError

	def check_health(
		self, query: Dict[str, bool] = None, diagnostic_url: str = None
	) -> bool:
		raise NotImplementedError

	def get_policies_list(self) -> list:
		raise NotImplementedError

	def get_policies_info(self) -> dict:
		raise NotImplementedError

	def update_policy_from_string(
		self, new_policy: str, endpoint: str
	) -> bool:
		raise NotImplementedError

	def update_policy_from_file(self, filepath: str, endpoint: str) -> bool:
		raise NotImplementedError

	def update_policy_from_url(self, url: str, endpoint: str) -> bool:
		raise NotImplementedError

	def update_or_create_data(self, new_data: dict, endpoint: str) -> bool:
		raise NotImplementedError

	def get_data(
		self, data_name: str = "", query_params: Dict[str, bool] = None
	) -> dict:
		raise NotImplementedError

	def policy_to_file(
		self,
		policy_name: str,
		path: Optional[str] = None,
		filename: str = "opa_policy.rego",
	) -> bool:
		raise NotImplementedError

	def get_policy(self, policy_name: str) -> dict:
		raise NotImplementedError

	def delete_policy(self, policy_name: str) -> bool:
		raise NotImplementedError

	def delete_data(self, data_name: str) -> bool:
		raise NotImplementedError

	def check_permission(
		self,
		input_data: dict,
		policy_name: str,
		rule_name: str,
		query_params: Dict[str, bool] = None,
	) -> dict:
		raise NotImplementedError

	def query_rule(
		self,
		input_data: dict,
		package_path: str,
		rule_name: Optional[str] = None,
	) -> dict:
		raise NotImplementedError

	def ad_hoc_query(self, query: str, input_data: dict = None) -> dict:
		raise NotImplementedError
