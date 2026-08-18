from typing import Dict, Optional, Union

from .rego_compat import prepare_policy_for_upload, raise_rego_parse_error


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
		retries: int = 2,
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
		self.retries = retries

		self.schema = "https://" if ssl else "http://"
		self.root_url = f"{self.schema}{self.host}:{self.port}/{self.version}"

		self.headers = headers

		self._session = None  # Will be initialized in the subclass

	def _raise_rego_parse_error(self, error: dict) -> None:
		raise_rego_parse_error(error)

	def _prepare_policy_for_upload(
		self, policy: str, error: dict, rego_compat: bool
	) -> list[str]:
		return prepare_policy_for_upload(policy, error, rego_compat)

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
		self, new_policy: str, endpoint: str, rego_compat: bool = True
	) -> bool:
		raise NotImplementedError

	def update_policy_from_file(self, filepath: str, endpoint: str) -> bool:
		raise NotImplementedError

	def update_policy_from_url(self, url: str, endpoint: str) -> bool:
		raise NotImplementedError

	def update_or_create_data(self, new_data: dict, endpoint: str) -> bool:
		raise NotImplementedError

	def patch_data(self, endpoint: str, patches: list) -> bool:
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

	def compile_query(
		self,
		query: str,
		input_data: dict = None,
		unknowns: Optional[list] = None,
		options: Optional[dict] = None,
	) -> dict:
		raise NotImplementedError

	def get_config(self) -> dict:
		raise NotImplementedError

	def get_metrics(self) -> str:
		raise NotImplementedError
