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


# class OpaClient(BaseOpaClient):
#     """
#     Synchronous OpaClient implementation using requests.
#     """

#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)

#         self._init_session()

#     def _init_session(self):
#         self._session = requests.Session()
#         self._session.headers.update(self.headers)

#         if self.ssl:
#             self._session.verify = self.cert if self.cert else True

#         # Optionally, configure retries and other session parameters

#     def close_connection(self):
#         if self._session:
#             self._session.close()
#             self._session = None

#     def check_connection(self) -> str:
#         url = self._build_url('policies/')
#         try:
#             response = self._session.get(url, timeout=self.timeout)
#             response.raise_for_status()
#             return "Yes, I'm here :)"
#         except requests.exceptions.RequestException as e:
#             raise ConnectionsError('Service unreachable', 'Check config and try again') from e

#     # Implement other synchronous methods similarly
#     # For example:
#     def get_policies_list(self) -> list:
#         url = self._build_url('policies/')
#         response = self._session.get(url, timeout=self.timeout)
#         response.raise_for_status()
#         policies = response.json().get('result', [])
#         return [policy.get('id') for policy in policies if policy.get('id')]

#     # ... Rest of synchronous methods ...


# class AsyncOpaClient(BaseOpaClient):
#     """
#     Asynchronous OpaClient implementation using aiohttp.
#     """

#     async def __aenter__(self):
#         await self._init_session()
#         return self

#     async def __aexit__(self, exc_type, exc_value, traceback):
#         await self.close_connection()

#     async def _init_session(self):
#         ssl_context = None

#         if self.ssl:
#             ssl_context = ssl.create_default_context()
#             if self.cert:
#                 if isinstance(self.cert, tuple):
#                     ssl_context.load_cert_chain(*self.cert)
#                 else:
#                     ssl_context.load_cert_chain(self.cert)
#             else:
#                 ssl_context.load_default_certs()

#         connector = aiohttp.TCPConnector(ssl=ssl_context)

#         self._session = aiohttp.ClientSession(
#             headers=self.headers,
#             connector=connector,
#             timeout=aiohttp.ClientTimeout(total=self.timeout),
#         )

#     async def close_connection(self):
#         if self._session and not self._session.closed:
#             await self._session.close()
#             self._session = None

#     async def check_connection(self) -> str:
#         url = self._build_url('policies/')
#         try:
#             async with self._session.get(url) as response:
#                 if response.status == 200:
#                     return "Yes, I'm here :)"
#                 else:
#                     raise ConnectionsError('Service unreachable', 'Check config and try again')
#         except Exception as e:
#             raise ConnectionsError('Service unreachable', 'Check config and try again') from e

#     # Implement other asynchronous methods similarly
#     # For example:
#     async def get_policies_list(self) -> list:
#         url = self._build_url('policies/')
#         async with self._session.get(url) as response:
#             response.raise_for_status()
#             policies = await response.json()
#             result = policies.get('result', [])
#             return [policy.get('id') for policy in result if policy.get('id')]

#     # ... Rest of asynchronous methods ...


# # Example usage:

# # Synchronous client
# def sync_example():
#     client = OpaClient(host='localhost', port=8181)
#     try:
#         result = client.check_connection()
#         print(result)
#         policies = client.get_policies_list()
#         print("Policies:", policies)
#     finally:
#         client.close_connection()


# # Asynchronous client
# async def async_example():
#     async with AsyncOpaClient(host='localhost', port=8181) as client:
#         result = await client.check_connection()
#         print(result)
#         policies = await client.get_policies_list()
#         print("Policies:", policies)


# if __name__ == '__main__':
#     # Run synchronous example
#     sync_example()

#     # Run asynchronous example
#     import asyncio
#     asyncio.run(async_example())
