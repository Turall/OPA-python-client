import asyncio
import os
import ssl
import warnings
from contextlib import asynccontextmanager
from typing import Dict, Optional
from urllib.parse import urlencode

import aiofiles
import aiohttp
from aiohttp import ClientSession, TCPConnector

from .base import BaseClient
from .errors import (
	CheckPermissionError,
	ConnectionsError,
	DeleteDataError,
	DeletePolicyError,
	FileError,
	PatchDataError,
	PathNotFoundError,
	PolicyNotFoundError,
	TypeException,
)
from .rego_compat import is_v0_rego_syntax_error

_RETRYABLE_STATUS_CODES = frozenset({500, 502, 504})
_BACKOFF_FACTOR = 0.3


class AsyncOpaClient(BaseClient):
	"""
	AsyncOpaClient client object to connect and manipulate OPA service asynchronously.

	Parameters:
	    host (str): Host to connect to OPA service, defaults to 'localhost'.
	    port (int): Port to connect to OPA service, defaults to 8181.
	    version (str): REST API version provided by OPA, defaults to 'v1'.
	    ssl (bool): Verify SSL certificates for HTTPS requests, defaults to False.
	    cert (Optional[str] or Tuple[str, str]): Path to client certificate or a tuple of (cert_file, key_file).
	    headers (Optional[dict]): Dictionary of headers to send, defaults to None.
	    retries (int): Number of retries for failed requests, defaults to 2.
	    timeout (float): Timeout for requests in seconds, defaults to 1.5.

	Example:
	    async with AsyncOpaClient(host='opa.example.com', ssl=True, cert='/path/to/cert.pem') as client:
	        await client.check_connection()
	"""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		# Initialize the session attributes
		self._session: Optional[ClientSession] = None
		self._connector = None  # Will be initialized in _init_session

	async def __aenter__(self):
		await self._init_session()
		return self

	async def __aexit__(self, exc_type, exc_value, traceback):
		await self.close_connection()

	async def _init_session(self):
		ssl_context = None

		if self.ssl:
			ssl_context = ssl.create_default_context()

			# If cert is provided, load the client certificate
			if self.cert:
				if isinstance(self.cert, tuple):
					# Tuple of (cert_file, key_file)
					ssl_context.load_cert_chain(*self.cert)
				else:
					# Single cert file (might contain both cert and key)
					ssl_context.load_cert_chain(self.cert)
			else:
				# Verify default CA certificates
				ssl_context.load_default_certs()

		self._connector = TCPConnector(ssl=ssl_context)

		self._session = aiohttp.ClientSession(
			headers=self.headers,
			connector=self._connector,
			timeout=aiohttp.ClientTimeout(total=self.timeout),
		)

	@asynccontextmanager
	async def _request(self, method: str, url: str, **kwargs):
		"""
		Perform an HTTP request, retrying on connection errors and on
		503/502/504 responses, matching the sync client's retry behavior.
		"""
		attempt = 0
		while True:
			try:
				response = await self._session.request(
					method, url, **kwargs
				)
			except aiohttp.ClientConnectionError:
				if attempt >= self.retries:
					raise
			else:
				if (
					response.status not in _RETRYABLE_STATUS_CODES
					or attempt >= self.retries
				):
					try:
						yield response
					finally:
						await response.release()
					return
				await response.release()

			attempt += 1
			await asyncio.sleep(_BACKOFF_FACTOR * (2 ** (attempt - 1)))

	async def close_connection(self):
		"""Close the session and release any resources."""
		if self._session and not self._session.closed:
			await self._session.close()
			self._session = None

	async def check_connection(self) -> str:
		"""
		Checks whether the established connection is configured properly.
		If not, raises a ConnectionsError.

		Returns:
		    str: Confirmation message if the connection is successful.
		"""
		url = f"{self.root_url}/policies/"
		try:
			async with self._request("GET", url) as response:
				if response.status == 200:
					return True
				else:
					raise ConnectionsError(
						"Service unreachable", "Check config and try again"
					)
		except Exception as e:
			raise ConnectionsError(
				"Service unreachable", "Check config and try again"
			) from e

	async def check_health(
		self, query: Dict[str, bool] = None, diagnostic_url: str = None
	) -> bool:
		"""
		Check if OPA is healthy.

		Parameters:
		    query (Dict[str, bool], optional): Query parameters for health check.
		    diagnostic_url (str, optional): Custom diagnostic URL.

		Returns:
		    bool: True if OPA is healthy, False otherwise.
		"""
		url = diagnostic_url or f"{self.schema}{self.host}:{self.port}/health"
		if query:
			url = f"{url}?{urlencode(query)}"
		try:
			async with self._request("GET", url) as response:
				return response.status == 200
		except Exception:
			return False

	async def get_config(self) -> dict:
		"""
		Returns the OPA server's active configuration.

		Returns:
		    dict: The OPA configuration document.
		"""
		url = f"{self.root_url}/config"
		async with self._request("GET", url) as response:
			response.raise_for_status()
			return await response.json()

	async def get_metrics(self) -> str:
		"""
		Returns Prometheus-formatted performance metrics for the OPA server.

		Returns:
		    str: The raw Prometheus metrics text.
		"""
		url = f"{self.schema}{self.host}:{self.port}/metrics"
		async with self._request("GET", url) as response:
			response.raise_for_status()
			return await response.text()

	async def get_policies_list(self) -> list:
		"""Returns all OPA policies in the service."""
		url = f"{self.root_url}/policies/"
		async with self._request("GET", url) as response:
			response.raise_for_status()
			policies = await response.json()
			result = policies.get("result", [])
			return [policy.get("id") for policy in result if policy.get("id")]

	async def get_policies_info(self) -> dict:
		"""
		Returns information about each policy, including
		policy path and policy rules.
		"""
		url = f"{self.root_url}/policies/"
		async with self._request("GET", url) as response:
			response.raise_for_status()
			policies = await response.json()
			result = policies.get("result", [])
			policies_info = {}

			for policy in result:
				policy_id = policy.get("id")
				ast = policy.get("ast", {})
				package_path = "/".join(
					[
						p.get("value")
						for p in ast.get("package", {}).get("path", [])
					]
				)
				rules = list(
					set(
						rule.get("head", {}).get("name")
						for rule in ast.get("rules", [])
					)
				)
				policy_url = f"{self.root_url}/{package_path}"
				rules_urls = [f"{policy_url}/{rule}" for rule in rules if rule]
				policies_info[policy_id] = {
					"path": policy_url,
					"rules": rules_urls,
				}

			return policies_info

	async def update_policy_from_string(
		self, new_policy: str, endpoint: str, rego_compat: bool = True
	) -> bool:
		"""
		Update OPA policy using a policy string.

		Parameters:
		    new_policy (str): The new policy in Rego language.
		    endpoint (str): The policy endpoint in OPA.
		    rego_compat (bool): When True, automatically upgrade common v0 Rego
		        syntax for OPA 1.0+ if the initial upload is rejected.

		Returns:
		    bool: True if the policy was successfully updated.
		"""
		if not new_policy or not isinstance(new_policy, str):
			raise TypeException("new_policy must be a non-empty string")

		url = f"{self.root_url}/policies/{endpoint}"
		headers = self.headers.copy() if self.headers else {}
		headers["Content-Type"] = "text/plain"
		async with self._request(
			"PUT", url, data=new_policy.encode("utf-8"), headers=headers
		) as response:
			if response.status == 200:
				return True

			error = await response.json()
			for upgraded in self._prepare_policy_for_upload(
				new_policy, error, rego_compat
			):
				async with self._request(
					"PUT",
					url,
					data=upgraded.encode("utf-8"),
					headers=headers,
				) as retry_response:
					if retry_response.status == 200:
						return True
					error = await retry_response.json()
					if not is_v0_rego_syntax_error(error):
						break

			self._raise_rego_parse_error(error)

	async def update_policy_from_file(
		self, filepath: str, endpoint: str
	) -> bool:
		"""
		Update OPA policy using a policy file.

		Parameters:
		    filepath (str): Path to the policy file.
		    endpoint (str): The policy endpoint in OPA.

		Returns:
		    bool: True if the policy was successfully updated.
		"""
		if not os.path.isfile(filepath):
			raise FileError(
				"file_not_found", f"'{filepath}' is not a valid file"
			)

		async with aiofiles.open(filepath, "r", encoding="utf-8") as file:
			policy_str = await file.read()

		return await self.update_policy_from_string(policy_str, endpoint)

	async def update_policy_from_url(self, url: str, endpoint: str) -> bool:
		"""
		Update OPA policy by fetching it from a URL.

		Parameters:
		    url (str): URL to fetch the policy from.
		    endpoint (str): The policy endpoint in OPA.

		Returns:
		    bool: True if the policy was successfully updated.
		"""
		async with aiohttp.ClientSession() as session:
			async with session.get(url) as response:
				response.raise_for_status()
				policy_str = await response.text()

		return await self.update_policy_from_string(policy_str, endpoint)

	async def update_or_create_data(
		self, new_data: dict, endpoint: str
	) -> bool:
		"""
		Update or create OPA data.

		Parameters:
		    new_data (dict): The data to be updated or created.
		    endpoint (str): The data endpoint in OPA.

		Returns:
		    bool: True if the data was successfully updated or created.
		"""
		if not isinstance(new_data, dict):
			raise TypeException("new_data must be a dictionary")

		url = f"{self.root_url}/data/{endpoint}"
		headers = self.headers.copy() if self.headers else {}
		headers["Content-Type"] = "application/json"
		async with self._request(
			"PUT", url, json=new_data, headers=headers
		) as response:
			if response.status == 204:
				return True
			else:
				self._raise_rego_parse_error(await response.json())

	async def patch_data(self, endpoint: str, patches: list) -> bool:
		"""
		Partially update OPA data using a JSON Patch (RFC 6902) document.

		Parameters:
		    endpoint (str): The data endpoint in OPA.
		    patches (list): A list of JSON Patch operations, e.g.
		        [{"op": "add", "path": "/a/b", "value": 1}].

		Returns:
		    bool: True if the data was successfully patched.
		"""
		if not isinstance(patches, list):
			raise TypeException("patches must be a list")

		url = f"{self.root_url}/data/{endpoint}"
		headers = self.headers.copy() if self.headers else {}
		headers["Content-Type"] = "application/json-patch+json"
		async with self._request(
			"PATCH", url, json=patches, headers=headers
		) as response:
			if response.status == 204:
				return True

			error = await response.json()
			raise PatchDataError(error.get("code"), error.get("message"))

	async def get_data(
		self, data_name: str = "", query_params: Dict[str, bool] = None
	) -> dict:
		"""
		Get OPA data.

		Parameters:
		    data_name (str, optional): The name of the data to retrieve.
		    query_params (Dict[str, bool], optional): Query parameters.

		Returns:
		    dict: The retrieved data.
		"""
		url = f"{self.root_url}/data/{data_name}"
		if query_params:
			url = f"{url}?{urlencode(query_params)}"
		async with self._request("GET", url) as response:
			if response.status == 200:
				return await response.json()
			else:
				error = await response.json()
				raise PolicyNotFoundError(
					error.get("code"), error.get("message")
				)

	async def policy_to_file(
		self,
		policy_name: str,
		path: Optional[str] = None,
		filename: str = "opa_policy.rego",
	) -> bool:
		"""
		Save an OPA policy to a file.

		Parameters:
		    policy_name (str): The name of the policy.
		    path (Optional[str]): The directory path to save the file.
		    filename (str): The name of the file.

		Returns:
		    bool: True if the policy was successfully saved.
		"""
		policy = await self.get_policy(policy_name)
		policy_raw = policy.get("result", {}).get("raw", "")

		if not policy_raw:
			raise PolicyNotFoundError(
				"resource_not_found", "Policy content is empty"
			)

		full_path = os.path.join(path or "", filename)

		try:
			async with aiofiles.open(full_path, "w", encoding="utf-8") as file:
				await file.write(policy_raw)
			return True
		except OSError as e:
			raise PathNotFoundError(
				"path_not_found", f"Failed to write to '{full_path}'"
			) from e

	async def get_policy(self, policy_name: str) -> dict:
		"""
		Get a specific OPA policy.

		Parameters:
		    policy_name (str): The name of the policy.

		Returns:
		    dict: The policy data.
		"""
		url = f"{self.root_url}/policies/{policy_name}"
		async with self._request("GET", url) as response:
			if response.status == 200:
				return await response.json()
			else:
				error = await response.json()
				raise PolicyNotFoundError(
					error.get("code"), error.get("message")
				)

	async def delete_policy(self, policy_name: str) -> bool:
		"""
		Delete an OPA policy.

		Parameters:
		    policy_name (str): The name of the policy.

		Returns:
		    bool: True if the policy was successfully deleted.
		"""
		url = f"{self.root_url}/policies/{policy_name}"
		async with self._request("DELETE", url) as response:
			if response.status == 200:
				return True
			else:
				error = await response.json()
				raise DeletePolicyError(
					error.get("code"), error.get("message")
				)

	async def delete_data(self, data_name: str) -> bool:
		"""
		Delete OPA data.

		Parameters:
		    data_name (str): The name of the data.

		Returns:
		    bool: True if the data was successfully deleted.
		"""
		url = f"{self.root_url}/data/{data_name}"
		async with self._request("DELETE", url) as response:
			if response.status == 204:
				return True
			else:
				error = await response.json()
				raise DeleteDataError(error.get("code"), error.get("message"))

	async def check_permission(
		self,
		input_data: dict,
		policy_name: str,
		rule_name: str,
		query_params: Dict[str, bool] = None,
	) -> dict:
		"""
		Check permissions based on input data, policy name, and rule name.

		Parameters:
		    input_data (dict): The input data to check against the policy.
		    policy_name (str): The name of the policy.
		    rule_name (str): The name of the rule in the policy.
		    query_params (Dict[str, bool], optional): Query parameters.

		Returns:
		    dict: The result of the permission check.
		"""
		warnings.warn(
			"check_permission is deprecated and will be removed in a future release. Use `query_rule` instead.",
			DeprecationWarning,
			stacklevel=2,
		)
		policy = await self.get_policy(policy_name)
		ast = policy.get("result", {}).get("ast", {})
		package_path = "/".join(
			[p.get("value") for p in ast.get("package", {}).get("path", [])]
		)
		rules = [
			rule.get("head", {}).get("name") for rule in ast.get("rules", [])
		]

		if rule_name not in rules:
			raise CheckPermissionError(
				"resource_not_found",
				f"Rule '{rule_name}' not found in policy '{policy_name}'",
			)

		url = f"{self.root_url}/{package_path}/{rule_name}"
		if query_params:
			url = f"{url}?{urlencode(query_params)}"

		async with self._request(
			"POST", url, json={"input": input_data}
		) as response:
			response.raise_for_status()
			return await response.json()

	async def query_rule(
		self,
		input_data: dict,
		package_path: str,
		rule_name: Optional[str] = None,
	) -> dict:
		"""
		Query a specific rule in a package.

		Parameters:
		    input_data (dict): The input data for the query.
		    package_path (str): The package path.
		    rule_name (Optional[str]): The rule name.

		Returns:
		    dict: The result of the query.
		"""
		path = package_path.replace(".", "/")
		if rule_name:
			path = f"{path}/{rule_name}"
		url = f"{self.root_url}/data/{path}"

		async with self._request(
			"POST", url, json={"input": input_data}
		) as response:
			response.raise_for_status()
			return await response.json()

	async def ad_hoc_query(self, query: str, input_data: dict = None) -> dict:
		"""
		Execute an ad-hoc query.

		Parameters:
		    query (str): The query string.
		    input_data (dict, optional): The input data for the query.

		Returns:
		    dict: The result of the query.
		"""
		url = f"{self.schema}{self.host}:{self.port}/v1/query"
		payload = {"query": query}
		if input_data:
			payload["input"] = input_data

		async with self._request("POST", url, json=payload) as response:
			response.raise_for_status()
			return await response.json()

	async def compile_query(
		self,
		query: str,
		input_data: dict = None,
		unknowns: Optional[list] = None,
		options: Optional[dict] = None,
	) -> dict:
		"""
		Partially evaluate and compile a query using the Compile API.

		Parameters:
		    query (str): The query to partially evaluate and compile.
		    input_data (dict, optional): The input document to use during
		        partial evaluation.
		    unknowns (list, optional): The terms to treat as unknown during
		        partial evaluation. Defaults to OPA's default of ["input"].
		    options (dict, optional): Compile options, e.g.
		        {"disableInlining": [...]}.

		Returns:
		    dict: The compile result, containing a "result" key with the
		        partially evaluated queries (or an empty dict if the query
		        is unconditionally false).
		"""
		url = f"{self.root_url}/compile"
		payload = {"query": query}
		if input_data:
			payload["input"] = input_data
		if unknowns is not None:
			payload["unknowns"] = unknowns
		if options:
			payload["options"] = options

		async with self._request("POST", url, json=payload) as response:
			response.raise_for_status()
			return await response.json()


# Example usage:
async def main():
	async with AsyncOpaClient() as client:
		try:
			result = await client.check_connection()
			print(result)
		finally:
			await client.close_connection()


# Run the example
if __name__ == "__main__":
	asyncio.run(main())

	# Example usage:
	async def main():
		async with AsyncOpaClient(
			host="localhost",
			port=8181,
			ssl=True,
			cert=("/path/to/cert.pem", "/path/to/key.pem"),
		) as client:
			try:
				result = await client.check_connection()
				print(result)
			finally:
				await client.close_connection()
