import asyncio
import json
import os
import ssl
from typing import Dict, Optional, Union
from urllib.parse import urlencode

import aiofiles
import aiohttp
from aiohttp import ClientSession, TCPConnector

from .errors import (
	CheckPermissionError,
	ConnectionsError,
	DeleteDataError,
	DeletePolicyError,
	FileError,
	PathNotFoundError,
	PolicyNotFoundError,
	RegoParseError,
	TypeException,
)


class AsyncOpaClient:
	"""
	AsyncOpaClient client object to connect and manipulate OPA service asynchronously.

	Parameters:
	    host (str): Host to connect to OPA service, defaults to 'localhost'.
	    port (int): Port to connect to OPA service, defaults to 8181.
	    version (str): REST API version provided by OPA, defaults to 'v1'.
	    ssl (bool): Verify SSL certificates for HTTPS requests, defaults to False.
	    cert (Optional[str] or Tuple[str, str]): Path to client certificate or a tuple of (cert_file, key_file).
	    headers (Optional[dict]): Dictionary of headers to send, defaults to None.
	    timeout (float): Timeout for requests in seconds, defaults to 1.5.

	Example:
	    async with AsyncOpaClient(host='opa.example.com', ssl=True, cert='/path/to/cert.pem') as client:
	        await client.check_connection()
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
			async with self._session.get(url) as response:
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
			async with self._session.get(url) as response:
				return response.status == 200
		except Exception:
			return False

	async def get_policies_list(self) -> list:
		"""Returns all OPA policies in the service."""
		url = f"{self.root_url}/policies/"
		async with self._session.get(url) as response:
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
		async with self._session.get(url) as response:
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
		self, new_policy: str, endpoint: str
	) -> bool:
		"""
		Update OPA policy using a policy string.

		Parameters:
		    new_policy (str): The new policy in Rego language.
		    endpoint (str): The policy endpoint in OPA.

		Returns:
		    bool: True if the policy was successfully updated.
		"""
		if not new_policy or not isinstance(new_policy, str):
			raise TypeException("new_policy must be a non-empty string")

		url = f"{self.root_url}/policies/{endpoint}"
		headers = self.headers.copy() if self.headers else {}
		headers["Content-Type"] = "text/plain"
		async with self._session.put(
			url, data=new_policy.encode("utf-8"), headers=self.headers
		) as response:
			if response.status == 200:
				return True
			else:
				error = await response.json()
				raise RegoParseError(error.get("code"), error.get("message"))

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
			raise FileError(f"'{filepath}' is not a valid file")

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
		async with self._session.put(
			url, json=new_data, headers=headers
		) as response:
			if response.status == 204:
				return True
			else:
				error = await response.json()
				raise RegoParseError(error.get("code"), error.get("message"))

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
		async with self._session.get(url) as response:
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
			raise PolicyNotFoundError("Policy content is empty")

		full_path = os.path.join(path or "", filename)

		try:
			async with aiofiles.open(full_path, "w", encoding="utf-8") as file:
				await file.write(policy_raw)
			return True
		except OSError as e:
			raise PathNotFoundError(f"Failed to write to '{full_path}'") from e

	async def get_policy(self, policy_name: str) -> dict:
		"""
		Get a specific OPA policy.

		Parameters:
		    policy_name (str): The name of the policy.

		Returns:
		    dict: The policy data.
		"""
		url = f"{self.root_url}/policies/{policy_name}"
		async with self._session.get(url) as response:
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
		async with self._session.delete(url) as response:
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
		async with self._session.delete(url) as response:
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
				f"Rule '{rule_name}' not found in policy '{policy_name}'"
			)

		url = f"{self.root_url}/data/{package_path}/{rule_name}"
		if query_params:
			url = f"{url}?{urlencode(query_params)}"

		async with self._session.post(
			url, json={"input": input_data}
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

		async with self._session.post(
			url, json={"input": input_data}
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
		params = {"q": query}
		payload = {"input": input_data} if input_data else None

		async with self._session.post(
			url, params=params, json=payload
		) as response:
			response.raise_for_status()
			return await response.json()

	# Property methods for read-only access to certain attributes
	@property
	def host(self) -> str:
		return self._host

	@host.setter
	def host(self, value: str):
		self._host = value

	@property
	def port(self) -> int:
		return self._port

	@port.setter
	def port(self, value: int):
		if not isinstance(value, int):
			raise TypeError("Port must be an integer")
		self._port = value

	@property
	def version(self) -> str:
		return self._version

	@version.setter
	def version(self, value: str):
		self._version = value

	@property
	def schema(self) -> str:
		return self._schema

	@schema.setter
	def schema(self, value: str):
		self._schema = value

	@property
	def root_url(self) -> str:
		return self._root_url

	@root_url.setter
	def root_url(self, value: str):
		self._root_url = value

	@property
	def ssl(self) -> bool:
		return self._ssl

	@ssl.setter
	def ssl(self, value: bool):
		self._ssl = value

	@property
	def cert(self) -> Optional[str]:
		return self._cert

	@cert.setter
	def cert(self, value: Optional[str]):
		self._cert = value

	@property
	def headers(self) -> dict:
		return self._headers

	@headers.setter
	def headers(self, value: dict):
		self._headers = value

	@property
	def timeout(self) -> float:
		return self._timeout

	@timeout.setter
	def timeout(self, value: float):
		self._timeout = value


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
