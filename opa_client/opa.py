import os
import threading
from typing import Dict, Optional
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .base import BaseClient
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


class OpaClient(BaseClient):
	"""
	OpaClient client object to connect and manipulate OPA service.

	Parameters:
	    host (str): Host to connect to OPA service, defaults to 'localhost'.
	    port (int): Port to connect to OPA service, defaults to 8181.
	    version (str): REST API version provided by OPA, defaults to 'v1'.
	    ssl (bool): Verify SSL certificates for HTTPS requests, defaults to False.
	    cert (Optional[str]): Path to client certificate for mutual TLS authentication.
	    headers (Optional[dict]): Dictionary of headers to send, defaults to None.
	    retries (int): Number of retries for failed requests, defaults to 2.
	    timeout (float): Timeout for requests in seconds, defaults to 1.5.

	Example:
	    client = OpaClient(host='opa.example.com', ssl=True, cert='/path/to/cert.pem')
	"""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self._lock = threading.Lock()
		self._session = self._init_session()

	def _init_session(self) -> requests.Session:
		session = requests.Session()
		if self.headers:
			session.headers.update(self.headers)

		# Configure retries
		retries = Retry(
			total=self.retries,
			backoff_factor=0.3,
			status_forcelist=(500, 502, 504),
		)
		adapter = HTTPAdapter(max_retries=retries)

		session.mount("http://", adapter)
		session.mount("https://", adapter)

		if self.ssl:
			session.verify = self.cert

		return session

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, traceback):
		self.close_connection()

	def close_connection(self):
		"""Close the session and release any resources."""
		with self._lock:
			self._session.close()

	def check_connection(self) -> str:
		"""
		Checks whether the established connection is configured properly.
		If not, raises a ConnectionsError.

		Returns:
		    str: Confirmation message if the connection is successful.
		"""
		url = f"{self.root_url}/policies/"
		try:
			response = self._session.get(url, timeout=self.timeout)
			response.raise_for_status()
			return True
		except requests.exceptions.RequestException as e:
			raise ConnectionsError(
				"Service unreachable", "Check config and try again"
			) from e

	def check_health(
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
			response = self._session.get(url, timeout=self.timeout)
			return response.status_code == 200
		except requests.exceptions.RequestException:
			return False

	def get_policies_list(self) -> list:
		"""Returns all OPA policies in the service."""
		url = f"{self.root_url}/policies/"
		response = self._session.get(url, timeout=self.timeout)
		response.raise_for_status()
		policies = response.json().get("result", [])
		return [policy.get("id") for policy in policies if policy.get("id")]

	def get_policies_info(self) -> dict:
		"""
		Returns information about each policy, including
		policy path and policy rules.
		"""
		url = f"{self.root_url}/policies/"
		response = self._session.get(url, timeout=self.timeout)
		response.raise_for_status()
		policies = response.json().get("result", [])
		policies_info = {}

		for policy in policies:
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

	def update_policy_from_string(
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
		response = self._session.put(
			url,
			data=new_policy.encode("utf-8"),
			headers={"Content-Type": "text/plain"},
			timeout=self.timeout,
		)

		if response.status_code == 200:
			return True
		else:
			error = response.json()
			raise RegoParseError(error.get("code"), error.get("message"))

	def update_policy_from_file(self, filepath: str, endpoint: str) -> bool:
		"""
		Update OPA policy using a policy file.

		Parameters:
		    filepath (str): Path to the policy file.
		    endpoint (str): The policy endpoint in OPA.

		Returns:
		    bool: True if the policy was successfully updated.
		"""
		if not os.path.isfile(filepath):
			raise FileError("file_not_found",f"'{filepath}' is not a valid file")

		with open(filepath, "r", encoding="utf-8") as file:
			policy_str = file.read()

		return self.update_policy_from_string(policy_str, endpoint)

	def update_policy_from_url(self, url: str, endpoint: str) -> bool:
		"""
		Update OPA policy by fetching it from a URL.

		Parameters:
		    url (str): URL to fetch the policy from.
		    endpoint (str): The policy endpoint in OPA.

		Returns:
		    bool: True if the policy was successfully updated.
		"""
		response = requests.get(url)
		response.raise_for_status()
		policy_str = response.text
		return self.update_policy_from_string(policy_str, endpoint)

	def update_or_create_data(self, new_data: dict, endpoint: str) -> bool:
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
		response = self._session.put(
			url,
			json=new_data,
			headers={"Content-Type": "application/json"},
			timeout=self.timeout,
		)

		if response.status_code == 204:
			return True
		else:
			error = response.json()
			raise RegoParseError(error.get("code"), error.get("message"))

	def get_data(
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
		response = self._session.get(url, timeout=self.timeout)
		if response.status_code == 200 and response.json().get("result"):
			return response.json()
		else:
			error = response.json()
			raise PolicyNotFoundError(
				"PolicyNotFoundError",
				error.get("message", "requested data not found"),
			)

	def policy_to_file(
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
		policy = self.get_policy(policy_name)
		policy_raw = policy.get("result", {}).get("raw", "")

		if not policy_raw:
			raise PolicyNotFoundError("resource_not_found", "Policy content is empty")

		full_path = os.path.join(path or "", filename)

		try:
			with open(full_path, "w", encoding="utf-8") as file:
				file.write(policy_raw)
			return True
		except OSError as e:
			raise PathNotFoundError("path_not_found", f"Failed to write to '{full_path}'") from e

	def get_policy(self, policy_name: str) -> dict:
		"""
		Get a specific OPA policy.

		Parameters:
		    policy_name (str): The name of the policy.

		Returns:
		    dict: The policy data.
		"""
		url = f"{self.root_url}/policies/{policy_name}"
		response = self._session.get(url, timeout=self.timeout)
		if response.status_code == 200:
			return response.json()
		else:
			error = response.json()
			raise PolicyNotFoundError(error.get("code"), error.get("message"))

	def delete_policy(self, policy_name: str) -> bool:
		"""
		Delete an OPA policy.

		Parameters:
		    policy_name (str): The name of the policy.

		Returns:
		    bool: True if the policy was successfully deleted.
		"""
		url = f"{self.root_url}/policies/{policy_name}"
		response = self._session.delete(url, timeout=self.timeout)
		if response.status_code == 200:
			return True
		else:
			error = response.json()
			raise DeletePolicyError(error.get("code"), error.get("message"))

	def delete_data(self, data_name: str) -> bool:
		"""
		Delete OPA data.

		Parameters:
		    data_name (str): The name of the data.

		Returns:
		    bool: True if the data was successfully deleted.
		"""
		url = f"{self.root_url}/data/{data_name}"
		response = self._session.delete(url, timeout=self.timeout)
		if response.status_code == 204:
			return True
		else:
			error = response.json()
			raise DeleteDataError(error.get("code"), error.get("message"))

	def check_permission(
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
		policy = self.get_policy(policy_name)
		ast = policy.get("result", {}).get("ast", {})
		package_path = "/".join(
			[p.get("value") for p in ast.get("package", {}).get("path", [])]
		)
		rules = [
			rule.get("head", {}).get("name") for rule in ast.get("rules", [])
		]

		if rule_name not in rules:
			raise CheckPermissionError(
				"resource_not_found", f"Rule '{rule_name}' not found in policy '{policy_name}'"
			)

		url = f"{self.root_url}/{package_path}/{rule_name}"
		if query_params:
			url = f"{url}?{urlencode(query_params)}"
		response = self._session.post(
			url, json={"input": input_data}, timeout=self.timeout
		)
		response.raise_for_status()
		return response.json()

	def query_rule(
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

		response = self._session.post(
			url, json={"input": input_data}, timeout=self.timeout
		)
		response.raise_for_status()
		return response.json()

	def ad_hoc_query(self, query: str, input_data: dict = None) -> dict:
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

		response = self._session.get(
			url, params=params, json=payload, timeout=self.timeout
		)
		response.raise_for_status()
		return response.json()


# Example usage:
if __name__ == "__main__":
	client = OpaClient()
	try:
		print(client.check_connection())
	finally:
		client.close_connection()
