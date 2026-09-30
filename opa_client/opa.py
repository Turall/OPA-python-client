import json
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .base import BaseClient
from .rego_compat import is_v0_rego_syntax_error
from .errors import (
	ConnectionsError,
	DeleteDataError,
	DeletePolicyError,
	FileError,
	PatchDataError,
	PathNotFoundError,
	PolicyNotFoundError,
	QueryExecuteError,
	TypeException,
)

_REGO_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


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
	    token (Optional[str]): Bearer token added as an Authorization header.
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
			# Return the final response instead of raising a generic,
			# body-less RetryError once retries are exhausted, so callers'
			# raise_for_status() can surface OPA's actual error message.
			raise_on_status=False,
		)
		adapter = HTTPAdapter(max_retries=retries)

		session.mount("http://", adapter)
		session.mount("https://", adapter)

		if self.ssl:
			session.verify = self.ssl
		if self.cert:
			session.cert = self.cert

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

	def get_config(self) -> dict:
		"""
		Returns the OPA server's active configuration.

		Returns:
		    dict: The OPA configuration document.
		"""
		url = f"{self.root_url}/config"
		response = self._session.get(url, timeout=self.timeout)
		response.raise_for_status()
		return response.json()

	def get_metrics(self) -> str:
		"""
		Returns Prometheus-formatted performance metrics for the OPA server.

		Returns:
		    str: The raw Prometheus metrics text.
		"""
		url = f"{self.schema}{self.host}:{self.port}/metrics"
		response = self._session.get(url, timeout=self.timeout)
		response.raise_for_status()
		return response.text

	def get_status(self) -> dict:
		"""
		Returns the OPA server's status, including bundle activation,
		discovery, and plugin status (requires the status plugin to be
		enabled on the server; otherwise OPA itself returns a 500 with
		a "status plugin not enabled" message).

		Returns:
		    dict: The status document.
		"""
		url = f"{self.root_url}/status"
		response = self._session.get(url, timeout=self.timeout)
		response.raise_for_status()
		return response.json()

	def wait_for_ready(
		self,
		timeout: float = 10.0,
		interval: float = 0.5,
		query: Dict[str, bool] = None,
		diagnostic_url: str = None,
	) -> bool:
		"""
		Block until the OPA server reports healthy, or raise ConnectionsError
		once `timeout` seconds have elapsed.

		Parameters:
		    timeout (float): Maximum time to wait, in seconds.
		    interval (float): Time to sleep between health checks, in seconds.
		    query (Dict[str, bool], optional): Query parameters for the health check.
		    diagnostic_url (str, optional): Custom diagnostic URL.

		Returns:
		    bool: True once OPA becomes healthy.
		"""
		deadline = time.monotonic() + timeout
		while True:
			if self.check_health(query=query, diagnostic_url=diagnostic_url):
				return True
			if time.monotonic() >= deadline:
				raise ConnectionsError(
					"Service not ready",
					f"OPA did not become healthy within {timeout}s",
				)
			time.sleep(interval)

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
		response = self._session.put(
			url,
			data=new_policy.encode("utf-8"),
			headers={"Content-Type": "text/plain"},
			timeout=self.timeout,
		)

		if response.status_code == 200:
			return True

		error = response.json()
		for upgraded in self._prepare_policy_for_upload(
			new_policy, error, rego_compat
		):
			response = self._session.put(
				url,
				data=upgraded.encode("utf-8"),
				headers={"Content-Type": "text/plain"},
				timeout=self.timeout,
			)
			if response.status_code == 200:
				return True
			error = response.json()
			if not is_v0_rego_syntax_error(error):
				break

		self._raise_rego_parse_error(error)

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
			raise FileError(
				"file_not_found", f"'{filepath}' is not a valid file"
			)

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
			self._raise_rego_parse_error(response.json())

	def patch_data(self, endpoint: str, patches: list) -> bool:
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
		response = self._session.patch(
			url,
			json=patches,
			headers={"Content-Type": "application/json-patch+json"},
			timeout=self.timeout,
		)

		if response.status_code == 204:
			return True

		error = response.json()
		raise PatchDataError(error.get("code"), error.get("message"))

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
		body = response.json()
		if response.status_code == 200 and "result" in body:
			return body
		else:
			raise PolicyNotFoundError(
				body.get("code", "PolicyNotFoundError"),
				body.get("message", "requested data not found"),
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
			raise PolicyNotFoundError(
				"resource_not_found", "Policy content is empty"
			)

		full_path = os.path.join(path or "", filename)

		try:
			with open(full_path, "w", encoding="utf-8") as file:
				file.write(policy_raw)
			return True
		except OSError as e:
			raise PathNotFoundError(
				"path_not_found", f"Failed to write to '{full_path}'"
			) from e

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

	def query_rule(
		self,
		input_data: dict,
		package_path: str,
		rule_name: Optional[str] = None,
		query_params: Dict[str, bool] = None,
	) -> dict:
		"""
		Query a specific rule in a package.

		Parameters:
		    input_data (dict): The input data for the query.
		    package_path (str): The package path.
		    rule_name (Optional[str]): The rule name.
		    query_params (Dict[str, bool], optional): Query parameters,
		        e.g. {"explain": "full", "metrics": True, "pretty": True}.

		Returns:
		    dict: The result of the query.
		"""
		path = package_path.replace(".", "/")
		if rule_name:
			path = f"{path}/{rule_name}"
		url = f"{self.root_url}/data/{path}"
		if query_params:
			url = f"{url}?{urlencode(query_params)}"

		response = self._session.post(
			url, json={"input": input_data}, timeout=self.timeout
		)
		response.raise_for_status()
		return response.json()

	def ad_hoc_query(
		self,
		query: str,
		input_data: dict = None,
		query_params: Dict[str, bool] = None,
	) -> dict:
		"""
		Execute an ad-hoc query.

		Parameters:
		    query (str): The query string.
		    input_data (dict, optional): The input data for the query.
		    query_params (Dict[str, bool], optional): Query parameters,
		        e.g. {"explain": "full", "metrics": True, "pretty": True}.

		Returns:
		    dict: The result of the query.
		"""
		url = f"{self.schema}{self.host}:{self.port}/v1/query"
		if query_params:
			url = f"{url}?{urlencode(query_params)}"
		payload = {"query": query}
		if input_data:
			payload["input"] = input_data

		response = self._session.post(
			url, json=payload, timeout=self.timeout
		)
		response.raise_for_status()
		return response.json()

	def bulk_query_rule(
		self,
		inputs: Union[List[dict], Dict[str, dict]],
		package_path: str,
		rule_name: Optional[str] = None,
		query_params: Dict[str, bool] = None,
	) -> Union[List[Any], Dict[str, Any]]:
		"""
		Evaluate the same rule against many different inputs in a single
		round-trip. Each input is evaluated with its own `with input as
		...` override inside one ad-hoc query, so OPA compiles and runs
		all of them together instead of one HTTP request per input.

		Parameters:
		    inputs (Union[List[dict], Dict[str, dict]]): The inputs to
		        evaluate the rule against. Pass a list for positional
		        results, or a dict to get results keyed by your own IDs.
		    package_path (str): The package path, e.g. "app.abac".
		    rule_name (Optional[str]): The rule name, e.g. "allow".
		    query_params (Dict[str, bool], optional): Query parameters,
		        e.g. {"metrics": True}.

		Returns:
		    Union[List[Any], Dict[str, Any]]: The rule's result for each
		    input, in the same shape (list or dict) as `inputs`.

		Raises:
		    ValueError: If `package_path`/`rule_name` isn't a valid Rego
		        identifier, or if the value is a list/dict of length 0.
		    QueryExecuteError: If the rule is undefined for at least one
		        of the inputs (e.g. it has no `default` value and the
		        condition doesn't match).
		"""
		for segment in package_path.split("."):
			if not _REGO_IDENTIFIER_RE.match(segment):
				raise ValueError(f"Invalid package path segment: {segment!r}")
		if rule_name and not _REGO_IDENTIFIER_RE.match(rule_name):
			raise ValueError(f"Invalid rule name: {rule_name!r}")

		is_mapping = isinstance(inputs, dict)
		items = list(inputs.items()) if is_mapping else list(enumerate(inputs))
		if not items:
			return {} if is_mapping else []

		rule_ref = f"data.{package_path}"
		if rule_name:
			rule_ref = f"{rule_ref}.{rule_name}"

		var_names = [f"r{i}" for i in range(len(items))]
		statements = [
			f"{var} := {rule_ref} with input as {json.dumps(item_input)}"
			for var, (_, item_input) in zip(var_names, items)
		]
		response = self.ad_hoc_query(
			"; ".join(statements), query_params=query_params
		)
		result_rows = response.get("result")
		if not result_rows:
			raise QueryExecuteError(
				rule_ref,
				"Rule is undefined for at least one input; check that "
				"it has a default value.",
			)
		values = [result_rows[0].get(var) for var in var_names]

		if is_mapping:
			return dict(zip((key for key, _ in items), values))
		return values

	def compile_query(
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

		response = self._session.post(
			url, json=payload, timeout=self.timeout
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
