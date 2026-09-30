import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import requests

from opa_client.opa import OpaClient

_CONTAINER_NAME = "opa-python-client-auth-test"
_PORT = 8283
_VALID_TOKEN = "supersecrettoken"

_AUTHZ_POLICY = f"""
package system.authz

default allow = false

allow if {{
	input.identity == "{_VALID_TOKEN}"
}}
"""


def _docker_available() -> bool:
	return shutil.which("docker") is not None


def _port_open(host: str, port: int) -> bool:
	try:
		with socket.create_connection((host, port), timeout=0.5):
			return True
	except OSError:
		return False


@unittest.skipUnless(_docker_available(), "docker is required for this test")
class TestIntegrationAuth(unittest.TestCase):
	"""
	Verifies OpaClient's `token` parameter against a real OPA server
	running with `--authentication=token --authorization=basic`.
	"""

	@classmethod
	def setUpClass(cls):
		cls.policy_dir = tempfile.mkdtemp()
		Path(cls.policy_dir, "authz.rego").write_text(_AUTHZ_POLICY)

		subprocess.run(
			["docker", "rm", "-f", _CONTAINER_NAME], capture_output=True
		)
		subprocess.run(
			[
				"docker",
				"run",
				"-d",
				"--name",
				_CONTAINER_NAME,
				"-p",
				f"{_PORT}:{_PORT}",
				"-v",
				f"{cls.policy_dir}:/policies",
				"openpolicyagent/opa:latest",
				"run",
				"--server",
				f"--addr=:{_PORT}",
				"--authentication=token",
				"--authorization=basic",
				"/policies/authz.rego",
			],
			check=True,
			capture_output=True,
		)

		deadline = time.monotonic() + 15
		while not _port_open("localhost", _PORT):
			if time.monotonic() >= deadline:
				cls.tearDownClass()
				raise RuntimeError(
					"OPA auth test server did not start in time."
				)
			time.sleep(0.5)

		# Port accepting connections doesn't guarantee the policy has
		# finished loading yet, so poll using our own CLI until an
		# authenticated request actually succeeds.
		deadline = time.monotonic() + 15
		while True:
			result = subprocess.run(
				[
					sys.executable,
					"-m",
					"opa_client.cli",
					"--port",
					str(_PORT),
					"--token",
					_VALID_TOKEN,
					"list-policies",
				],
				capture_output=True,
			)
			if result.returncode == 0:
				break
			if time.monotonic() >= deadline:
				cls.tearDownClass()
				raise RuntimeError(
					"OPA auth test server did not become ready in time."
				)
			time.sleep(0.5)

	@classmethod
	def tearDownClass(cls):
		subprocess.run(
			["docker", "rm", "-f", _CONTAINER_NAME], capture_output=True
		)
		shutil.rmtree(cls.policy_dir, ignore_errors=True)

	@staticmethod
	def _run_cli(*args):
		return subprocess.run(
			[sys.executable, "-m", "opa_client.cli", "--port", str(_PORT)]
			+ list(args),
			capture_output=True,
			text=True,
		)

	def test_request_without_token_is_rejected(self):
		client = OpaClient(host="localhost", port=_PORT, timeout=3)
		with self.assertRaises(requests.exceptions.HTTPError):
			client.get_policies_list()
		client.close_connection()

		result = self._run_cli("list-policies")
		self.assertNotEqual(result.returncode, 0)

	def test_request_with_wrong_token_is_rejected(self):
		client = OpaClient(
			host="localhost", port=_PORT, token="wrongtoken", timeout=3
		)
		with self.assertRaises(requests.exceptions.HTTPError):
			client.get_policies_list()
		client.close_connection()

		result = self._run_cli("--token", "wrongtoken", "list-policies")
		self.assertNotEqual(result.returncode, 0)

	def test_request_with_valid_token_is_accepted(self):
		client = OpaClient(
			host="localhost", port=_PORT, token=_VALID_TOKEN, timeout=3
		)
		policies = client.get_policies_list()
		self.assertIn("policies/authz.rego", policies)
		client.close_connection()

		result = self._run_cli("--token", _VALID_TOKEN, "list-policies")
		self.assertEqual(result.returncode, 0)
		self.assertIn("policies/authz.rego", result.stdout)


if __name__ == "__main__":
	unittest.main()
