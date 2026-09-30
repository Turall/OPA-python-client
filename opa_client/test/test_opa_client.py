import unittest
from unittest.mock import Mock, patch

import requests

from opa_client import create_opa_client
from opa_client.errors import (
	ConnectionsError,
	DeletePolicyError,
	PatchDataError,
	QueryExecuteError,
	RegoParseError,
)


class TestOpaClient(unittest.TestCase):
	def setUp(self):
		self.client = create_opa_client(host="localhost", port=8181)

	def tearDown(self):
		self.client.close_connection()

	@patch("requests.Session.get")
	def test_check_connection_success(self, mock_get):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_get.return_value = mock_response

		result = self.client.check_connection()
		self.assertEqual(result, True)
		mock_get.assert_called_once()

	@patch("requests.Session.get")
	def test_check_connection_failure(self, mock_get):
		mock_response = Mock()
		mock_response.status_code = 500
		mock_response.raise_for_status.side_effect = (
			requests.exceptions.HTTPError()
		)
		mock_get.return_value = mock_response
		with self.assertRaises(ConnectionsError):
			self.client.check_connection()
		mock_get.assert_called_once()

	@patch("requests.Session.get")
	def test_get_policies_list(self, mock_get):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_response.json.return_value = {
			"result": [{"id": "policy1"}, {"id": "policy2"}]
		}
		mock_get.return_value = mock_response

		policies = self.client.get_policies_list()
		self.assertEqual(policies, ["policy1", "policy2"])
		mock_get.assert_called_once()

	@patch("requests.Session.put")
	def test_update_policy_from_string_success(self, mock_put):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_put.return_value = mock_response

		new_policy = "package example\n\ndefault allow = false"
		result = self.client.update_policy_from_string(new_policy, "example")
		self.assertTrue(result)
		mock_put.assert_called_once()

	@patch("requests.Session.put")
	def test_update_policy_from_string_v0_auto_upgrade(self, mock_put):
		v0_error_response = Mock()
		v0_error_response.status_code = 400
		v0_error_response.json.return_value = {
			"code": "invalid_parameter",
			"message": "error(s) occurred while compiling module(s)",
			"errors": [
				{
					"message": "`if` keyword is required before rule body",
				}
			],
		}
		success_response = Mock()
		success_response.status_code = 200
		mock_put.side_effect = [v0_error_response, success_response]

		new_policy = "package example\n\nallow {\n    true\n}\n"
		result = self.client.update_policy_from_string(new_policy, "example")
		self.assertTrue(result)
		self.assertEqual(mock_put.call_count, 2)
		upgraded_payload = (
			mock_put.call_args_list[1].kwargs["data"].decode("utf-8")
		)
		self.assertIn("allow if {", upgraded_payload)
		self.assertNotIn("import rego.v1", upgraded_payload)

	@patch("requests.Session.put")
	def test_update_policy_from_string_failure(self, mock_put):
		mock_response = Mock()
		mock_response.status_code = 400
		mock_response.json.return_value = {
			"code": "invalid_parameter",
			"message": "Parse error",
		}
		mock_put.return_value = mock_response

		new_policy = "invalid policy"
		with self.assertRaises(Exception) as context:
			self.client.update_policy_from_string(new_policy, "invalid")

		self.assertIsInstance(context.exception, RegoParseError)
		mock_put.assert_called_once()

	@patch("requests.Session.delete")
	def test_delete_policy_success(self, mock_delete):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_delete.return_value = mock_response

		result = self.client.delete_policy("policy1")
		self.assertTrue(result)
		mock_delete.assert_called_once()

	@patch("requests.Session.delete")
	def test_delete_policy_failure(self, mock_delete):
		mock_response = Mock()
		mock_response.status_code = 404
		mock_response.json.return_value = {
			"code": "not_found",
			"message": "Policy not found",
		}
		mock_delete.return_value = mock_response

		with self.assertRaises(DeletePolicyError):
			self.client.delete_policy("nonexistent_policy")
		mock_delete.assert_called_once()

	@patch("requests.Session.post")
	def test_compile_query(self, mock_post):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_response.json.return_value = {"result": {"queries": [[]]}}
		mock_post.return_value = mock_response

		result = self.client.compile_query(
			"data.example.allow == true",
			input_data={"user": {"role": "admin"}},
			unknowns=[],
		)
		self.assertEqual(result, {"result": {"queries": [[]]}})
		mock_post.assert_called_once()
		payload = mock_post.call_args.kwargs["json"]
		self.assertEqual(payload["query"], "data.example.allow == true")
		self.assertEqual(payload["input"], {"user": {"role": "admin"}})
		self.assertEqual(payload["unknowns"], [])

	@patch("requests.Session.get")
	def test_get_config(self, mock_get):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_response.json.return_value = {
			"result": {"labels": {"version": "0.68.0"}}
		}
		mock_get.return_value = mock_response

		result = self.client.get_config()
		self.assertEqual(result["result"]["labels"]["version"], "0.68.0")
		mock_get.assert_called_once()

	@patch("requests.Session.get")
	def test_get_metrics(self, mock_get):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_response.text = "# HELP go_info Information.\ngo_info 1\n"
		mock_get.return_value = mock_response

		result = self.client.get_metrics()
		self.assertIn("go_info", result)
		call_url = mock_get.call_args.args[0]
		self.assertTrue(call_url.endswith(":8181/metrics"))

	@patch("requests.Session.patch")
	def test_patch_data_success(self, mock_patch):
		mock_response = Mock()
		mock_response.status_code = 204
		mock_patch.return_value = mock_response

		result = self.client.patch_data(
			"users", [{"op": "add", "path": "/a", "value": 1}]
		)
		self.assertTrue(result)
		mock_patch.assert_called_once()
		payload = mock_patch.call_args.kwargs["json"]
		self.assertEqual(payload, [{"op": "add", "path": "/a", "value": 1}])

	@patch("requests.Session.patch")
	def test_patch_data_failure(self, mock_patch):
		mock_response = Mock()
		mock_response.status_code = 404
		mock_response.json.return_value = {
			"code": "resource_not_found",
			"message": "document does not exist",
		}
		mock_patch.return_value = mock_response

		with self.assertRaises(PatchDataError):
			self.client.patch_data(
				"missing", [{"op": "add", "path": "/a", "value": 1}]
			)

	def test_patch_data_invalid_type(self):
		with self.assertRaises(TypeError):
			self.client.patch_data("users", {"op": "add"})

	@patch("requests.Session.get")
	def test_get_status(self, mock_get):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_response.json.return_value = {
			"result": {"labels": {"version": "0.68.0"}}
		}
		mock_get.return_value = mock_response

		result = self.client.get_status()
		self.assertEqual(result["result"]["labels"]["version"], "0.68.0")
		call_url = mock_get.call_args.args[0]
		self.assertTrue(call_url.endswith("/v1/status"))

	@patch("requests.Session.get")
	def test_get_status_raises_http_error_when_plugin_disabled(
		self, mock_get
	):
		error_response = Mock()
		error_response.json.return_value = {
			"code": "internal_error",
			"message": "status plugin not enabled",
		}
		http_error = requests.exceptions.HTTPError(response=error_response)
		mock_response = Mock()
		mock_response.raise_for_status.side_effect = http_error
		mock_get.return_value = mock_response

		with self.assertRaises(requests.exceptions.HTTPError) as ctx:
			self.client.get_status()
		self.assertEqual(
			ctx.exception.response.json()["message"],
			"status plugin not enabled",
		)

	@patch("requests.Session.get")
	def test_wait_for_ready_success(self, mock_get):
		unhealthy = Mock(status_code=500)
		healthy = Mock(status_code=200)
		mock_get.side_effect = [unhealthy, healthy]

		result = self.client.wait_for_ready(timeout=5, interval=0)
		self.assertTrue(result)
		self.assertEqual(mock_get.call_count, 2)

	@patch("requests.Session.get")
	def test_wait_for_ready_timeout(self, mock_get):
		mock_get.return_value = Mock(status_code=500)

		with self.assertRaises(ConnectionsError):
			self.client.wait_for_ready(timeout=0.05, interval=0.01)

	def test_token_sets_authorization_header(self):
		client = create_opa_client(
			host="localhost", port=8181, token="secret-token"
		)
		self.assertEqual(
			client.headers["Authorization"], "Bearer secret-token"
		)
		client.close_connection()

	@patch("requests.Session.post")
	def test_query_rule_with_query_params(self, mock_post):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_response.json.return_value = {"result": True}
		mock_post.return_value = mock_response

		result = self.client.query_rule(
			{"message": "world"},
			"play",
			"hello",
			query_params={"metrics": True},
		)
		self.assertEqual(result, {"result": True})
		call_url = mock_post.call_args.args[0]
		self.assertIn("metrics=True", call_url)

	@patch("requests.Session.post")
	def test_ad_hoc_query_with_query_params(self, mock_post):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_response.json.return_value = {"result": []}
		mock_post.return_value = mock_response

		result = self.client.ad_hoc_query(
			"data.example.allow", query_params={"explain": "full"}
		)
		self.assertEqual(result, {"result": []})
		call_url = mock_post.call_args.args[0]
		self.assertIn("explain=full", call_url)

	@patch("requests.Session.post")
	def test_bulk_query_rule_with_list_input(self, mock_post):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_response.json.return_value = {
			"result": [{"r0": True, "r1": False}]
		}
		mock_post.return_value = mock_response

		result = self.client.bulk_query_rule(
			[{"role": "admin"}, {"role": "user"}], "app.abac", "allow"
		)
		self.assertEqual(result, [True, False])
		payload = mock_post.call_args.kwargs["json"]
		self.assertIn("r0 := data.app.abac.allow with input as", payload["query"])
		self.assertIn("r1 := data.app.abac.allow with input as", payload["query"])

	@patch("requests.Session.post")
	def test_bulk_query_rule_with_dict_input(self, mock_post):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_response.json.return_value = {
			"result": [{"r0": True, "r1": False}]
		}
		mock_post.return_value = mock_response

		result = self.client.bulk_query_rule(
			{"alice": {"role": "admin"}, "bob": {"role": "user"}},
			"app.abac",
			"allow",
		)
		self.assertEqual(result, {"alice": True, "bob": False})

	def test_bulk_query_rule_empty_inputs_skips_request(self):
		self.assertEqual(
			self.client.bulk_query_rule([], "app.abac", "allow"), []
		)
		self.assertEqual(
			self.client.bulk_query_rule({}, "app.abac", "allow"), {}
		)

	def test_bulk_query_rule_rejects_invalid_package_path(self):
		with self.assertRaises(ValueError):
			self.client.bulk_query_rule(
				[{"role": "admin"}], "app; malicious", "allow"
			)

	@patch("requests.Session.post")
	def test_bulk_query_rule_raises_on_undefined_rule(self, mock_post):
		mock_response = Mock()
		mock_response.status_code = 200
		mock_response.json.return_value = {}
		mock_post.return_value = mock_response

		with self.assertRaises(QueryExecuteError):
			self.client.bulk_query_rule(
				[{"role": "admin"}], "app.abac", "allow"
			)

	# Add more test methods to cover other functionalities


if __name__ == "__main__":
	unittest.main()
