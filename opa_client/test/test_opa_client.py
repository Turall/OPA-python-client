import unittest
from unittest.mock import Mock, patch

import requests

from opa_client import create_opa_client
from opa_client.errors import (
	ConnectionsError,
	DeleteDataError,
	DeletePolicyError,
	PolicyNotFoundError,
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

	# Add more test methods to cover other functionalities


if __name__ == "__main__":
	unittest.main()
