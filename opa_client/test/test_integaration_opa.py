import unittest

from opa_client.errors import (
	ConnectionsError,
	DeleteDataError,
	DeletePolicyError,
	PolicyNotFoundError,
	RegoParseError,
)
from opa_client.opa import OpaClient


class TestIntegrationOpaClient(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.client = OpaClient(host="localhost", port=8181)
		try:
			cls.client.check_connection()
		except ConnectionsError:
			raise RuntimeError(
				"OPA server is not running. Please start the OPA server before running tests."
			)

	@classmethod
	def tearDownClass(cls):
		cls.client.close_connection()

	def test_check_connection(self):
		result = self.client.check_connection()
		self.assertEqual(result, True)

	def test_policy_lifecycle(self):
		# Define a sample policy
		policy_name = "example_policy"
		policy_content = """
        package example

        default allow = false

        allow {
            input.user == "admin"
        }
        """

		# Create/Update the policy
		result = self.client.update_policy_from_string(
			policy_content, policy_name
		)
		self.assertTrue(result)

		# Retrieve the policy
		policy = self.client.get_policy(policy_name)
		self.assertIn("result", policy)
		self.assertIn("raw", policy["result"])
		self.assertIn("package example", policy["result"]["raw"])

		# Delete the policy
		result = self.client.delete_policy(policy_name)
		self.assertTrue(result)

		# Ensure the policy is deleted
		with self.assertRaises(PolicyNotFoundError):
			self.client.get_policy(policy_name)

	def test_data_lifecycle(self):
		# Define sample data
		data_name = "users"
		data_content = {
			"users": [
				{"name": "alice", "role": "admin"},
				{"name": "bob", "role": "user"},
			]
		}

		# Create/Update the data
		result = self.client.update_or_create_data(data_content, data_name)
		self.assertTrue(result)

		# Retrieve the data
		data = self.client.get_data(data_name)
		self.assertIn("result", data)
		self.assertEqual(data["result"], data_content)

		# Delete the data
		result = self.client.delete_data(data_name)
		self.assertTrue(result)

		# Ensure the data is deleted
		with self.assertRaises(PolicyNotFoundError):
			self.client.get_data(data_name)

	def test_check_permission(self):
		# Define a sample policy
		policy_name = "authz"
		policy_content = """
        package authz

        default allow = false

        allow {
            input.user.role == "admin"
        }
        """

		# Create the policy
		self.client.update_policy_from_string(policy_content, policy_name)

		# Define sample input data
		input_data = {"user": {"name": "alice", "role": "admin"}}

		# Check permission
		result = self.client.check_permission(input_data, policy_name, "allow")
		self.assertIn("result", result), result
		self.assertTrue(result["result"])

		# Clean up
		self.client.delete_policy(policy_name)

	# Add more integration tests as needed


if __name__ == "__main__":
	unittest.main()
