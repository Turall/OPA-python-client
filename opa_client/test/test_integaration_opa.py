import unittest

from opa_client.errors import (
	ConnectionsError,
	PatchDataError,
	PolicyNotFoundError,
	QueryExecuteError,
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

	def test_query_rule(self):
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

		# Query the rule
		result = self.client.query_rule(input_data, "authz", "allow")
		self.assertIn("result", result), result
		self.assertTrue(result["result"])

		# Clean up
		self.client.delete_policy(policy_name)

	def test_bulk_query_rule(self):
		policy_name = "authz_bulk"
		policy_content = """
        package authz_bulk

        default allow = false

        allow {
            input.role == "admin"
        }
        """
		self.client.update_policy_from_string(policy_content, policy_name)

		inputs = [{"role": "admin"}, {"role": "user"}, {"role": "admin"}]
		result = self.client.bulk_query_rule(inputs, "authz_bulk", "allow")
		self.assertEqual(result, [True, False, True])

		keyed_inputs = {
			"alice": {"role": "admin"},
			"bob": {"role": "user"},
		}
		result = self.client.bulk_query_rule(
			keyed_inputs, "authz_bulk", "allow"
		)
		self.assertEqual(result, {"alice": True, "bob": False})

		self.assertEqual(
			self.client.bulk_query_rule([], "authz_bulk", "allow"), []
		)

		with self.assertRaises(ValueError):
			self.client.bulk_query_rule(
				[{"role": "admin"}], "authz_bulk; drop", "allow"
			)

		self.client.delete_policy(policy_name)

	def test_bulk_query_rule_undefined_rule_raises(self):
		policy_name = "authz_bulk_nodefault"
		policy_content = """
        package authz_bulk_nodefault

        allow {
            input.role == "admin"
        }
        """
		self.client.update_policy_from_string(policy_content, policy_name)

		with self.assertRaises(QueryExecuteError):
			self.client.bulk_query_rule(
				[{"role": "user"}], "authz_bulk_nodefault", "allow"
			)

		self.client.delete_policy(policy_name)

	def test_compile_query(self):
		# Define a sample policy
		policy_name = "authz_compile"
		policy_content = """
        package authz_compile

        default allow = false

        allow {
            input.user.role == "admin"
        }
        """
		self.client.update_policy_from_string(policy_content, policy_name)

		# Fully resolved query: input is fully known, so the compiler
		# should reduce the query to unconditionally true.
		resolved = self.client.compile_query(
			"data.authz_compile.allow == true",
			input_data={"user": {"role": "admin"}},
			unknowns=[],
		)
		self.assertEqual(resolved["result"], {"queries": [[]]})

		# Partial evaluation: leave input.user.role unknown so the
		# compiler returns a residual expression instead of a boolean.
		partial = self.client.compile_query(
			"data.authz_compile.allow == true",
			unknowns=["input.user.role"],
		)
		self.assertIn("queries", partial["result"])
		self.assertTrue(partial["result"]["queries"])

		# Clean up
		self.client.delete_policy(policy_name)

	def test_get_config(self):
		config = self.client.get_config()
		self.assertIn("result", config)
		self.assertIn("labels", config["result"])

	def test_get_metrics(self):
		metrics = self.client.get_metrics()
		self.assertIsInstance(metrics, str)
		self.assertIn("go_info", metrics)

	def test_patch_data(self):
		data_name = "patchtest"
		self.client.update_or_create_data({"a": {"b": 1}}, data_name)

		result = self.client.patch_data(
			data_name, [{"op": "add", "path": "/a/c", "value": 2}]
		)
		self.assertTrue(result)

		data = self.client.get_data(data_name)
		self.assertEqual(data["result"], {"a": {"b": 1, "c": 2}})

		self.client.delete_data(data_name)

		with self.assertRaises(PatchDataError):
			self.client.patch_data(
				"nonexistent_path",
				[{"op": "replace", "path": "/x", "value": 1}],
			)

	# Add more integration tests as needed


if __name__ == "__main__":
	unittest.main()
