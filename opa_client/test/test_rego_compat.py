import unittest

from opa_client.errors import RegoParseError
from opa_client.rego_compat import (
	is_v0_rego_syntax_error,
	prepare_policy_for_upload,
	raise_rego_parse_error,
	upgrade_policy_to_v1,
)


class TestRegoCompat(unittest.TestCase):
	def test_upgrade_simple_allow_rule(self):
		policy = """package example

default allow = false

allow {
    input.user == "admin"
}
"""
		upgraded = upgrade_policy_to_v1(policy)
		self.assertIn("allow if {", upgraded)
		self.assertNotIn("allow {", upgraded)
		self.assertNotIn("import rego.v1", upgraded)

	def test_upgrade_with_import_for_opa_zero_x(self):
		policy = """package example

allow {
    true
}
"""
		upgraded = upgrade_policy_to_v1(policy, include_import=True)
		self.assertIn("import rego.v1", upgraded)
		self.assertIn("allow if {", upgraded)

	def test_upgrade_dedents_indented_policy(self):
		policy = """
        package example

        allow {
            true
        }
        """
		upgraded = upgrade_policy_to_v1(policy)
		self.assertIn("package example\n", upgraded)
		self.assertNotIn("        package example", upgraded)

	def test_upgrade_partial_set_rule(self):
		policy = """package example

deny[msg] {
    msg := "denied"
}
"""
		upgraded = upgrade_policy_to_v1(policy)
		self.assertIn("deny contains msg if {", upgraded)

	def test_does_not_duplicate_rego_v1_import(self):
		policy = """import rego.v1

package example

allow if {
    true
}
"""
		upgraded = upgrade_policy_to_v1(policy)
		self.assertEqual(upgraded.count("import rego.v1"), 1)

	def test_is_v0_rego_syntax_error(self):
		error = {
			"errors": [
				{
					"message": "`if` keyword is required before rule body",
				}
			]
		}
		self.assertTrue(is_v0_rego_syntax_error(error))
		self.assertFalse(is_v0_rego_syntax_error({"errors": []}))

	def test_prepare_policy_for_upload_disabled(self):
		error = {
			"errors": [
				{"message": "`if` keyword is required before rule body"}
			]
		}
		policy = "package example\n\nallow {\n    true\n}\n"
		self.assertEqual(
			prepare_policy_for_upload(policy, error, rego_compat=False), []
		)

	def test_raise_rego_parse_error_includes_details(self):
		error = {
			"code": "invalid_parameter",
			"message": "error(s) occurred while compiling module(s)",
			"errors": [
				{"message": "`if` keyword is required before rule body"}
			],
		}
		with self.assertRaises(RegoParseError) as context:
			raise_rego_parse_error(error)

		self.assertIn(
			"`if` keyword is required before rule body",
			str(context.exception),
		)


if __name__ == "__main__":
	unittest.main()
