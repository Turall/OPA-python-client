import unittest
from unittest.mock import MagicMock, patch

from opa_client import cli


class TestCli(unittest.TestCase):
	@patch("opa_client.cli.OpaClient")
	def test_list_policies(self, mock_opa_client_cls):
		mock_client = MagicMock()
		mock_client.get_policies_list.return_value = ["a", "b"]
		mock_opa_client_cls.return_value = mock_client

		exit_code = cli.main(["list-policies"])

		self.assertEqual(exit_code, 0)
		mock_client.get_policies_list.assert_called_once()
		mock_client.close_connection.assert_called_once()

	@patch("opa_client.cli.OpaClient")
	def test_get_policy(self, mock_opa_client_cls):
		mock_client = MagicMock()
		mock_client.get_policy.return_value = {"result": {"raw": "package x"}}
		mock_opa_client_cls.return_value = mock_client

		exit_code = cli.main(["get-policy", "example"])

		self.assertEqual(exit_code, 0)
		mock_client.get_policy.assert_called_once_with("example")

	@patch("opa_client.cli.OpaClient")
	def test_put_data_inline_json(self, mock_opa_client_cls):
		mock_client = MagicMock()
		mock_client.update_or_create_data.return_value = True
		mock_opa_client_cls.return_value = mock_client

		exit_code = cli.main(["put-data", "acl", "--json", '{"a": 1}'])

		self.assertEqual(exit_code, 0)
		mock_client.update_or_create_data.assert_called_once_with(
			{"a": 1}, "acl"
		)

	@patch("opa_client.cli.OpaClient")
	def test_query_rule_with_input(self, mock_opa_client_cls):
		mock_client = MagicMock()
		mock_client.query_rule.return_value = {"result": True}
		mock_opa_client_cls.return_value = mock_client

		exit_code = cli.main(
			["query-rule", "play", "hello", "--input", '{"message": "world"}']
		)

		self.assertEqual(exit_code, 0)
		mock_client.query_rule.assert_called_once_with(
			{"message": "world"}, "play", "hello"
		)

	@patch("opa_client.cli.OpaClient")
	def test_bulk_query_rule_with_inline_json(self, mock_opa_client_cls):
		mock_client = MagicMock()
		mock_client.bulk_query_rule.return_value = [True, False]
		mock_opa_client_cls.return_value = mock_client

		exit_code = cli.main(
			[
				"bulk-query-rule",
				"app.abac",
				"allow",
				"--inputs-json",
				'[{"role": "admin"}, {"role": "user"}]',
			]
		)

		self.assertEqual(exit_code, 0)
		mock_client.bulk_query_rule.assert_called_once_with(
			[{"role": "admin"}, {"role": "user"}], "app.abac", "allow"
		)

	@patch("opa_client.cli.OpaClient")
	def test_wait_for_ready(self, mock_opa_client_cls):
		mock_client = MagicMock()
		mock_client.wait_for_ready.return_value = True
		mock_opa_client_cls.return_value = mock_client

		exit_code = cli.main(["wait-for-ready", "--max-wait", "3"])

		self.assertEqual(exit_code, 0)
		mock_client.wait_for_ready.assert_called_once_with(timeout=3.0)

	@patch("opa_client.cli.OpaClient")
	def test_error_returns_nonzero_exit_code(self, mock_opa_client_cls):
		mock_client = MagicMock()
		mock_client.get_policy.side_effect = Exception("boom")
		mock_opa_client_cls.return_value = mock_client

		exit_code = cli.main(["get-policy", "missing"])

		self.assertEqual(exit_code, 1)
		mock_client.close_connection.assert_called_once()

	@patch("opa_client.cli.OpaClient")
	def test_token_passed_to_client(self, mock_opa_client_cls):
		mock_client = MagicMock()
		mock_opa_client_cls.return_value = mock_client

		cli.main(["--token", "secret", "health"])

		mock_opa_client_cls.assert_called_once_with(
			host="localhost",
			port=8181,
			ssl=False,
			token="secret",
			timeout=1.5,
		)


if __name__ == "__main__":
	unittest.main()
