import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from opa_client import create_opa_client
from opa_client.errors import (
	ConnectionsError,
	DeleteDataError,
	DeletePolicyError,
	PolicyNotFoundError,
	RegoParseError,
)


class TestAsyncOpaClient(unittest.IsolatedAsyncioTestCase):
	async def asyncSetUp(self):
		self.client = create_opa_client(
			async_mode=True, host="localhost", port=8181
		)
		await self.client._init_session()

	async def asyncTearDown(self):
		await self.client.close_connection()

	@patch("aiohttp.ClientSession.get")
	async def test_check_connection_success(self, mock_get):
		mock_response = AsyncMock()
		mock_response.status = 200
		mock_get.return_value.__aenter__.return_value = mock_response

		result = await self.client.check_connection()
		self.assertEqual(result, True)
		mock_get.assert_called_once()

	@patch("aiohttp.ClientSession.get")
	async def test_check_connection_failure(self, mock_get):
		mock_response = AsyncMock()
		mock_response.status = 500
		mock_get.return_value.__aenter__.return_value = mock_response

		with self.assertRaises(ConnectionsError):
			await self.client.check_connection()
		mock_get.assert_called_once()

	@patch("aiohttp.ClientSession.get")
	async def test_get_policies_list(self, mock_get):
		mock_response = AsyncMock()
		mock_response.status = 200
		mock_response.raise_for_status = Mock()
		mock_response.json = AsyncMock(
			return_value={"result": [{"id": "policy1"}, {"id": "policy2"}]}
		)
		mock_get.return_value.__aenter__.return_value = mock_response

		policies = await self.client.get_policies_list()
		self.assertEqual(policies, ["policy1", "policy2"])
		mock_get.assert_called_once()

	@patch("aiohttp.ClientSession.put")
	async def test_update_policy_from_string_success(self, mock_put):
		mock_response = AsyncMock()
		mock_response.status = 200
		mock_put.return_value.__aenter__.return_value = mock_response

		new_policy = "package example\n\ndefault allow = false"
		result = await self.client.update_policy_from_string(
			new_policy, "example"
		)
		self.assertTrue(result)
		mock_put.assert_called_once()

	@patch("aiohttp.ClientSession.put")
	async def test_update_policy_from_string_failure(self, mock_put):
		mock_response = AsyncMock()
		mock_response.status = 400
		mock_response.json = AsyncMock(
			return_value={
				"code": "invalid_parameter",
				"message": "Parse error",
			}
		)
		mock_put.return_value.__aenter__.return_value = mock_response

		new_policy = "invalid policy"
		with self.assertRaises(Exception) as context:
			await self.client.update_policy_from_string(new_policy, "invalid")

		self.assertIsInstance(context.exception, RegoParseError)
		mock_put.assert_called_once()

	@patch("aiohttp.ClientSession.delete")
	async def test_delete_policy_success(self, mock_delete):
		mock_response = AsyncMock()
		mock_response.status = 200
		mock_delete.return_value.__aenter__.return_value = mock_response

		result = await self.client.delete_policy("policy1")
		self.assertTrue(result)
		mock_delete.assert_called_once()

	@patch("aiohttp.ClientSession.delete")
	async def test_delete_policy_failure(self, mock_delete):
		mock_response = AsyncMock()
		mock_response.status = 404
		mock_response.json = AsyncMock(
			return_value={"code": "not_found", "message": "Policy not found"}
		)
		mock_delete.return_value.__aenter__.return_value = mock_response

		with self.assertRaises(DeletePolicyError):
			await self.client.delete_policy("nonexistent_policy")
		mock_delete.assert_called_once()

	# Add more test methods to cover other functionalities


if __name__ == "__main__":
	unittest.main()
