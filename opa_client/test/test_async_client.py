import unittest
from unittest.mock import AsyncMock, Mock, patch

from opa_client import create_opa_client
from opa_client.errors import (
	ConnectionsError,
	DeletePolicyError,
	PatchDataError,
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

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_check_connection_success(self, mock_request):
		mock_response = AsyncMock()
		mock_response.status = 200
		mock_request.return_value = mock_response

		result = await self.client.check_connection()
		self.assertEqual(result, True)
		mock_request.assert_called_once()

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_check_connection_failure(self, mock_request):
		mock_response = AsyncMock()
		mock_response.status = 500
		mock_request.return_value = mock_response

		with self.assertRaises(ConnectionsError):
			await self.client.check_connection()

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_get_policies_list(self, mock_request):
		mock_response = AsyncMock()
		mock_response.status = 200
		mock_response.raise_for_status = Mock()
		mock_response.json = AsyncMock(
			return_value={"result": [{"id": "policy1"}, {"id": "policy2"}]}
		)
		mock_request.return_value = mock_response

		policies = await self.client.get_policies_list()
		self.assertEqual(policies, ["policy1", "policy2"])
		mock_request.assert_called_once()

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_update_policy_from_string_success(self, mock_request):
		mock_response = AsyncMock()
		mock_response.status = 200
		mock_request.return_value = mock_response

		new_policy = "package example\n\ndefault allow = false"
		result = await self.client.update_policy_from_string(
			new_policy, "example"
		)
		self.assertTrue(result)
		mock_request.assert_called_once()

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_update_policy_from_string_failure(self, mock_request):
		mock_response = AsyncMock()
		mock_response.status = 400
		mock_response.json = AsyncMock(
			return_value={
				"code": "invalid_parameter",
				"message": "Parse error",
			}
		)
		mock_request.return_value = mock_response

		new_policy = "invalid policy"
		with self.assertRaises(Exception) as context:
			await self.client.update_policy_from_string(new_policy, "invalid")

		self.assertIsInstance(context.exception, RegoParseError)

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_delete_policy_success(self, mock_request):
		mock_response = AsyncMock()
		mock_response.status = 200
		mock_request.return_value = mock_response

		result = await self.client.delete_policy("policy1")
		self.assertTrue(result)
		mock_request.assert_called_once()

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_delete_policy_failure(self, mock_request):
		mock_response = AsyncMock()
		mock_response.status = 404
		mock_response.json = AsyncMock(
			return_value={"code": "not_found", "message": "Policy not found"}
		)
		mock_request.return_value = mock_response

		with self.assertRaises(DeletePolicyError):
			await self.client.delete_policy("nonexistent_policy")

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_compile_query(self, mock_request):
		mock_response = AsyncMock()
		mock_response.status = 200
		mock_response.raise_for_status = Mock()
		mock_response.json = AsyncMock(
			return_value={"result": {"queries": [[]]}}
		)
		mock_request.return_value = mock_response

		result = await self.client.compile_query(
			"data.example.allow == true",
			input_data={"user": {"role": "admin"}},
			unknowns=[],
		)
		self.assertEqual(result, {"result": {"queries": [[]]}})
		mock_request.assert_called_once()
		call_args = mock_request.call_args
		self.assertEqual(call_args.args[0], "POST")
		payload = call_args.kwargs["json"]
		self.assertEqual(payload["query"], "data.example.allow == true")
		self.assertEqual(payload["input"], {"user": {"role": "admin"}})
		self.assertEqual(payload["unknowns"], [])

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_request_retries_on_502_then_succeeds(self, mock_request):
		failing_response = AsyncMock()
		failing_response.status = 502
		success_response = AsyncMock()
		success_response.status = 200
		mock_request.side_effect = [failing_response, success_response]

		result = await self.client.check_connection()
		self.assertEqual(result, True)
		self.assertEqual(mock_request.call_count, 2)

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_get_config(self, mock_request):
		mock_response = AsyncMock()
		mock_response.status = 200
		mock_response.raise_for_status = Mock()
		mock_response.json = AsyncMock(
			return_value={"result": {"labels": {"version": "0.68.0"}}}
		)
		mock_request.return_value = mock_response

		result = await self.client.get_config()
		self.assertEqual(result["result"]["labels"]["version"], "0.68.0")
		mock_request.assert_called_once()

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_get_metrics(self, mock_request):
		mock_response = AsyncMock()
		mock_response.status = 200
		mock_response.raise_for_status = Mock()
		mock_response.text = AsyncMock(
			return_value="# HELP go_info Information.\ngo_info 1\n"
		)
		mock_request.return_value = mock_response

		result = await self.client.get_metrics()
		self.assertIn("go_info", result)
		call_args = mock_request.call_args
		self.assertTrue(call_args.args[1].endswith(":8181/metrics"))

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_patch_data_success(self, mock_request):
		mock_response = AsyncMock()
		mock_response.status = 204
		mock_request.return_value = mock_response

		result = await self.client.patch_data(
			"users", [{"op": "add", "path": "/a", "value": 1}]
		)
		self.assertTrue(result)
		mock_request.assert_called_once()
		call_args = mock_request.call_args
		self.assertEqual(call_args.args[0], "PATCH")
		self.assertEqual(
			call_args.kwargs["json"], [{"op": "add", "path": "/a", "value": 1}]
		)

	@patch("aiohttp.ClientSession.request", new_callable=AsyncMock)
	async def test_patch_data_failure(self, mock_request):
		mock_response = AsyncMock()
		mock_response.status = 404
		mock_response.json = AsyncMock(
			return_value={
				"code": "resource_not_found",
				"message": "document does not exist",
			}
		)
		mock_request.return_value = mock_response

		with self.assertRaises(PatchDataError):
			await self.client.patch_data(
				"missing", [{"op": "add", "path": "/a", "value": 1}]
			)

	async def test_patch_data_invalid_type(self):
		with self.assertRaises(TypeError):
			await self.client.patch_data("users", {"op": "add"})

	# Add more test methods to cover other functionalities


if __name__ == "__main__":
	unittest.main()
