# -*- coding: utf-8 -*-
"""
Unit tests for the OpaClient.
"""


from unittest import TestCase

from opa_client.errors import DeleteDataError, DeletePolicyError
from opa_client.opa import OpaClient


class TestClient(TestCase):
    def test_client(self):
        """Set up the test  for OpaClient object"""
        with OpaClient() as client:
            self.assertEqual('http://localhost:8181/v1', client._root_url)
            self.assertFalse(False, client._secure)
            self.assertEqual('http://', client._schema)
            self.assertEqual('v1', client._version)
            self.assertEqual('localhost', client._host)
            self.assertEqual(8181, client._port)

    def test_functions(self):
        with OpaClient() as client:
            self.assertEqual("Yes I'm here :)", client.check_connection())
            self.assertEqual(list(), client.get_policies_list())
            self.assertEqual(dict(), client.get_policies_info())

            new_policy = """
                package play

                default hello = false

                hello {
                    m := input.message
                    m == "world"
                }
            """
            self.assertEqual(
                True, client.update_opa_policy_fromstring(new_policy, 'test')
            )

            self.assertEqual(['test'], client.get_policies_list())
            _dict = {
                'test': {
                    'path': ['http://localhost:8181/v1/data/play'],
                    'rules': ['http://localhost:8181/v1/data/play/hello'],
                }
            }

            self.assertEqual(_dict, client.get_policies_info())

            my_policy_list = [
                {
                    'resource': '/api/someapi',
                    'identity': 'your_identity',
                    'method': 'PUT',
                },
                {
                    'resource': '/api/someapi',
                    'identity': 'your_identity',
                    'method': 'GET',
                },
            ]

            self.assertTrue(
                True,
                client.update_or_create_opa_data(
                    my_policy_list, 'exampledata/accesses'
                ),
            )
            value = {'result': {'hello': False}}

            self.assertEqual(True, client.opa_policy_to_file('test'))

            self.assertEqual(value, client.get_opa_raw_data('play'))

            self.assertTrue(True, client.delete_opa_policy('test'))
            with self.assertRaises(DeletePolicyError):
                client.delete_opa_policy('test')

            with self.assertRaises(DeleteDataError):
                client.delete_opa_data('play')
