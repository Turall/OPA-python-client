# -*- coding: utf-8 -*-
"""
Unit tests for the OpaClient.
"""


from unittest import TestCase

from opa_client.errors import DeleteDataError, DeletePolicyError
from opa_client.opa import OpaClient


class TestClient(TestCase):
    def setUp(self):
        """Set up the test  for OpaClient object"""

        self.myclient = OpaClient()

    def tearDown(self):
        """Close the connection to the OPA server by deleting the client"""
        del self.myclient

    def test_client(self):
        """Set up the test for OpaClient object"""

        client = OpaClient('localhost', 8181, 'v1')
        self.assertEqual('http://localhost:8181/v1', client._root_url)

        client = OpaClient('localhost', 8181, 'v1')
        self.assertEqual('http://localhost:8181/v1', client._root_url)

        self.assertFalse(False, self.myclient._secure)
        self.assertEqual('http://', self.myclient._schema)
        self.assertEqual('v1', self.myclient._version)
        self.assertEqual('localhost', self.myclient._host)
        self.assertEqual(8181, self.myclient._port)

    def test_connection_to_opa(self):
        self.assertEqual("Yes I'm here :)", self.myclient.check_connection())
    
    def test_functions(self):
        new_policy = """
            package test.policy

            import data.test.acl
            import input

            default allow = false

            allow {
                access := acl[input.user]
                access[_] == input.access
            }

            authorized_users[user] {
                access := acl[user]
                access[_] == input.access
            }
        """

        _dict = {
            'test': {
                'path': ['http://localhost:8181/v1/data/test/policy'],
                'rules': [
                    'http://localhost:8181/v1/data/test/policy/allow',
                    'http://localhost:8181/v1/data/test/policy/authorized_users'
                ],
            }
        }

        my_policy_list = {
            "alice": ["read","write"],
            "bob": ["read"]
        }

        self.assertEqual(list(), self.myclient.get_policies_list())
        self.assertEqual(dict(), self.myclient.get_policies_info())
        self.assertEqual(True, self.myclient.update_opa_policy_fromstring(new_policy, 'test'))
        self.assertEqual(['test'], self.myclient.get_policies_list())
        
        policy_info = self.myclient.get_policies_info()
        self.assertEqual(_dict['test']['path'], policy_info['test']['path'])
        for rule in _dict['test']['rules']:
            self.assertIn(rule, policy_info['test']['rules'])

        self.assertTrue(
            True, self.myclient.update_or_create_opa_data(my_policy_list, 'test/acl')
        )

        self.assertEqual(True, self.myclient.opa_policy_to_file('test'))

        value = {'result': {'acl': {'alice': ['read', 'write'], 'bob': ['read']}, 'policy': {'allow': False, 'authorized_users': []}}}
        self.assertEqual(value, self.myclient.get_opa_raw_data('test'))

        _input_a = {"input": {"user": "alice", "access": "write"}}
        _input_b = {"input": {"access": "read"}}
        value_a = {"result": True}
        value_b = {"result": ["alice", "bob"]}
        self.assertEqual(value_a, self.myclient.check_permission(input_data=_input_a, policy_name="test", rule_name="allow"))
        self.assertEqual(value_b, self.myclient.check_permission(input_data=_input_b, policy_name="test", rule_name="authorized_users"))

        self.assertTrue(True, self.myclient.delete_opa_policy('test'))
        with self.assertRaises(DeletePolicyError):
            self.myclient.delete_opa_policy('test')

        self.assertTrue(True, self.myclient.delete_opa_data('test/acl'))
        with self.assertRaises(DeleteDataError):
            self.myclient.delete_opa_data('test/acl')
