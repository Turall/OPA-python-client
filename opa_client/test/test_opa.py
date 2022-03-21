# -*- coding: utf-8 -*-
"""
Unit tests for the OpaClient.

"""


from unittest import TestCase
from opa_client.opa import OpaClient
from opa_client.OpaExceptions import DeleteDataError, DeletePolicyError


class TestClient(TestCase):

    def setUp(self):
        """Set up the test  for OpaClient object"""

        self.myclient = OpaClient()

    def tearDown(self):
        """ Close the connection to the OPA server by deleting the client"""
        del self.myclient

    def test_client(self):
        """Set up the test  for OpaClient object"""

        client = OpaClient("localhost", 8181, "v1")
        self.assertEqual("http://localhost:8181/v1", client._root_url)

        client = OpaClient("localhost", 8181, "v1")
        self.assertEqual("http://localhost:8181/v1", client._root_url)

        self.assertFalse(False, self.myclient._secure)
        self.assertEqual("http://", self.myclient._schema)
        self.assertEqual("v1", self.myclient._version)
        self.assertEqual("localhost", self.myclient._host)
        self.assertEqual(8181, self.myclient._port)

    def test_functions(self):

        self.assertEqual("Yes I'm here :)", self.myclient.check_connection())
        self.assertEqual(list(), self.myclient.get_policies_list())
            
        self.assertEqual(dict(), self.myclient.get_policies_info())
     
        # _dict = {'test': {'path': [
        #     'http://localhost:8181/v1/data/play'], 'rules': ['http://localhost:8181/v1/data/play/hello']}}

        # self.assertEqual(_dict, self.myclient.get_policies_info())
    
        new_policy = '''
            package play

            default hello = false

            hello {
                m := input.message
                m == "world"
            }
        '''
        self.assertEqual(
            True, self.myclient.update_opa_policy_fromstring(new_policy, "test"))

        self.assertEqual(["test"], self.myclient.get_policies_list())
        _dict = {'test': {'path': ['http://localhost:8181/v1/data/play'],
                            'rules': ['http://localhost:8181/v1/data/play/hello']}}

        self.assertEqual(_dict, self.myclient.get_policies_info())

        my_policy_list = [
            {"resource": "/api/someapi", "identity": "your_identity", "method": "PUT"},
            {"resource": "/api/someapi", "identity": "your_identity", "method": "GET"},
        ]

        self.assertTrue(True, self.myclient.update_or_create_opa_data(
            my_policy_list, 'exampledata/accesses'))
        value = {'result': {'hello': False}}
          
        self.assertEqual(True, self.myclient.opa_policy_to_file("test"))
       
        self.assertEqual(value, self.myclient.get_opa_raw_data("play"))
    
        self.assertTrue(True, self.myclient.delete_opa_policy("test"))
        with self.assertRaises(DeletePolicyError):
            self.myclient.delete_opa_policy("test")

        with self.assertRaises(DeleteDataError):
            self.myclient.delete_opa_data("play")
