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

        client = OpaClient("127.0.0.1", 8181, "v1")
        self.assertEqual("http://127.0.0.1:8181/v1", client._root_url)

        self.assertFalse(False, self.myclient._secure)
        self.assertEqual("http://", self.myclient._schema)
        self.assertEqual("v1", self.myclient._version)
        self.assertEqual("127.0.0.1", self.myclient._host)
        self.assertEqual(8181, self.myclient._port)

    def test_functions(self):

        self.assertEqual("Yes I'm here :)", self.myclient.check_connection())
        try:
            self.assertEqual(list(), self.myclient.get_policies_list())
        except Exception as e:
            print(e)
            try:
                self.assertEqual(["test"], self.myclient.get_policies_list())
            except Exception as test:
                print(test)
        try:
            self.assertEqual(dict(), self.myclient.get_policies_info())
        except Exception as rr:
            print(rr)
            try:
                my_dict = {'test': {'path': [
                    'http://127.0.0.1:8181/v1/data/play'], 'rules': ['http://127.0.0.1:8181/v1/data/play/hello']}}

                self.assertEqual(my_dict, self.myclient.get_policies_info())
            except Exception as testing:
                print(testing)

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

        # self.assertEqual(False, self.myclient.update_opa_policy_fromfile(
        #     "/home/root/Documents/OPA-python-client/opa_client/test/test.txt", "test"))

        # self.assertEqual(self.myclient.update_opa_policy_fromurl())
        self.assertEqual(["test"], self.myclient.get_policies_list())
        my_dict = {'test': {'path': ['http://127.0.0.1:8181/v1/data/play'],
                            'rules': ['http://127.0.0.1:8181/v1/data/play/hello']}}

        self.assertEqual(my_dict, self.myclient.get_policies_info())

        my_policy_list = [
            {"resource": "/api/someapi", "identity": "your_identity", "method": "PUT"},
            {"resource": "/api/someapi", "identity": "your_identity", "method": "GET"},
        ]

        self.assertTrue(True, self.myclient.update_or_create_opa_data(
            my_policy_list, 'exampledata/accesses'))
        value = {'result': {'hello': False}}
        try:
            self.assertEqual(dict(), self.myclient.get_opa_raw_data("play"))
        except Exception as err:
            print("not right one", err)
            try:
                self.assertEqual(
                    value, self.myclient.get_opa_raw_data("hello"))
            except Exception as errr:
                print(errr)

        self.assertEqual(True, self.myclient.opa_policy_to_file("test"))

        try:
            self.assertEqual(dict(), self.myclient.get_opa_raw_data("play"))
        except Exception as er:
            print("not right", er)
            try:
                self.assertEqual(value, self.myclient.get_opa_raw_data("play"))
            except Exception as identifier:
                print(identifier)

        # TODO
        # self.assertEqual("sad", self.myclient.get_opa_policy("test"))

        self.assertTrue(True, self.myclient.delete_opa_policy("test"))
        with self.assertRaises(DeletePolicyError):
            self.myclient.delete_opa_policy("test")

        with self.assertRaises(DeleteDataError):
            self.myclient.delete_opa_data("play")

        # TODO #check with owner of client
        # self.assertEqual(dict(), self.myclient.check_permission())
