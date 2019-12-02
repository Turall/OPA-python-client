# Python Open Policy Agent (OPA) Client 

See offical documentation page [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/)

```
>>> from opa_client.opa import OpaClient
>>> client = OpaClient() # default host='localhost', port=8181, version='v1'
>>> print(client.check_connection())
True
>>>  test_policy = """
...     package play
... 
...     import data.testapi.testdata
... 
...     default hello = false
... 
...     hello {
...         m := input.message
...         testdata[i] == "world"
...     }
... """

>>> print(client.update_opa_policy_fromstring(test_policy, "testpolicy"))
True
>>> print(client.get_policies_list())
['testpolicy']
>>> data = ["world", "hello"]
>>> print(client.update_or_create_opa_data(data, "testapi/testdata"))
True
>>> check_data = {"input": {"message": "hello"}}
>>> print(client.check_permission(input_data=check_data, policy_name="testpolicy", rule_name="hello"))
{'result': True}
```



### OPA-python-client  supports Python >= 3.6
