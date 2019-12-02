# Python Open Policy Agent (OPA) Client 

See offical documentation page [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/)

```python
>>> from opa_client.opa import OpaClient
>>> client = OpaClient() # default host='localhost', port=8181, version='v1'
>>> client.check_connection()
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
...         testdata[i] == m
...     }
... """

>>> client.update_opa_policy_fromstring(test_policy, "testpolicy")
True
>>> client.get_policies_list()
['testpolicy']
>>> data = ["world", "hello"]
>>> client.update_or_create_opa_data(data, "testapi/testdata")
True
>>> check_data = {"input": {"message": "hello"}}
>>> client.check_permission(input_data=check_data, policy_name="testpolicy", rule_name="hello")
{'result': True}
```

### Update policy from rego file ###

```python
from opa_client.opa import OpaClient

client = OpaClient() # default host='localhost', port=8181, version='v1'

client.update_opa_policy_fromfile("/your/path/filename.rego", endpoint="fromfile") # response is True

client.get_policies_list() # response is ["fromfile"]

```


### Update policy from URL ###

```python

from opa_client.opa import OpaClient

client = OpaClient() # default host='localhost', port=8181, version='v1'


client.update_opa_policy_fromurl("http://opapolicyurlexample.test/example.rego", endpoint="fromurl") # response is True

client.get_policies_list() # response is ["fromfile","fromurl"]

```


### Delete policy ###


```python


from opa_client.opa import OpaClient

client = OpaClient() # default host='localhost', port=8181, version='v1'

client.delete_opa_policy("fromfile") # response is True

client.get_policies_list() # response is [fromurl"]

```

### Get raw data from OPA service ###


```python


from opa_client.opa import OpaClient

client = OpaClient() # default host='localhost', port=8181, version='v1'

print(client.get_opa_raw_data("testapi/testdata"))  # response is {'result': ['world', 'hello']}

```

### Save policy to file from OPA service ###


```python


from opa_client.opa import OpaClient

client = OpaClient() # default host='localhost', port=8181, version='v1'

client.opa_policy_to_file(policy_name="fromurl",path="/your/path",filename="example.rego")  # response is True


```

### Delete data from OPA service ###


```python


from opa_client.opa import OpaClient

client = OpaClient() # default host='localhost', port=8181, version='v1'

client.delete_opa_data("testapi")  # response is True


```


### Information about policy path and rules ###


```python


from opa_client.opa import OpaClient

client = OpaClient() # default host='localhost', port=8181, version='v1'

client.get_policies_info()

# response is {'testpolicy': {'path': ['http://your-opa-service/v1/data/play'], 'rules': ['http://your-opa-service/v1/data/play/hello']}

```


### Check permissions ###


```python


from opa_client.opa import OpaClient

client = OpaClient() # default host='localhost', port=8181, version='v1'

permission_you_want_check = {"input": {"message": "hello"}}
client.check_permission(input_data=permission_you_want_check, policy_name="testpolicy", rule_name="hello")

# response is {'result': True}

```




### OPA-python-client  supports Python >= 3.6
