# Python Open Policy Agent (OPA) Client 

[![MIT licensed](https://img.shields.io/github/license/Turall/OPA-python-client)](https://raw.githubusercontent.com/Turall/OPA-python-client/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Turall/OPA-python-client.svg)](https://github.com/Turall/OPA-python-client/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Turall/OPA-python-client.svg)](https://github.com/Turall/OPA-python-client/network)
[![GitHub issues](https://img.shields.io/github/issues-raw/Turall/OPA-python-client)](https://github.com/Turall/OPA-python-client/issues)
[![Downloads](https://pepy.tech/badge/opa-python-client)](https://pepy.tech/project/opa-python-client)


See offical documentation page [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/)


### Installation ###

```sh
$ pip install OPA-python-client
```

Alternatively, if you prefer to use `poetry` for package dependencies:

```bash
$ poetry shell
$ poetry add OPA-python-client
```



## Usage Examples 

```python
>>> from opa_client.opa import OpaClient
>>> client = OpaClient() # default host='localhost', port=8181, version='v1'
>>> client.check_connection()
'Yes I"m here :)'
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


### Connection to OPA service

```python
from opa_client.opa import OpaClient

client = OpaClient() # default host='localhost', port=8181, version='v1'

client.check_connection() # response is  Yes I'm here :)

# Ensure the connection is closed correctly by deleting the client
del client
```


### Connection to OPA service with SSL

```python
from opa_client.opa import OpaClient


client = OpaClient(
    host="https://192.168.99.100",
    port=8181,
    version="v1",
    ssl=True,
    cert="/your/certificate/file/path/mycert.crt",
)

client.check_connection() # response is  Yes I'm here :)

del client
```


### Update policy from rego file

```python
from opa_client.opa import OpaClient

client = OpaClient() 

client.update_opa_policy_fromfile("/your/path/filename.rego", endpoint="fromfile") # response is True

client.get_policies_list() # response is ["fromfile"]

del client
```


### Update policy from URL

```python
from opa_client.opa import OpaClient

client = OpaClient() 


client.update_opa_policy_fromurl("http://opapolicyurlexample.test/example.rego", endpoint="fromurl") # response is True

client.get_policies_list() # response is ["fromfile","fromurl"]

del client
```


### Delete policy


```python
from opa_client.opa import OpaClient

client = OpaClient() 

client.delete_opa_policy("fromfile") # response is True

client.get_policies_list() # response is [] 

del client
```

### Get raw data from OPA service


```python
from opa_client.opa import OpaClient

client = OpaClient() 

print(client.get_opa_raw_data("testapi/testdata"))  # response is {'result': ['world', 'hello']}

# You can use query params for additional info
# provenance - If parameter is true, response will include build/version info in addition to the result.
# metrics - Return query performance metrics in addition to result 

print(client.get_opa_raw_data("userinfo",query_params={"provenance": True})) 
# response is {'provenance': {'version': '0.25.2', 'build_commit': '4c6e524', 'build_timestamp': '2020-12-08T16:56:55Z', 'build_hostname': '3bb58334a5a9'}, 'result': {'user_roles': {'alice': ['admin'], 'bob': ['employee', 'billing'], 'eve': ['customer']}}}

print(client.get_opa_raw_data("userinfo",query_params={"metrics": True})) 

# response is {'metrics': {'counter_server_query_cache_hit': 0, 'timer_rego_external_resolve_ns': 231, 'timer_rego_input_parse_ns': 381, 'timer_rego_query_compile_ns': 40173, 'timer_rego_query_eval_ns': 12674, 'timer_rego_query_parse_ns': 5692, 'timer_server_handler_ns': 83490}, 'result': {'user_roles': {'alice': ['admin'], 'bob': ['employee', 'billing'], 'eve': ['customer']}}}

del client
```


### Save policy to file from OPA service


```python
from opa_client.opa import OpaClient

client = OpaClient() 

client.opa_policy_to_file(policy_name="fromurl",path="/your/path",filename="example.rego")  # response is True

del client
```


### Delete data from OPA service


```python
from opa_client.opa import OpaClient

client = OpaClient() 

client.delete_opa_data("testapi")  # response is True

del client
```


### Information about policy path and rules


```python
from opa_client.opa import OpaClient

client = OpaClient() 

client.get_policies_info()

# response is {'testpolicy': {'path': ['http://your-opa-service/v1/data/play'], 'rules': ['http://your-opa-service/v1/data/play/hello']}

del client
```


### Check permissions


```python
from opa_client.opa import OpaClient

client = OpaClient() 

permission_you_want_check = {"input": {"message": "hello"}}
client.check_permission(input_data=permission_you_want_check, policy_name="testpolicy", rule_name="hello")

# response is {'result': True}

# You can use query params for additional info
# provenance - If parameter is true, response will include build/version info in addition to the result.
# metrics - Return query performance metrics in addition to result 

del client
```

### Queries a package rule with the given input data

```python
from opa_client.opa import OpaClient

client = OpaClient()

rego = """
package play

default hello = false

hello {
    m := input.message
    m == "world"
}
"""

check_data = {"message": "world"}
client.check_policy_rule(input_data=check_data, package_path="play", rule_name="hello") # response {'result': True}
```

### Execute an Ad-hoc Query

```python
from opa_client.opa import OpaClient

client = OpaClient()

print(client.ad_hoc_query(query_params={"q": "data.userinfo.user_roles[name]"})) # response is {}

data = {
    "user_roles": {
        "alice": [
            "admin"
        ],
        "bob": [
            "employee",
            "billing"
        ],
        "eve": [
            "customer"
        ]
    }
}

print(client.update_or_create_opa_data(data, "userinfo")) # response is True

# execute query 
print(client.ad_hoc_query(query_params={"q": "data.userinfo.user_roles[name]"})) 
# response is {'result': [{'name': 'eve'}, {'name': 'alice'}, {'name': 'bob'}]}

#you can send body request
print(client.ad_hoc_query(body={"query": "data.userinfo.user_roles[name] "})) 
# response is {'result': [{'name': 'eve'}, {'name': 'alice'}, {'name': 'bob'}]}
```

### Check OPA healthy. If you want check bundels or plugins, add query params for this.

```python
from opa_client.opa import OpaClient

client = OpaClient()

print(client.check_health()) # response is  True or False
print(client.check_health({"bundle": True})) # response is  True or False
# If your diagnostic url different than default url, you can provide it.
print(client.check_health(diagnostic_url="http://localhost:8282/health"))  # response is  True or False
print(client.check_health(query={"bundle": True}, diagnostic_url="http://localhost:8282/health"))  # response is  True or False
```


# Contributing

Fell free to open issue and send pull request.

Thanks To [Contributors](https://github.com/Turall/OPA-python-client/graphs/contributors).
Contributions of any kind are welcome!

Before you start please read [CONTRIBUTING](https://github.com/Turall/OPA-python-client/blob/master/CONTRIBUTING.md)
