
# OpaClient - Open Policy Agent Python Client

OpaClient is a Python client library designed to interact with the [Open Policy Agent (OPA)](https://www.openpolicyagent.org/). It supports both **synchronous** and **asynchronous** requests, making it easy to manage policies, data, and evaluate rules in OPA servers.

## Features

- **Manage Policies**: Create, update, retrieve, and delete policies.
- **Manage Data**: Create, update, retrieve, and delete data in OPA.
- **Evaluate Policies**: Use input data to evaluate policies and return decisions.
- **Synchronous & Asynchronous**: Choose between sync or async operations to suit your application.
- **SSL/TLS Support**: Communicate securely with SSL/TLS, including client certificates.
- **Customizable**: Use custom headers, timeouts, and other configurations.

## Installation

You can install the OpaClient package via `pip`:

```bash
pip install OPA-python-client
```

## Quick Start

### Synchronous Client Example

```python
from opa_client.opa import OpaClient

# Initialize the OPA client
client = OpaClient(host='localhost', port=8181)

# Check the OPA server connection
try:
    print(client.check_connection())  # True
finally:
    client.close_connection()
```
or with client factory

```python
from opa_client import create_opa_client

client = create_opa_client(host="localhost", port=8181)

```

Check OPA healthy. If you want check bundels or plugins, add query params for this.

```python
from opa_client.opa import OpaClient

client = OpaClient()

print(client.check_health()) # response is  True or False
print(client.check_health({"bundle": True})) # response is  True or False
# If your diagnostic url different than default url, you can provide it.
print(client.check_health(diagnostic_url="http://localhost:8282/health"))  # response is  True or False
print(client.check_health(query={"bundle": True}, diagnostic_url="http://localhost:8282/health"))  # response is  True or False
```

### Asynchronous Client Example

```python
import asyncio
from opa_client.opa_async import AsyncOpaClient

async def main():
    async with AsyncOpaClient(host='localhost', port=8181) as client:
        result = await client.check_connection()
        print(result)

# Run the async main function
asyncio.run(main())
```
or with clien factory

```python
from opa_client import create_opa_client

client = create_opa_client(async_mode=True,host="localhost", port=8181)

```

## Secure Connection with SSL/TLS

You can use OpaClient with secure SSL/TLS connections, including mutual TLS (mTLS), by providing a client certificate and key.

### Synchronous Client with SSL/TLS

```python
from opa_client.opa import OpaClient

# Path to your certificate and private key
cert_path = '/path/to/client_cert.pem'
key_path = '/path/to/client_key.pem'

# Initialize the OPA client with SSL/TLS
client = OpaClient(
    host='your-opa-server.com',
    port=443,  # Typically for HTTPS
    ssl=True,
    cert=(cert_path, key_path)  # Provide the certificate and key as a tuple
)

# Check the OPA server connection
try:
    result = client.check_connection()
    print(result)
finally:
    client.close_connection()
```

### Asynchronous Client with SSL/TLS

```python
import asyncio
from opa_client.opa_async import AsyncOpaClient

# Path to your certificate and private key
cert_path = '/path/to/client_cert.pem'
key_path = '/path/to/client_key.pem'

async def main():
    # Initialize the OPA client with SSL/TLS
    async with AsyncOpaClient(
        host='your-opa-server.com',
        port=443,  # Typically for HTTPS
        ssl=True,
        cert=(cert_path, key_path)  # Provide the certificate and key as a tuple
    ) as client:
        # Check the OPA server connection
        result = await client.check_connection()
        print(result)

# Run the async main function
asyncio.run(main())
```

## Usage

### Policy Management

#### Create or Update a Policy

You can create or update a policy using the following syntax:

- **Synchronous**:

```python
policy_name = 'example_policy'
policy_content = '''
package example

default allow = false

allow {
    input.user == "admin"
}
'''

client.update_policy_from_string(policy_content, policy_name)
```

- **Asynchronous**:

```python
await client.update_policy_from_string(policy_content, policy_name)
```

Or from url:

- **Synchronous**:

```python
policy_name = 'example_policy'

client.update_policy_from_url("http://opapolicyurlexample.test/example.rego", policy_name) 

```

- **Asynchronous**:

```python
await client.update_policy_from_url("http://opapolicyurlexample.test/example.rego", policy_name) 
```

Update policy from rego file

```python
client.update_opa_policy_fromfile("/your/path/filename.rego", endpoint="fromfile") # response is True

client.get_policies_list()
```

- **Asynchronous**:
```python
await client.update_opa_policy_fromfile("/your/path/filename.rego", endpoint="fromfile") # response is True

await client.get_policies_list()
```

#### Retrieve a Policy

After creating a policy, you can retrieve it:

- **Synchronous**:

```python
policy = client.get_policy('example_policy')
print(policy)
# or
policies = client.get_policies_list()
print(policies)
```

- **Asynchronous**:

```python
policy = await client.get_policy('example_policy')
print(policy)

# or
policies = await client.get_policies_list()
print(policies)
```

Save policy to file from OPA service

```python
client.policy_to_file(policy_name="example_policy",path="/your/path",filename="example.rego")

```

- **Asynchronous**:

```python

await client.policy_to_file(policy_name="example_policy",path="/your/path",filename="example.rego")

```

Information about policy path and rules

```python

print(client.get_policies_info())
#{'example_policy': {'path': 'http://localhost:8181/v1/data/example', 'rules': ['http://localhost:8181/v1/data/example/allow']}}

```
- **Asynchronous**:


```python

print(await client.get_policies_info())
#{'example_policy': {'path': 'http://localhost:8181/v1/data/example', 'rules': ['http://localhost:8181/v1/data/example/allow']}}

```

#### Delete a Policy

You can delete a policy by name:

- **Synchronous**:

```python
client.delete_policy('example_policy')
```

- **Asynchronous**:

```python
await client.delete_policy('example_policy')
```

### Data Management

#### Create or Update Data

You can upload arbitrary data to OPA:

- **Synchronous**:

```python
data_name = 'users'
data_content = {
    "users": [
        {"name": "alice", "role": "admin"},
        {"name": "bob", "role": "user"}
    ]
}

client.update_or_create_data(data_content, data_name)
```

- **Asynchronous**:

```python
await client.update_or_create_data(data_content, data_name)
```

#### Retrieve Data

You can fetch the data stored in OPA:

- **Synchronous**:

```python
data = client.get_data('users')
print(data)
# You can use query params for additional info
# provenance - If parameter is true, response will include build/version info in addition to the result.
# metrics - Return query performance metrics in addition to result 
data = client.get_data('users',query_params={"provenance": True})
print(data) # {'provenance': {'version': '0.68.0', 'build_commit': 'db53d77c482676fadd53bc67a10cf75b3d0ce00b', 'build_timestamp': '2024-08-29T15:23:19Z', 'build_hostname': '3aae2b82a15f'}, 'result': {'users': [{'name': 'alice', 'role': 'admin'}, {'name': 'bob', 'role': 'user'}]}}


data = client.get_data('users',query_params={"metrics": True})
print(data) # {'metrics': {'counter_server_query_cache_hit': 0, 'timer_rego_external_resolve_ns': 7875, 'timer_rego_input_parse_ns': 875, 'timer_rego_query_compile_ns': 501083, 'timer_rego_query_eval_ns': 50250, 'timer_rego_query_parse_ns': 199917, 'timer_server_handler_ns': 1031291}, 'result': {'users': [{'name': 'alice', 'role': 'admin'}, {'name': 'bob', 'role': 'user'}]}}


```

- **Asynchronous**:

```python
data = await client.get_data('users')
print(data)
```

#### Delete Data

To delete data from OPA:

- **Synchronous**:

```python
client.delete_data('users')
```

- **Asynchronous**:

```python
await client.delete_data('users')
```

### Policy Evaluation

#### Check Permission (Policy Evaluation)

You can evaluate policies with input data using `check_permission`.

- **Synchronous**:

```python
input_data = {"user": "admin"}
policy_name = 'example_policy'
rule_name = 'allow'

result = client.check_permission(input_data, policy_name, rule_name)
print(result)
```

- **Asynchronous**:

```python
input_data = {"user": "admin"}
policy_name = 'example_policy'
rule_name = 'allow'

result = await client.check_permission(input_data, policy_name, rule_name)
print(result)
```

Queries a package rule with the given input data

```python

rego = """
package play

default hello = false

hello {
    m := input.message
    m == "world"
}
"""

check_data = {"message": "world"}

client.update_policy_from_string(rego, "test")
print(client.query_rule(input_data=check_data, package_path="play", rule_name="hello")) # {'result': True}

```

- **Asynchronous**:

```python

rego = """
package play

default hello = false

hello {
    m := input.message
    m == "world"
}
"""

check_data = {"message": "world"}

await client.update_policy_from_string(rego, "test")
print(await client.query_rule(input_data=check_data, package_path="play", rule_name="hello")) # {'result': True}

```

### Ad-hoc Queries

Execute ad-hoc queries directly:

- **Synchronous**:

```python
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
input_data = {"user": "admin"}
client.update_or_create_data(data, "userinfo")

result = client.ad_hoc_query(query="data.userinfo.user_roles[name]")
print(result) # {'result': [{'name': 'alice'}, {'name': 'bob'}, {'name': 'eve'}]}
```

- **Asynchronous**:

```python
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
input_data = {"user": "admin"}
await client.update_or_create_data(data, "userinfo")

result = await client.ad_hoc_query(query="data.userinfo.user_roles[name]")
print(result) # {'result': [{'name': 'alice'}, {'name': 'bob'}, {'name': 'eve'}]}
```

## API Reference

### Synchronous Client (OpaClient)

- `check_connection()`: Verify connection to OPA server.
- `get_policies_list()`: Get a list of all policies.
- `get_policies_info()`: Returns information about each policy, including policy path and policy rules.
- `get_policy(policy_name)`: Fetch a specific policy.
- `policy_to_file(policy_name)`: Save an OPA policy to a file..
- `update_policy_from_string(policy_content, policy_name)`: Upload or update a policy using its string content.
- `update_policy_from_url(url,endpoint)`: Update OPA policy by fetching it from a URL.
- `update_policy_from_file(filepath,endpoint)`: Update OPA policy using a policy file.
- `delete_policy(policy_name)`: Delete a specific policy.
- `update_or_create_data(data_content, data_name)`: Create or update data in OPA.
- `get_data(data_name)`: Retrieve data from OPA.
- `delete_data(data_name)`: Delete data from OPA.
- `check_permission(input_data, policy_name, rule_name)`: Evaluate a policy using input data.
- `query_rule(input_data, package_path, rule_name)`: Query a specific rule in a package.
- `ad_hoc_query(query, input_data)`: Run an ad-hoc query.

### Asynchronous Client (AsyncOpaClient)

Same as the synchronous client, but all methods are asynchronous and must be awaited.

## Contributing

Contributions are welcome! Feel free to open issues, fork the repo, and submit pull requests.

## License

This project is licensed under the MIT License.
