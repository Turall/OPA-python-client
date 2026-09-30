
# OpaClient - Open Policy Agent Python Client
[![MIT licensed](https://img.shields.io/github/license/Turall/OPA-python-client)](https://raw.githubusercontent.com/Turall/OPA-python-client/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Turall/OPA-python-client.svg)](https://github.com/Turall/OPA-python-client/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Turall/OPA-python-client.svg)](https://github.com/Turall/OPA-python-client/network)
[![GitHub issues](https://img.shields.io/github/issues-raw/Turall/OPA-python-client)](https://github.com/Turall/OPA-python-client/issues)
[![Downloads](https://pepy.tech/badge/opa-python-client)](https://pepy.tech/project/opa-python-client)

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
pip install opa-python-client
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

## Authentication with a Bearer Token

If your OPA server is configured with token-based authentication, pass a `token` and the client will send it as an `Authorization: Bearer <token>` header on every request:

```python
from opa_client.opa import OpaClient

client = OpaClient(host='opa.example.com', token='my-secret-token')
```

This works the same way for `AsyncOpaClient`.

## Waiting for OPA to Become Ready

Useful during container/CI startup, when OPA may not be immediately reachable:

```python
from opa_client.opa import OpaClient

client = OpaClient()
client.wait_for_ready(timeout=10)  # blocks until healthy, or raises ConnectionsError
```

- **Asynchronous**:

```python
await client.wait_for_ready(timeout=10)
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

allow if {
    input.user == "admin"
}
'''

client.update_policy_from_string(policy_content, policy_name)
```

- **Asynchronous**:

```python
await client.update_policy_from_string(policy_content, policy_name)
```

**OPA 1.0+ compatibility:** Policies should use Rego v1 syntax (`allow if { ... }`).
The client accepts legacy v0 policies as well — when uploading to OPA 1.0+, it
automatically upgrades common v0 constructs and retries. Disable this with
`rego_compat=False` on `update_policy_from_string`.

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

#### Partially Update Data (JSON Patch)

You can partially update data already stored in OPA using a [JSON Patch](https://datatracker.ietf.org/doc/html/rfc6902) (RFC 6902) document, instead of replacing the whole document with `update_or_create_data`:

- **Synchronous**:

```python
client.update_or_create_data({"users": {"alice": {"role": "admin"}}}, "acl")

client.patch_data("acl", [
    {"op": "add", "path": "/users/bob", "value": {"role": "user"}},
])
print(client.get_data("acl"))
# {'result': {'users': {'alice': {'role': 'admin'}, 'bob': {'role': 'user'}}}}
```

- **Asynchronous**:

```python
await client.update_or_create_data({"users": {"alice": {"role": "admin"}}}, "acl")

await client.patch_data("acl", [
    {"op": "add", "path": "/users/bob", "value": {"role": "user"}},
])
print(await client.get_data("acl"))
```

### Server Configuration & Metrics

#### Get Server Configuration

Retrieve OPA's active configuration (e.g. to check labels, decision logging, or bundle settings):

- **Synchronous**:

```python
print(client.get_config())
# {'result': {'default_decision': '/system/main', 'labels': {'id': '...', 'version': '0.68.0'}}}
```

- **Asynchronous**:

```python
print(await client.get_config())
```

#### Get Server Metrics

Retrieve Prometheus-formatted performance metrics from OPA:

- **Synchronous**:

```python
print(client.get_metrics())
# '# HELP go_info Information about the Go environment.\n# TYPE go_info gauge\ngo_info{version="go1.23.0"} 1\n...'
```

- **Asynchronous**:

```python
print(await client.get_metrics())
```

#### Get Server Status

Retrieve OPA's bundle activation, discovery, and plugin status (requires the [status plugin](https://www.openpolicyagent.org/docs/latest/monitoring/#status) to be enabled on the server):

- **Synchronous**:

```python
print(client.get_status())
# {'result': {'labels': {...}, 'bundles': {...}, 'plugins': {...}}}
```

- **Asynchronous**:

```python
print(await client.get_status())
```

If the status plugin isn't enabled, OPA itself responds with a 500 and a
`"status plugin not enabled"` message. `get_status()` doesn't hide this behind
a generic connection error — it raises a normal `requests.exceptions.HTTPError`
(sync) or `aiohttp.ClientResponseError` (async), with OPA's real response
still accessible (e.g. `e.response.json()["message"]` on the sync client).

### Policy Evaluation

#### Check Permission (Policy Evaluation)

Evaluate a rule from a known package path. This is the **recommended method** for evaluating OPA decisions.

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

You can pass OPA query parameters (e.g. `explain`, `metrics`, `pretty`, `instrument`) via `query_params`:

```python
print(client.query_rule(
    input_data=check_data,
    package_path="play",
    rule_name="hello",
    query_params={"metrics": True},
))
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

`ad_hoc_query` also accepts `query_params` for `explain`, `metrics`, `pretty`, etc., the same way `query_rule` does.

### Bulk Rule Evaluation

> **Note:** Open-source OPA has no dedicated "batch decision" REST endpoint — that only exists in Styra's discontinued Enterprise OPA fork. `bulk_query_rule` gets you the same practical benefit (evaluating one rule against many inputs in a single HTTP round-trip) by building one ad-hoc query that overrides `input` per item with Rego's `with` keyword, which works against any standard OPA server.

Use `bulk_query_rule` when you need a policy decision for many resources/users at once (e.g. filtering a list by permission) without making one `query_rule` HTTP call per item:

- **Synchronous**:

```python
rego = """
package app.abac

default allow = false

allow {
    input.role == "admin"
}
"""
client.update_policy_from_string(rego, "abac")

# Pass a list for positional results:
result = client.bulk_query_rule(
    [{"role": "admin"}, {"role": "user"}],
    package_path="app.abac",
    rule_name="allow",
)
print(result)  # [True, False]

# Or a dict to get results keyed by your own IDs:
result = client.bulk_query_rule(
    {"alice": {"role": "admin"}, "bob": {"role": "user"}},
    package_path="app.abac",
    rule_name="allow",
)
print(result)  # {'alice': True, 'bob': False}
```

- **Asynchronous**:

```python
result = await client.bulk_query_rule(
    [{"role": "admin"}, {"role": "user"}],
    package_path="app.abac",
    rule_name="allow",
)
print(result)  # [True, False]
```

Notes:
- `package_path` and `rule_name` must be valid Rego identifiers (dot-separated for `package_path`); a `ValueError` is raised otherwise.
- The rule must resolve to a defined value for every input (e.g. via a `default` declaration). If it's undefined for any input, `bulk_query_rule` raises `QueryExecuteError` rather than silently dropping that result.
- An empty `inputs` list/dict short-circuits to `[]`/`{}` without making a request.

### Compile API (Partial Evaluation)

Use `compile_query` to partially evaluate a query against a set of `unknowns`. If the query fully resolves given `input_data`, the result is unconditionally true/false; otherwise OPA returns a residual set of queries (e.g. usable as a filter for a downstream data store).

- **Synchronous**:

```python
policy = """
package authz

default allow = false

allow if {
    input.user.role == "admin"
}
"""
client.update_policy_from_string(policy, "authz")

# Fully resolved: input is fully known, so the query reduces to true.
result = client.compile_query(
    "data.authz.allow == true",
    input_data={"user": {"role": "admin"}},
    unknowns=[],
)
print(result) # {'result': {'queries': [[]]}}

# Partial evaluation: leave input.user.role unknown to get a residual query.
partial = client.compile_query(
    "data.authz.allow == true",
    unknowns=["input.user.role"],
)
print(partial) # {'result': {'queries': [[{'index': 0, 'terms': [...]}]]}}
```

- **Asynchronous**:

```python
await client.update_policy_from_string(policy, "authz")

result = await client.compile_query(
    "data.authz.allow == true",
    input_data={"user": {"role": "admin"}},
    unknowns=[],
)
print(result) # {'result': {'queries': [[]]}}
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
- `patch_data(data_name, patches)`: Partially update data using a JSON Patch (RFC 6902) document.
- `delete_data(data_name)`: Delete data from OPA.
- `query_rule(input_data, package_path, rule_name, query_params)`: Query a specific rule in a package.
- `ad_hoc_query(query, input_data, query_params)`: Run an ad-hoc query.
- `bulk_query_rule(inputs, package_path, rule_name, query_params)`: Evaluate the same rule against many inputs (list or dict) in a single request.
- `compile_query(query, input_data, unknowns, options)`: Partially evaluate a query using the Compile API.
- `get_config()`: Get OPA's active server configuration.
- `get_metrics()`: Get Prometheus-formatted server performance metrics.
- `get_status()`: Get OPA's bundle/discovery/plugin status.
- `wait_for_ready(timeout, interval)`: Block until OPA reports healthy, or raise `ConnectionsError`.

### Asynchronous Client (AsyncOpaClient)

Same as the synchronous client, but all methods are asynchronous and must be awaited.

## Command-Line Interface

Installing the package also installs an `opa-client` CLI for scripting and CI use:

```bash
opa-client --host localhost --port 8181 health
opa-client wait-for-ready --max-wait 10
opa-client list-policies
opa-client put-policy example --file ./example.rego
opa-client get-policy example
opa-client put-data acl --file ./acl.json
opa-client get-data acl
opa-client query-rule play hello --input '{"message": "world"}'
opa-client bulk-query-rule app.abac allow --inputs-json '[{"role": "admin"}, {"role": "user"}]'
opa-client query "data.play.hello == true" --input '{"message": "world"}'
opa-client status
opa-client config
opa-client metrics
```

Use `--ssl` and `--token <token>` for secured servers. Run `opa-client <command> --help` for the full option list of any subcommand.

## Contributing

Contributions are welcome! Feel free to open issues, fork the repo, and submit pull requests.

## License

This project is licensed under the MIT License.
