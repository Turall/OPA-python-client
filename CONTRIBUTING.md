# Contributing to OPA-python-client

We welcome contributions to [OPA-python-client](https://github.com/Turall/OPA-python-client)

## Issues

Feel free to submit issues and enhancement requests.

[OPA-python-client Issues](https://github.com/Turall/OPA-python-client/issues)

## Contributing

Please refer to each project's style and contribution guidelines for submitting patches and additions. In general, we follow the "fork-and-pull" Git workflow.

1.  **Fork** the repo on GitHub
2.  **Clone** the project to your own machine
3.  **Commit** changes to your own branch
4.  **Push** your work
5.  Submit a **Pull request** so that we can review your changes


## Testing
```sh
$ docker run -it --rm -p 8181:8181 openpolicyagent/opa run --server --addr :8181
$ pytest
```

NOTE: Be sure to merge the latest from "upstream" before making a pull request!
