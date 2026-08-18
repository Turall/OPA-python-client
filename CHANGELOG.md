# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- `OpaClient.compile_query` / `AsyncOpaClient.compile_query` — support for OPA's
  Compile API (`POST /v1/compile`), enabling partial evaluation of a query against
  a chosen set of unknowns (e.g. compiling a policy into a residual filter for
  use with `data.reports`-style authorization-as-filter patterns).
- `AsyncOpaClient` now retries requests on connection errors and on `500`/`502`/`504`
  responses, honoring the `retries` option the same way the sync client's
  `urllib3.Retry`-backed session already did.

### Changed

- `AsyncOpaClient` now inherits from `BaseClient`, removing ~70 lines of duplicated
  property boilerplate and sharing the Rego-compat helper methods with the sync client.

### Fixed

- `AsyncOpaClient.update_or_create_data` raised `AttributeError` instead of
  `RegoParseError` on a `400` response, because `AsyncOpaClient` did not inherit
  `BaseClient` and therefore lacked `_raise_rego_parse_error`.

- `AsyncOpaClient.check_permission` sent requests to a duplicated `/v1/data/data/...`
  endpoint (the AST-derived package path already includes a leading `data` segment),
  causing it to silently return an empty result instead of the permission decision.
- `AsyncOpaClient` raised `TypeError` instead of the intended exception in several
  error paths (`update_policy_from_file`, `policy_to_file`, `check_permission`) because
  `FileError`, `PolicyNotFoundError`, `PathNotFoundError`, and `CheckPermissionError`
  were called with only one of their two required constructor arguments.
- `OpaClient.ad_hoc_query` and `AsyncOpaClient.ad_hoc_query` now send the ad hoc query
  and `input` document in the JSON body of a `POST /v1/query` request, matching OPA's
  REST API contract, instead of mixing a GET-style `q` query parameter with an
  unrelated JSON body.

## [2.0.5]

- Add OPA 1.0 Rego compatibility with automatic v0 policy upgrade.
- Update dependencies.

## [2.0.4]

- Fix `BaseClient` not respecting `retries` and `timeout` configuration.

## [2.0.3]

- Merge fixes from issue #31 and #32.

## [2.0.2]

- Add expressions for raised errors.

## [2.0.0]

- Major rewrite (V2): unified sync/async client interfaces, updated dependencies.

[Unreleased]: https://github.com/Turall/OPA-python-client/compare/v2.0.5...HEAD
[2.0.5]: https://github.com/Turall/OPA-python-client/compare/v2.0.4...v2.0.5
[2.0.4]: https://github.com/Turall/OPA-python-client/compare/v2.0.3...v2.0.4
[2.0.3]: https://github.com/Turall/OPA-python-client/compare/v2.0.2...v2.0.3
[2.0.2]: https://github.com/Turall/OPA-python-client/compare/v2.0.0...v2.0.2
[2.0.0]: https://github.com/Turall/OPA-python-client/releases/tag/v2.0.0
