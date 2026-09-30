"""Command-line interface for the OPA Python client."""

import argparse
import json
import sys

from .errors import ConnectionsError
from .opa import OpaClient


def _load_json(value: str) -> dict:
	return json.loads(value)


def _print(result) -> None:
	if isinstance(result, str):
		print(result)
	else:
		print(json.dumps(result, indent=2))


def _build_client(args: argparse.Namespace) -> OpaClient:
	return OpaClient(
		host=args.host,
		port=args.port,
		ssl=args.ssl,
		token=args.token,
		timeout=args.timeout,
	)


def _cmd_list_policies(client, args):
	_print(client.get_policies_list())


def _cmd_get_policy(client, args):
	_print(client.get_policy(args.name))


def _cmd_put_policy(client, args):
	_print(client.update_policy_from_file(args.file, args.name))


def _cmd_delete_policy(client, args):
	_print(client.delete_policy(args.name))


def _cmd_get_data(client, args):
	_print(client.get_data(args.path))


def _cmd_put_data(client, args):
	if args.file:
		with open(args.file, "r", encoding="utf-8") as file:
			data = json.load(file)
	else:
		data = _load_json(args.json)
	_print(client.update_or_create_data(data, args.path))


def _cmd_delete_data(client, args):
	_print(client.delete_data(args.path))


def _cmd_query(client, args):
	input_data = _load_json(args.input) if args.input else None
	_print(client.ad_hoc_query(args.query, input_data=input_data))


def _cmd_query_rule(client, args):
	input_data = _load_json(args.input) if args.input else {}
	_print(client.query_rule(input_data, args.package_path, args.rule_name))


def _cmd_bulk_query_rule(client, args):
	if args.inputs_file:
		with open(args.inputs_file, "r", encoding="utf-8") as file:
			inputs = json.load(file)
	else:
		inputs = _load_json(args.inputs_json)
	_print(
		client.bulk_query_rule(inputs, args.package_path, args.rule_name)
	)


def _cmd_health(client, args):
	_print(client.check_health())


def _cmd_status(client, args):
	_print(client.get_status())


def _cmd_config(client, args):
	_print(client.get_config())


def _cmd_metrics(client, args):
	_print(client.get_metrics())


def _cmd_wait_for_ready(client, args):
	_print(client.wait_for_ready(timeout=args.max_wait))


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		prog="opa-client",
		description="Command-line interface for the OPA Python client.",
	)
	parser.add_argument("--host", default="localhost")
	parser.add_argument("--port", type=int, default=8181)
	parser.add_argument("--ssl", action="store_true")
	parser.add_argument(
		"--token", default=None, help="Bearer token for authentication"
	)
	parser.add_argument(
		"--timeout", type=float, default=1.5, help="Request timeout in seconds"
	)

	subparsers = parser.add_subparsers(dest="command", required=True)

	list_policies = subparsers.add_parser(
		"list-policies", help="List all policy IDs"
	)
	list_policies.set_defaults(func=_cmd_list_policies)

	get_policy = subparsers.add_parser("get-policy", help="Fetch a policy")
	get_policy.add_argument("name")
	get_policy.set_defaults(func=_cmd_get_policy)

	put_policy = subparsers.add_parser(
		"put-policy", help="Create or update a policy from a .rego file"
	)
	put_policy.add_argument("name")
	put_policy.add_argument("--file", required=True, help="Path to .rego file")
	put_policy.set_defaults(func=_cmd_put_policy)

	delete_policy = subparsers.add_parser(
		"delete-policy", help="Delete a policy"
	)
	delete_policy.add_argument("name")
	delete_policy.set_defaults(func=_cmd_delete_policy)

	get_data = subparsers.add_parser("get-data", help="Fetch data")
	get_data.add_argument("path", nargs="?", default="")
	get_data.set_defaults(func=_cmd_get_data)

	put_data = subparsers.add_parser("put-data", help="Create or update data")
	put_data.add_argument("path")
	data_source = put_data.add_mutually_exclusive_group(required=True)
	data_source.add_argument("--file", help="Path to a JSON file")
	data_source.add_argument("--json", help="Inline JSON string")
	put_data.set_defaults(func=_cmd_put_data)

	delete_data = subparsers.add_parser("delete-data", help="Delete data")
	delete_data.add_argument("path")
	delete_data.set_defaults(func=_cmd_delete_data)

	query = subparsers.add_parser("query", help="Run an ad-hoc query")
	query.add_argument("query")
	query.add_argument("--input", help="Inline JSON input document")
	query.set_defaults(func=_cmd_query)

	query_rule = subparsers.add_parser(
		"query-rule", help="Query a rule in a package"
	)
	query_rule.add_argument("package_path")
	query_rule.add_argument("rule_name", nargs="?", default=None)
	query_rule.add_argument("--input", help="Inline JSON input document")
	query_rule.set_defaults(func=_cmd_query_rule)

	bulk_query_rule = subparsers.add_parser(
		"bulk-query-rule",
		help="Query a rule against many inputs in a single request",
	)
	bulk_query_rule.add_argument("package_path")
	bulk_query_rule.add_argument("rule_name", nargs="?", default=None)
	inputs_source = bulk_query_rule.add_mutually_exclusive_group(
		required=True
	)
	inputs_source.add_argument(
		"--inputs-file",
		help="Path to a JSON file containing a list or object of inputs",
	)
	inputs_source.add_argument(
		"--inputs-json",
		help="Inline JSON list or object of inputs",
	)
	bulk_query_rule.set_defaults(func=_cmd_bulk_query_rule)

	health = subparsers.add_parser("health", help="Check OPA health")
	health.set_defaults(func=_cmd_health)

	status = subparsers.add_parser("status", help="Get OPA server status")
	status.set_defaults(func=_cmd_status)

	config = subparsers.add_parser("config", help="Get OPA server config")
	config.set_defaults(func=_cmd_config)

	metrics = subparsers.add_parser("metrics", help="Get Prometheus metrics")
	metrics.set_defaults(func=_cmd_metrics)

	wait_for_ready = subparsers.add_parser(
		"wait-for-ready", help="Block until OPA reports healthy"
	)
	wait_for_ready.add_argument(
		"--max-wait",
		type=float,
		default=10.0,
		help="Max time to wait, in seconds",
	)
	wait_for_ready.set_defaults(func=_cmd_wait_for_ready)

	return parser


def main(argv=None) -> int:
	parser = build_parser()
	args = parser.parse_args(argv)

	client = _build_client(args)
	try:
		args.func(client, args)
	except ConnectionsError as e:
		print(f"error: {e.message}", file=sys.stderr)
		return 1
	except Exception as e:
		print(f"error: {e}", file=sys.stderr)
		return 1
	finally:
		client.close_connection()
	return 0


if __name__ == "__main__":
	sys.exit(main())
