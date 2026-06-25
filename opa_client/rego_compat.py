"""Utilities for OPA Rego v0/v1 syntax compatibility."""

import re
import textwrap

REGO_V1_IMPORT = "import rego.v1"

_V0_RULE_PATTERN = re.compile(
	r"^(\s*)"
	r"(?!package\b|import\b|default\b|#)"
	r"([\w.]+(?:\[[^\]]+\])?)"
	r"\s*\{",
	re.MULTILINE,
)

_V0_SYNTAX_MARKERS = (
	"`if` keyword is required",
	"`contains` keyword is required",
)


def is_v0_rego_syntax_error(error: dict) -> bool:
	"""Return True when OPA rejected policy due to missing v1 keywords."""
	for err in error.get("errors", []):
		message = err.get("message", "")
		if any(marker in message for marker in _V0_SYNTAX_MARKERS):
			return True
	return False


def upgrade_policy_to_v1(policy: str, include_import: bool = False) -> str:
	"""
	Upgrade common v0 Rego constructs for OPA 1.0+.

	Rewrites rule heads such as ``allow {`` to ``allow if {`` and
	``deny[msg] {`` to ``deny contains msg if {``.

	When ``include_import`` is True, also adds ``import rego.v1`` for OPA 0.x
	servers that accept v1 syntax only with that import. OPA 1.0+ does not
	need (and rejects) that import when v1 syntax is used.
	"""
	normalized = textwrap.dedent(policy).strip("\n")
	if include_import:
		normalized = _ensure_rego_v1_import(normalized)

	def replacer(match: re.Match) -> str:
		indent, head = match.group(1), match.group(2)
		return _upgrade_rule_head(indent, head)

	return _V0_RULE_PATTERN.sub(replacer, normalized)


def _ensure_rego_v1_import(policy: str) -> str:
	if re.search(r"^\s*import\s+rego\.v1\b", policy, re.MULTILINE):
		return policy
	if re.search(r"^\s*import\s+future\.keywords", policy, re.MULTILINE):
		return policy
	return f"{REGO_V1_IMPORT}\n\n{policy.lstrip()}"


def _upgrade_rule_head(indent: str, head: str) -> str:
	bracket_match = re.match(r"^([\w.]+)\[([^\]]+)\]$", head)
	if bracket_match:
		name, key = bracket_match.groups()
		return f"{indent}{name} contains {key} if {{"
	return f"{indent}{head} if {{"


def prepare_policy_for_upload(
	policy: str, error: dict, rego_compat: bool
) -> list[str]:
	if not rego_compat or not is_v0_rego_syntax_error(error):
		return []

	candidates = []
	for include_import in (False, True):
		upgraded = upgrade_policy_to_v1(
			policy, include_import=include_import
		)
		if upgraded != policy and upgraded not in candidates:
			candidates.append(upgraded)
	return candidates


def raise_rego_parse_error(error: dict) -> None:
	from .errors import RegoParseError

	raise RegoParseError(
		error.get("code"),
		error.get("message"),
		errors=error.get("errors"),
	)
