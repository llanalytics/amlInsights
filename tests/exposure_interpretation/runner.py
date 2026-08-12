from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_USER_EMAIL = "investigator@tenant1.com"
DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_CASE_DIR = Path(__file__).resolve().parent / "cases"


@dataclass
class CaseFailure:
    case_name: str
    turn_index: int
    question: str
    message: str


@dataclass
class RunResult:
    passed: int = 0
    failed: list[CaseFailure] = field(default_factory=list)


def _json_request(
    *,
    base_url: str,
    path: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    user_email: str = DEFAULT_USER_EMAIL,
    timeout: int = 120,
) -> dict[str, Any]:
    url = base_url.rstrip("/") + path
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url=url,
        data=body,
        method=method,
        headers={
            "Content-Type": "application/json",
            "x-user-email": user_email,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} {path}: {raw[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Connection error for {path}: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON from {path}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"Expected object JSON from {path}")
    return data


def _load_case_files(case_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    files = sorted(case_dir.glob("*.json"))
    if not files:
        raise RuntimeError(f"No case files found in {case_dir}")
    out: list[tuple[Path, dict[str, Any]]] = []
    for path in files:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise RuntimeError(f"{path} must contain an object")
        cases = data.get("cases")
        if not isinstance(cases, list):
            raise RuntimeError(f"{path} missing cases[]")
        out.append((path, data))
    return out


def _create_session(base_url: str, tenant_id: int, case_name: str, user_email: str) -> int:
    data = _json_request(
        base_url=base_url,
        path="/api/entity-search/exposure-sessions",
        method="POST",
        payload={"tenant_id": tenant_id, "title": f"Regression: {case_name}"},
        user_email=user_email,
    )
    session_id = int(data.get("session_id") or 0)
    if session_id < 1:
        raise RuntimeError(f"Session create did not return session_id: {data}")
    return session_id


def _sum_tx_rows(response: dict[str, Any]) -> int:
    evidence = response.get("transaction_evidence")
    if not isinstance(evidence, list):
        return 0
    return sum(int(row.get("row_count") or 0) for row in evidence if isinstance(row, dict))


def _sample_transaction_keys(response: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    evidence = response.get("transaction_evidence")
    if not isinstance(evidence, list):
        return keys
    for item in evidence:
        rows = item.get("sample_rows") if isinstance(item, dict) else []
        if not isinstance(rows, list):
            continue
        for row in rows:
            if isinstance(row, dict) and row.get("transaction_key"):
                keys.add(str(row.get("transaction_key")))
    return keys


def _queried_steps(response: dict[str, Any]) -> list[str]:
    rows = response.get("queried_data")
    if not isinstance(rows, list):
        return []
    return [str(row.get("step") or "") for row in rows if isinstance(row, dict)]


def _plan_endpoints(response: dict[str, Any]) -> list[str]:
    plan = response.get("structured_query_plan")
    steps = plan.get("steps") if isinstance(plan, dict) else []
    if not isinstance(steps, list):
        return []
    return [
        str(step.get("endpoint") or "")
        for step in steps
        if isinstance(step, dict) and str(step.get("endpoint") or "")
    ]


def _applied_filters(response: dict[str, Any]) -> dict[str, Any]:
    mapping = response.get("transaction_filter_mapping")
    applied = mapping.get("applied_filters") if isinstance(mapping, dict) else {}
    return applied if isinstance(applied, dict) else {}


def _clarification_labels(response: dict[str, Any]) -> list[str]:
    clarification = response.get("clarification")
    choices = clarification.get("choices") if isinstance(clarification, dict) else []
    if not isinstance(choices, list):
        return []
    return [str(choice.get("label") or "") for choice in choices if isinstance(choice, dict)]


def _evidence_count(response: dict[str, Any]) -> int:
    evidence = response.get("evidence")
    return len(evidence) if isinstance(evidence, list) else 0


def _enriched_transaction_node_count(response: dict[str, Any]) -> int:
    nodes = response.get("enriched_transaction_nodes")
    return len(nodes) if isinstance(nodes, list) else 0


def _graph_node_count(response: dict[str, Any]) -> int:
    graph = response.get("graph_payload")
    if not isinstance(graph, dict):
        return 0
    explicit_count = graph.get("node_count")
    if isinstance(explicit_count, int):
        return explicit_count
    elements = graph.get("elements") if isinstance(graph.get("elements"), dict) else {}
    nodes = elements.get("nodes") if isinstance(elements.get("nodes"), list) else []
    return len(nodes)


def _response_scope(response: dict[str, Any]) -> str | None:
    if response.get("status") == "needs_clarification" or isinstance(response.get("clarification"), dict):
        return "clarification"
    tx_evidence = response.get("transaction_evidence")
    if isinstance(tx_evidence, list):
        scopes = {
            str(item.get("scope") or "")
            for item in tx_evidence
            if isinstance(item, dict) and item.get("scope")
        }
        if "global" in scopes:
            return "global"
        if scopes:
            return "seeded"
    if response.get("graph_seed_node_id"):
        return "seeded"
    steps = set(_queried_steps(response))
    if "seed_search" in steps or "graph_expansion" in steps:
        return "seeded"
    if "global_transaction_details" in steps:
        return "global"
    return None


def _assert_equal(actual: Any, expected: Any, label: str) -> str | None:
    if actual != expected:
        return f"{label}: expected {expected!r}, got {actual!r}"
    return None


def _is_ordered_subsequence(expected: list[str], actual: list[str]) -> bool:
    if not expected:
        return True
    pos = 0
    for value in actual:
        if value == expected[pos]:
            pos += 1
            if pos == len(expected):
                return True
    return False


def _values_match(actual: Any, expected: Any) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.casefold() == expected.casefold()
    return actual == expected


def _assert_turn(case_name: str, turn_index: int, question: str, response: dict[str, Any], expect: dict[str, Any]) -> list[CaseFailure]:
    failures: list[CaseFailure] = []

    def add(message: str) -> None:
        failures.append(CaseFailure(case_name, turn_index, question, message))

    if "mode" in expect:
        msg = _assert_equal(response.get("mode"), expect.get("mode"), "mode")
        if msg:
            add(msg)
    if "status" in expect:
        msg = _assert_equal(response.get("status"), expect.get("status"), "status")
        if msg:
            add(msg)
    if "scope" in expect:
        msg = _assert_equal(_response_scope(response), expect.get("scope"), "scope")
        if msg:
            add(msg)

    if "queried_steps" in expect:
        actual = _queried_steps(response)
        expected = [str(v) for v in expect.get("queried_steps") or []]
        if not _is_ordered_subsequence(expected, actual):
            add(f"queried_steps: expected ordered sequence {expected!r}, got {actual!r}")

    forbidden = {str(v) for v in expect.get("must_not_query_steps") or []}
    if forbidden:
        actual_set = set(_queried_steps(response))
        bad = sorted(forbidden & actual_set)
        if bad:
            add(f"must_not_query_steps present: {bad!r}")

    if "plan_endpoints" in expect:
        actual = _plan_endpoints(response)
        expected = [str(v) for v in expect.get("plan_endpoints") or []]
        if not _is_ordered_subsequence(expected, actual):
            add(f"plan_endpoints: expected ordered sequence {expected!r}, got {actual!r}")

    filters = expect.get("filters")
    if isinstance(filters, dict):
        applied = _applied_filters(response)
        for key, expected in filters.items():
            actual = applied.get(key)
            if not _values_match(actual, expected):
                add(f"filter {key}: expected {expected!r}, got {actual!r}")

    tx_rows = _sum_tx_rows(response)
    if "min_tx_rows" in expect and tx_rows < int(expect["min_tx_rows"]):
        add(f"min_tx_rows: expected >= {int(expect['min_tx_rows'])}, got {tx_rows}")
    if "max_tx_rows" in expect and tx_rows > int(expect["max_tx_rows"]):
        add(f"max_tx_rows: expected <= {int(expect['max_tx_rows'])}, got {tx_rows}")

    if "min_evidence_count" in expect and _evidence_count(response) < int(expect["min_evidence_count"]):
        add(f"min_evidence_count: expected >= {int(expect['min_evidence_count'])}, got {_evidence_count(response)}")
    if "max_evidence_count" in expect and _evidence_count(response) > int(expect["max_evidence_count"]):
        add(f"max_evidence_count: expected <= {int(expect['max_evidence_count'])}, got {_evidence_count(response)}")
    if "min_enriched_transaction_nodes" in expect and _enriched_transaction_node_count(response) < int(expect["min_enriched_transaction_nodes"]):
        add(
            "min_enriched_transaction_nodes: "
            f"expected >= {int(expect['min_enriched_transaction_nodes'])}, got {_enriched_transaction_node_count(response)}"
        )
    if "min_graph_nodes" in expect and _graph_node_count(response) < int(expect["min_graph_nodes"]):
        add(f"min_graph_nodes: expected >= {int(expect['min_graph_nodes'])}, got {_graph_node_count(response)}")

    expected_keys = {str(v) for v in expect.get("sample_transaction_keys") or []}
    if expected_keys:
        actual_keys = _sample_transaction_keys(response)
        missing = sorted(expected_keys - actual_keys)
        if missing:
            add(f"sample_transaction_keys missing: {missing!r}; sampled={sorted(actual_keys)!r}")

    if "clarification_required" in expect:
        required = bool(expect.get("clarification_required"))
        has_clarification = isinstance(response.get("clarification"), dict) and bool(response.get("clarification"))
        if has_clarification != required:
            add(f"clarification_required: expected {required!r}, got {has_clarification!r}")

    expected_labels = [str(v) for v in expect.get("clarification_labels") or []]
    if expected_labels:
        labels = _clarification_labels(response)
        missing = [label for label in expected_labels if label not in labels]
        if missing:
            add(f"clarification_labels missing: {missing!r}; labels={labels!r}")

    return failures


def _run_case(base_url: str, user_email: str, case: dict[str, Any]) -> RunResult:
    result = RunResult()
    case_name = str(case.get("name") or "unnamed_case")
    tenant_id = int(case.get("tenant_id") or 1)
    create_session = bool(case.get("create_session", True))
    session_id = _create_session(base_url, tenant_id, case_name, user_email) if create_session else None
    turns = case.get("turns")
    if not isinstance(turns, list) or not turns:
        return RunResult(failed=[CaseFailure(case_name, 0, "", "case has no turns")])

    for idx, turn in enumerate(turns, start=1):
        question = str(turn.get("question") or "").strip()
        expect = turn.get("expect") if isinstance(turn.get("expect"), dict) else {}
        payload: dict[str, Any] = {
            "tenant_id": tenant_id,
            "question": question,
            "filter_overrides": turn.get("filter_overrides") if isinstance(turn.get("filter_overrides"), dict) else {},
            "seed_limit": int(turn.get("seed_limit") or 10),
            "hops": int(turn.get("hops") or 2),
            "max_nodes": int(turn.get("max_nodes") or 120),
            "max_edges": int(turn.get("max_edges") or 300),
            "include_graph": bool(turn.get("include_graph", False)),
        }
        if session_id:
            payload["session_id"] = session_id
        try:
            response = _json_request(
                base_url=base_url,
                path="/api/entity-search/exposure-question",
                method="POST",
                payload=payload,
                user_email=user_email,
            )
        except Exception as exc:
            result.failed.append(CaseFailure(case_name, idx, question, f"request failed: {exc}"))
            continue
        failures = _assert_turn(case_name, idx, question, response, expect)
        if failures:
            result.failed.extend(failures)
        else:
            result.passed += 1
    return result


def run_cases(base_url: str, user_email: str, case_dir: Path) -> RunResult:
    aggregate = RunResult()
    for path, data in _load_case_files(case_dir):
        for case in data.get("cases") or []:
            if not isinstance(case, dict):
                aggregate.failed.append(CaseFailure(str(path), 0, "", "case entry is not an object"))
                continue
            result = _run_case(base_url, user_email, case)
            aggregate.passed += result.passed
            aggregate.failed.extend(result.failed)
    return aggregate


def _filter_cases(case_files: list[tuple[Path, dict[str, Any]]], case_filter: str | None) -> list[tuple[Path, dict[str, Any]]]:
    if not case_filter:
        return case_files
    needle = case_filter.casefold()
    filtered: list[tuple[Path, dict[str, Any]]] = []
    for path, data in case_files:
        cases = [
            case
            for case in data.get("cases") or []
            if isinstance(case, dict) and needle in str(case.get("name") or "").casefold()
        ]
        if cases:
            filtered_data = dict(data)
            filtered_data["cases"] = cases
            filtered.append((path, filtered_data))
    return filtered


def _failed_turn_count(failures: list[CaseFailure]) -> int:
    return len({(failure.case_name, failure.turn_index, failure.question) for failure in failures})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run exposure interpretation regression cases.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"amlInsights base URL. Default: {DEFAULT_BASE_URL}")
    parser.add_argument("--user-email", default=DEFAULT_USER_EMAIL, help=f"User email header. Default: {DEFAULT_USER_EMAIL}")
    parser.add_argument("--case-dir", default=str(DEFAULT_CASE_DIR), help=f"Case directory. Default: {DEFAULT_CASE_DIR}")
    parser.add_argument("--case", default=None, help="Run only cases whose name contains this text.")
    args = parser.parse_args(argv)

    case_dir = Path(args.case_dir)
    case_files = _filter_cases(_load_case_files(case_dir), args.case)
    if args.case and not case_files:
        print(f"No cases matched --case {args.case!r}")
        return 1
    aggregate = RunResult()
    for _path, data in case_files:
        for case in data.get("cases") or []:
            if not isinstance(case, dict):
                aggregate.failed.append(CaseFailure(str(_path), 0, "", "case entry is not an object"))
                continue
            result = _run_case(str(args.base_url), str(args.user_email), case)
            aggregate.passed += result.passed
            aggregate.failed.extend(result.failed)
    result = aggregate
    failed_turns = _failed_turn_count(result.failed)
    total = result.passed + failed_turns
    print(
        f"Exposure interpretation regression: {result.passed}/{total} turn(s) passed "
        f"({failed_turns} failed turn(s), {len(result.failed)} assertion failure(s))"
    )
    if result.failed:
        print("")
        for failure in result.failed:
            print(f"FAIL {failure.case_name} turn {failure.turn_index}: {failure.question}")
            print(f"  {failure.message}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
