#!/usr/bin/env python3
"""
generate-summary.py — Collect all result.json files from a multi-lang-bench run
and produce three summary tables in Markdown + a machine-readable JSON.

Usage:
    python3 generate-summary.py <results_base_dir> <agent1> <agent2> ...

Output files (written to results_base_dir):
    summary.md   — Human-readable Markdown with 3 tables
    summary.json — Machine-readable JSON
"""

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

def find_result_files(base_dir, agent):
    """Find all result.json files for a given agent under base_dir/<agent>/."""
    agent_dir = Path(base_dir) / agent
    results = []
    if not agent_dir.exists():
        return results
    for rj in sorted(agent_dir.rglob("result.json")):
        try:
            with open(rj) as f:
                data = json.load(f)
            # Also try to count patch lines from the diff file
            patch_file = rj.parent / "patch.diff"
            gold_file = rj.parent / "gold-patch.diff"
            test_patch_file = rj.parent / "test-patch.diff"
            data["_patch_lines"] = count_lines(patch_file)
            data["_gold_patch_lines"] = count_lines(gold_file)
            data["_test_patch_lines"] = count_lines(test_patch_file)
            data["_result_path"] = str(rj)
            results.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return results

def count_lines(path):
    """Count non-empty lines in a file, return 0 if missing."""
    try:
        with open(path) as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0

def is_success(result):
    """Check if the result is considered successful."""
    status = result.get("status", "")
    resolved = result.get("resolved", False)
    return resolved or status in ("resolved", "patch_generated")

def is_benchmark_resolved(result):
    """Check if validated as resolved by the benchmark harness."""
    return result.get("resolved", False) or result.get("status") == "resolved"

def build_table1(all_results, agents):
    """Table 1: Per-test detail across agents."""
    # Group by instance_id
    by_instance = defaultdict(dict)
    for agent in agents:
        for r in all_results.get(agent, []):
            iid = r.get("instance_id", "unknown")
            by_instance[iid][agent] = r

    rows = []
    for iid in sorted(by_instance.keys()):
        agent_data = by_instance[iid]
        for agent in agents:
            r = agent_data.get(agent)
            if r is None:
                rows.append({
                    "instance_id": iid,
                    "agent": agent,
                    "language": "?",
                    "difficulty": "?",
                    "success": False,
                    "fix_lines": 0,
                    "test_lines": 0,
                    "benchmark_resolved": False,
                    "status": "not_run",
                    "duration_s": 0,
                })
            else:
                rows.append({
                    "instance_id": iid,
                    "agent": agent,
                    "language": r.get("language", "?"),
                    "difficulty": r.get("difficulty", "?"),
                    "success": is_success(r),
                    "fix_lines": r.get("patch_lines", r.get("_patch_lines", 0)),
                    "test_lines": r.get("_test_patch_lines", 0),
                    "benchmark_resolved": is_benchmark_resolved(r),
                    "status": r.get("status", "unknown"),
                    "duration_s": r.get("duration_seconds", 0),
                })
    return rows

def build_table2(all_results, agents):
    """Table 2: Per-model totals."""
    summaries = []
    for agent in agents:
        results = all_results.get(agent, [])
        total = len(results)
        success = sum(1 for r in results if is_success(r))
        resolved = sum(1 for r in results if is_benchmark_resolved(r))
        failed = sum(1 for r in results if r.get("status") in ("no_patch", "not_resolved"))
        errors = sum(1 for r in results if r.get("status") in ("timeout", "error"))
        total_fix_lines = sum(r.get("patch_lines", r.get("_patch_lines", 0)) for r in results)
        total_duration = sum(r.get("duration_seconds", 0) for r in results)
        avg_duration = total_duration / max(total, 1)

        summaries.append({
            "agent": agent,
            "model": results[0].get("model", "default") if results else "default",
            "total_tests": total,
            "successful": success,
            "benchmark_resolved": resolved,
            "failed": failed,
            "errors_timeouts": errors,
            "total_fix_lines": total_fix_lines,
            "avg_duration_s": round(avg_duration, 1),
            "total_duration_s": total_duration,
            "success_rate": round(100 * success / max(total, 1), 1),
            "resolve_rate": round(100 * resolved / max(total, 1), 1),
        })
    return summaries

def determine_best(summaries):
    """Table 3: Determine best model."""
    if not summaries:
        return "No results to compare."

    # Primary: benchmark resolve rate; secondary: success rate; tertiary: fewer lines (efficient)
    ranked = sorted(summaries, key=lambda s: (
        -s["resolve_rate"],
        -s["success_rate"],
        s["total_fix_lines"],  # fewer lines = more efficient
        s["avg_duration_s"],
    ))

    best = ranked[0]
    lines = []
    lines.append(f"**Best performing agent: `{best['agent']}`** (model: {best['model']})")
    lines.append("")
    lines.append(f"- Benchmark resolve rate: {best['resolve_rate']}%")
    lines.append(f"- Success rate (patch generated): {best['success_rate']}%")
    lines.append(f"- Total fix lines generated: {best['total_fix_lines']}")
    lines.append(f"- Average duration per task: {best['avg_duration_s']}s")
    lines.append("")
    if len(ranked) > 1:
        lines.append("**Ranking (best → worst):**")
        lines.append("")
        for i, s in enumerate(ranked, 1):
            lines.append(
                f"{i}. **{s['agent']}** — "
                f"resolved {s['benchmark_resolved']}/{s['total_tests']} ({s['resolve_rate']}%), "
                f"success {s['successful']}/{s['total_tests']} ({s['success_rate']}%), "
                f"avg {s['avg_duration_s']}s"
            )
    return "\n".join(lines)

def render_markdown(table1_rows, table2_summaries, conclusion, run_dir):
    """Render the full summary as Markdown."""
    lines = []
    lines.append(f"# Multi-Language Benchmark Results")
    lines.append("")
    lines.append(f"**Run directory:** `{run_dir}`")
    lines.append("")

    # --- Table 1 ---
    lines.append("## Table 1: Per-Test Results")
    lines.append("")
    lines.append("| Instance ID | Agent | Lang | Difficulty | Success | Fix Lines | Test Lines | Benchmark Resolved | Status | Duration |")
    lines.append("|-------------|-------|------|------------|---------|-----------|------------|--------------------|--------|----------|")
    for r in table1_rows:
        ok = "✅" if r["success"] else "❌"
        bm = "✅" if r["benchmark_resolved"] else "❌"
        lines.append(
            f"| `{r['instance_id'][:40]}` "
            f"| {r['agent']} "
            f"| {r['language']} "
            f"| {r['difficulty']} "
            f"| {ok} "
            f"| {r['fix_lines']} "
            f"| {r['test_lines']} "
            f"| {bm} "
            f"| {r['status']} "
            f"| {r['duration_s']}s |"
        )
    lines.append("")

    # --- Table 2 ---
    lines.append("## Table 2: Per-Model Summary")
    lines.append("")
    lines.append("| Agent | Model | Tests | Successful | Resolved | Failed | Errors | Fix Lines | Avg Time | Success % | Resolve % |")
    lines.append("|-------|-------|-------|------------|----------|--------|--------|-----------|----------|-----------|-----------|")
    for s in table2_summaries:
        lines.append(
            f"| **{s['agent']}** "
            f"| {s['model']} "
            f"| {s['total_tests']} "
            f"| {s['successful']} "
            f"| {s['benchmark_resolved']} "
            f"| {s['failed']} "
            f"| {s['errors_timeouts']} "
            f"| {s['total_fix_lines']} "
            f"| {s['avg_duration_s']}s "
            f"| {s['success_rate']}% "
            f"| {s['resolve_rate']}% |"
        )
    lines.append("")

    # --- Table 3: Conclusion ---
    lines.append("## Table 3: Conclusion — Best Model")
    lines.append("")
    lines.append(conclusion)
    lines.append("")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 3:
        print("Usage: generate-summary.py <results_base_dir> <agent1> [agent2 ...]", file=sys.stderr)
        sys.exit(1)

    results_base = sys.argv[1]
    agents = sys.argv[2:]

    print(f"[summary] Scanning results in {results_base} for agents: {', '.join(agents)}")

    # Collect all results
    all_results = {}
    total_found = 0
    for agent in agents:
        results = find_result_files(results_base, agent)
        all_results[agent] = results
        total_found += len(results)
        print(f"  {agent}: {len(results)} result files found")

    if total_found == 0:
        print("[summary] WARNING: No result files found. Writing empty summary.")

    # Build tables
    table1 = build_table1(all_results, agents)
    table2 = build_table2(all_results, agents)
    conclusion = determine_best(table2)

    # Render markdown
    md = render_markdown(table1, table2, conclusion, results_base)

    # Write outputs
    summary_md = os.path.join(results_base, "summary.md")
    summary_json = os.path.join(results_base, "summary.json")

    with open(summary_md, "w") as f:
        f.write(md)

    with open(summary_json, "w") as f:
        json.dump({
            "per_test": table1,
            "per_model": table2,
            "conclusion": conclusion,
            "agents": agents,
            "results_dir": results_base,
        }, f, indent=2)

    print(f"[summary] Written: {summary_md}")
    print(f"[summary] Written: {summary_json}")


if __name__ == "__main__":
    main()
