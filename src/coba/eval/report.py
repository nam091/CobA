"""Generate Markdown / JSON / HTML report from one or more :class:`EvalRun`."""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path

from coba.eval.schemas import EvalReport, EvalRun


def write_json_report(report: EvalReport, path: Path) -> None:
    """Write ``EvalReport`` to ``path`` (pretty-printed JSON)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def write_markdown_report(report: EvalReport, path: Path) -> None:
    """Write a small Markdown leaderboard table to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# CobA Evaluation Report",
        "",
        f"_Generated at_: {report.generated_at.isoformat()}",
        "",
        "| Config | Dataset | N | Precision | Recall | F1 | MCC | FP rate | Cost (USD) |",
        "|--------|---------|---|-----------|--------|----|-----|---------|------------|",
    ]
    for run in report.runs:
        m = run.metrics
        lines.append(
            "| {name} | {ds} | {n} | {p:.3f} | {r:.3f} | {f1:.3f} | {mcc:.3f} | {fpr:.3f} | {cost:.4f} |".format(
                name=run.config.name,
                ds=run.config.dataset,
                n=run.n_samples,
                p=m.get("precision", 0.0),
                r=m.get("recall", 0.0),
                f1=m.get("f1", 0.0),
                mcc=m.get("mcc", 0.0),
                fpr=m.get("fp_rate", 0.0),
                cost=run.cost_usd,
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CobA Evaluation Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 960px; margin: 2em auto; color: #1d2330; }}
  h1 {{ border-bottom: 2px solid #1d2330; padding-bottom: 0.25em; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1em; }}
  th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: right; }}
  th:first-child, td:first-child, td.text {{ text-align: left; }}
  thead {{ background: #f5f6f8; }}
  tr:nth-child(even) {{ background: #fafbfc; }}
  .footer {{ margin-top: 2em; color: #6a737d; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>CobA Evaluation Report</h1>
<p>Generated at: {generated_at}</p>
<table>
<thead>
<tr><th class="text">Config</th><th class="text">Dataset</th><th>N</th>
<th>Precision</th><th>Recall</th><th>F1</th><th>MCC</th>
<th>FP rate</th><th>Cost (USD)</th></tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
<p class="footer">{n_runs} run(s). See <code>eval_report.json</code> for full detail.</p>
</body>
</html>
"""


def write_html_report(report: EvalReport, path: Path) -> None:
    """Write a single-file static HTML leaderboard."""
    path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[str] = []
    for run in report.runs:
        m = run.metrics
        rows.append(
            "<tr>"
            f"<td class='text'>{html.escape(run.config.name)}</td>"
            f"<td class='text'>{html.escape(run.config.dataset)}</td>"
            f"<td>{run.n_samples}</td>"
            f"<td>{m.get('precision', 0.0):.3f}</td>"
            f"<td>{m.get('recall', 0.0):.3f}</td>"
            f"<td>{m.get('f1', 0.0):.3f}</td>"
            f"<td>{m.get('mcc', 0.0):.3f}</td>"
            f"<td>{m.get('fp_rate', 0.0):.3f}</td>"
            f"<td>{run.cost_usd:.4f}</td>"
            "</tr>"
        )
    content = HTML_TEMPLATE.format(
        generated_at=html.escape(report.generated_at.isoformat()),
        rows="\n".join(rows),
        n_runs=len(report.runs),
    )
    path.write_text(content, encoding="utf-8")


def assemble_report(runs: list[EvalRun]) -> EvalReport:
    return EvalReport(runs=runs, generated_at=datetime.now(UTC))


def write_all(runs: list[EvalRun], output_dir: Path) -> dict[str, Path]:
    """Convenience: write the report in all three formats.

    Returns a mapping ``{"json": ..., "markdown": ..., "html": ...}``."""
    report = assemble_report(runs)
    paths = {
        "json": output_dir / "eval_report.json",
        "markdown": output_dir / "eval_report.md",
        "html": output_dir / "eval_report.html",
    }
    write_json_report(report, paths["json"])
    write_markdown_report(report, paths["markdown"])
    write_html_report(report, paths["html"])
    # Also dump a one-liner CSV that's friendly to scripts.
    csv_lines = ["name,dataset,n,precision,recall,f1,mcc,fp_rate,cost_usd"]
    for run in report.runs:
        m = run.metrics
        csv_lines.append(
            "{name},{ds},{n},{p:.4f},{r:.4f},{f1:.4f},{mcc:.4f},{fpr:.4f},{cost:.4f}".format(
                name=run.config.name,
                ds=run.config.dataset,
                n=run.n_samples,
                p=m.get("precision", 0.0),
                r=m.get("recall", 0.0),
                f1=m.get("f1", 0.0),
                mcc=m.get("mcc", 0.0),
                fpr=m.get("fp_rate", 0.0),
                cost=run.cost_usd,
            )
        )
    paths["csv"] = output_dir / "eval_report.csv"
    paths["csv"].write_text("\n".join(csv_lines) + "\n", encoding="utf-8")
    # Pretty-print the JSON for human consumption.
    paths["pretty"] = output_dir / "eval_report_pretty.json"
    paths["pretty"].write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, default=str),
        encoding="utf-8",
    )
    return paths
