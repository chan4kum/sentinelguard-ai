"""SentinelGuard AI — Streamlit dashboard (consumes the REST API; never touches the database).

Run:  streamlit run src/sentinelguard/dashboard/app.py
"""

from __future__ import annotations

import os
from datetime import datetime

import altair as alt
import pandas as pd
import streamlit as st

from sentinelguard.dashboard.client import ApiClient, ApiError

TITLE = "SentinelGuard AI"
SUBTITLE = "Enterprise Security Guardrail Auditor"
DEFAULT_API_URL = "http://localhost:8000"

SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
}
LEVEL_COLORS = {
    "secure": "#15803d",
    "low": "#2563eb",
    "medium": "#ca8a04",
    "high": "#ea580c",
    "critical": "#b91c1c",
}
LEVEL_ICONS = {"secure": "🟢", "low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def api_url() -> str:
    return os.environ.get("SENTINELGUARD_API_BASE_URL", DEFAULT_API_URL)


def level_badge(level: str) -> str:
    """Markdown for a level. Only whitelisted enum values are ever interpolated."""
    level = level if level in LEVEL_COLORS else "low"
    return f"{LEVEL_ICONS[level]} **{level.upper()}**"


def severity_chart(counts: dict[str, int]) -> alt.Chart:
    frame = pd.DataFrame(
        {"severity": SEVERITIES, "findings": [counts.get(s, 0) for s in SEVERITIES]}
    )
    return (
        alt.Chart(frame)
        .mark_bar()
        .encode(
            x=alt.X("severity:N", sort=SEVERITIES, title=None),
            y=alt.Y("findings:Q", title=None, axis=alt.Axis(tickMinStep=1)),
            color=alt.Color(
                "severity:N",
                scale=alt.Scale(domain=SEVERITIES, range=[SEVERITY_COLORS[s] for s in SEVERITIES]),
                legend=None,
            ),
            tooltip=["severity", "findings"],
        )
        .properties(height=230)
    )


def simple_bar(frame: pd.DataFrame, category: str, horizontal: bool = False) -> alt.Chart:
    base = alt.Chart(frame).mark_bar(color="#334155")
    if horizontal:
        chart = base.encode(
            y=alt.Y(f"{category}:N", sort="-x", title=None),
            x=alt.X("findings:Q", title=None, axis=alt.Axis(tickMinStep=1)),
        )
    else:
        chart = base.encode(
            x=alt.X(f"{category}:N", title=None),
            y=alt.Y("findings:Q", title=None, axis=alt.Axis(tickMinStep=1)),
        )
    return chart.encode(tooltip=[category, "findings"]).properties(height=230)


def short_time(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return iso


def render_sidebar(client: ApiClient) -> None:
    with st.sidebar:
        st.header("Run a scan")
        st.caption(f"API: {client.base_url}")
        uploads = st.file_uploader(
            "Terraform / CloudFormation files",
            type=["tf", "json", "yaml", "yml", "template"],
            accept_multiple_files=True,
        )
        if st.button("Scan files", type="primary", disabled=not uploads):
            try:
                scan = client.upload_scan([(u.name, u.getvalue()) for u in uploads])
            except ApiError as exc:
                st.error(str(exc))
            else:
                st.session_state["selected_scan"] = scan["scan_id"]
                st.success(
                    f"Scan complete: risk {scan['risk_score']}/100 "
                    f"({scan['risk_level']}), {scan['finding_count']} finding(s)."
                )
        if st.button("Refresh"):
            st.rerun()
        st.divider()
        st.caption(
            "Files are analysed as data. Nothing is executed or applied to any cloud account."
        )


def render_overview(summary: dict) -> None:
    score = summary["overall_risk_score"]
    level = summary["overall_risk_level"]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Overall Risk Score", f"{score} / 100")
    c1.progress(score / 100)
    c2.metric("Risk classification", level.upper())
    c2.markdown(level_badge(level))
    c3.metric("Scans", summary["scan_count"])
    c4.metric("Total findings", summary["finding_count"])

    counts = summary["findings_by_severity"]
    k1, k2, k3, k4 = st.columns(4)
    for column, severity in zip((k1, k2, k3, k4), SEVERITIES, strict=True):
        column.metric(severity.capitalize(), counts.get(severity, 0))
    st.caption(summary["score_explanation"])

    if summary["finding_count"] == 0:
        return
    left, middle, right = st.columns(3)
    with left:
        st.subheader("Findings by severity")
        st.altair_chart(severity_chart(counts), width="stretch")
    with middle:
        st.subheader("Findings by cloud provider")
        providers = pd.DataFrame(
            {
                "provider": [p.upper() for p in summary["findings_by_provider"]],
                "findings": list(summary["findings_by_provider"].values()),
            }
        )
        st.altair_chart(simple_bar(providers, "provider"), width="stretch")
    with right:
        st.subheader("Findings by rule")
        rules = pd.DataFrame(
            {
                "rule": [r["rule_id"] for r in summary["findings_by_rule"]],
                "findings": [r["count"] for r in summary["findings_by_rule"]],
            }
        )
        st.altair_chart(simple_bar(rules, "rule", horizontal=True), width="stretch")


def render_recent_scans(scans: list[dict]) -> None:
    st.subheader("Recent scans")
    if not scans:
        st.info("No scans yet. Upload a Terraform or CloudFormation file from the sidebar.")
        return
    st.dataframe(
        pd.DataFrame(
            {
                "Scan": [s["scan_id"][:8] for s in scans],
                "When (UTC)": [short_time(s["created_at"]) for s in scans],
                "Files": [", ".join(s["files"]) for s in scans],
                "Risk score": [s["risk_score"] for s in scans],
                "Level": [s["risk_level"] for s in scans],
                "Findings": [s["finding_count"] for s in scans],
            }
        ),
        hide_index=True,
        width="stretch",
    )


def render_score_explanation(detail: dict) -> None:
    breakdown = detail["score_breakdown"]
    st.markdown("#### Why this score?")
    st.write(breakdown["method"])
    cap_note = (
        f" (raw total {breakdown['raw_total']}, capped at {breakdown['cap']})"
        if breakdown["cap_applied"]
        else ""
    )
    st.write(
        f"**Score {breakdown['score']}/100**{cap_note} → band **{breakdown['score_band']}**"
        + (
            f", raised to **{breakdown['risk_level']}** because a CRITICAL finding is present."
            if breakdown["escalated"]
            else f" → level **{breakdown['risk_level']}**."
        )
    )
    left, right = st.columns(2)
    with left:
        st.caption("Points by severity")
        st.dataframe(
            pd.DataFrame(
                [
                    {"Severity": s["severity"], "Findings": s["count"], "Points": s["points"]}
                    for s in breakdown["by_severity"]
                ]
            ),
            hide_index=True,
            width="stretch",
        )
    with right:
        st.caption("Every finding's contribution")
        if breakdown["contributions"]:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Rule": c["rule_id"],
                            "Resource": c["resource_name"],
                            "Severity": c["severity"],
                            "Points": c["points"],
                        }
                        for c in breakdown["contributions"]
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
        else:
            st.write("No findings, so no points.")


def render_findings(detail: dict) -> None:
    st.markdown("#### Findings")
    findings = detail["findings"]
    if not findings:
        st.success("No guardrail violations found in this scan.")
        return
    chosen = st.multiselect("Filter by severity", SEVERITIES, default=SEVERITIES, key="sev_filter")
    for finding in findings:
        if finding["severity"] not in chosen:
            continue
        icon = LEVEL_ICONS.get(finding["severity"], "⚪")
        label = f"{icon} {finding['severity'].upper()} · {finding['rule_id']} · {finding['title']}"
        with st.expander(label):
            st.write(finding["description"])
            st.caption(
                f"Provider: {finding['provider'].upper()} · Resource type: "
                f"{finding['resource_type']} · Risk weight: {finding['risk_weight']}"
            )
            st.markdown("**Resource**")
            st.code(f"{finding['resource_name']}  ({finding['source_file']})", language=None)
            st.markdown("**Evidence**")
            st.code("\n".join(finding["evidence"]), language=None)
            st.markdown("**Remediation**")
            st.info(finding["remediation"])


def render_scan_detail(client: ApiClient, scans: list[dict]) -> None:
    st.subheader("Scan details")
    if not scans:
        return
    by_label = {
        f"{s['scan_id'][:8]} · {short_time(s['created_at'])} · {', '.join(s['files'])}": s[
            "scan_id"
        ]
        for s in scans
    }
    labels = list(by_label)
    selected_id = st.session_state.get("selected_scan")
    # Default to the newest scan that has findings (more informative than a clean one).
    default_index = next((i for i, s in enumerate(scans) if s["finding_count"] > 0), 0)
    index = next(
        (i for i, label in enumerate(labels) if by_label[label] == selected_id), default_index
    )
    label = st.selectbox("Scan", labels, index=index)
    detail = client.get_scan(by_label[label])

    a, b, c = st.columns(3)
    a.metric("Risk score", f"{detail['risk_score']} / 100")
    b.metric("Risk level", detail["risk_level"].upper())
    c.metric("Resources analysed", f"{detail['resources_analyzed']} of {detail['resources_total']}")
    render_score_explanation(detail)
    render_findings(detail)


def main() -> None:
    st.set_page_config(page_title=TITLE, page_icon="🛡️", layout="wide")
    st.title(f"🛡️ {TITLE}")
    st.caption(SUBTITLE)

    client = ApiClient(api_url())
    render_sidebar(client)
    try:
        summary = client.summary()
        scans = client.list_scans(limit=25)
        render_overview(summary)
        render_recent_scans(scans)
        render_scan_detail(client, scans)
    except ApiError as exc:
        st.error(str(exc))


main()
