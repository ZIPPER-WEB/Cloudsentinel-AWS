import json
from datetime import datetime

import pandas as pd
import streamlit as st

from scanner import run_scan


# ==========================================================
# PAGE CONFIGURATION
# ==========================================================
st.set_page_config(
    page_title="CloudSentinel",
    page_icon="☁️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ==========================================================
# DESIGN SYSTEM — CLEAN, ICLOUD-INSPIRED LIGHT THEME
# ==========================================================
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    :root {
        --blue: #2878f0;
        --text: #1d1d1f;
        --muted: #74747a;
        --border: #e8e8ed;
        --background: #f5f5f7;
        --white: #ffffff;
    }

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }

    .stApp { background: var(--background); color: var(--text); }
    [data-testid="stHeader"] { background: rgba(245,245,247,.92); }
    .block-container {
        max-width: 1700px;
        padding: 1.5rem 2.5rem 2rem;
    }
    [data-testid="stSidebar"] {
        background: var(--white);
        border-right: 1px solid var(--border);
    }
    .brand {
        font-size: 1.55rem; font-weight: 800; letter-spacing: -1px;
        color: var(--text);
    }
    .brand-subtitle { color: var(--muted); font-size: .8rem; margin-top: .2rem; }
    .eyebrow {
        color: var(--blue); font-size: .72rem; font-weight: 800;
        letter-spacing: 1.8px; margin-bottom: .8rem;
    }
    .hero-title {
        font-size: clamp(2rem, 3vw, 2.8rem); font-weight: 750;
        letter-spacing: -1.8px; line-height: 1.15; color: var(--text);
        margin-bottom: .5rem;
    }
    .hero-description {
        color: var(--muted); font-size: 1rem; line-height: 1.8;
        max-width: 720px; margin-bottom: 1.5rem;
    }
    .section-title {
        font-size: 1.45rem; font-weight: 750; letter-spacing: -.8px;
        color: var(--text); margin-top: 1.2rem; margin-bottom: .4rem;
    }
    .section-description { color: var(--muted); font-size: .87rem; margin-bottom: 1.2rem; }
    .premium-card {
        background: linear-gradient(145deg, #fff 0%, #fbfcff 100%);
        border: 1px solid #e7eaf1; border-radius: 20px; padding: 1.25rem;
        margin-bottom: .8rem; box-shadow: 0 2px 8px rgba(25,45,85,.025);
        transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease;
        min-height: 135px;
    }
    .premium-card:hover {
        transform: translateY(-3px); border-color: #c8d7f7;
        box-shadow: 0 8px 24px rgba(25,45,85,.07);
    }
    .card-label { font-size: .83rem; font-weight: 500; color: var(--muted); margin-bottom: .7rem; }
    .card-value { font-size: 1.65rem; font-weight: 800; letter-spacing: -1px; color: var(--text); }
    .card-note { color: var(--muted); font-size: .78rem; margin-top: .5rem; }
    div[data-testid="stMetric"] {
        background: #fff; border: 1px solid var(--border); border-radius: 17px;
        padding: 1.1rem; transition: border-color .2s ease;
    }
    div[data-testid="stMetric"]:hover { border-color: #c8d7f7; }
    div[data-testid="stMetricLabel"] { color: var(--muted); }
    div[data-testid="stMetricValue"] { color: var(--text); font-weight: 800; letter-spacing: -1px; }
    .stButton > button, .stDownloadButton > button {
        border-radius: 12px; min-height: 43px; font-weight: 600;
        transition: transform .2s ease;
    }
    .stButton > button:hover, .stDownloadButton > button:hover { transform: translateY(-1px); }
    .stButton > button[kind="primary"] { background: var(--blue); border-color: var(--blue); }
    div[data-testid="stExpander"] {
        background: #fff; border: 1px solid var(--border);
        border-radius: 14px; margin-bottom: .5rem;
    }
    div[data-testid="stTabs"] button { font-weight: 600; }
    div[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
    .footer {
        border-top: 1px solid var(--border); padding-top: 1.5rem; margin-top: 3rem;
        text-align: center; color: var(--muted); font-size: .8rem; line-height: 1.8;
    }
    @media (max-width: 700px) {
        .block-container { padding: 1rem .8rem 1.5rem; }
        .hero-title { letter-spacing: -1px; }
    }
    @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after { transition: none !important; animation: none !important; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ==========================================================
# REUSABLE COMPONENTS
# ==========================================================
def render_card(label, value, note, color="#2878f0", background="#edf4ff"):
    st.markdown(
        f"""
        <div class="premium-card">
            <div class="card-label">
                <span style="display:inline-block;width:8px;height:8px;border-radius:50%;
                    background:{color};margin-right:8px;"></span>{label}
            </div>
            <div class="card-value">{value}</div>
            <div class="card-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_table(data, name):
    if not data:
        st.info("No resources found in this category.")
        return

    frame = pd.DataFrame(data)
    st.dataframe(frame, use_container_width=True, hide_index=True)
    st.download_button(
        "↓ Download CSV",
        data=frame.to_csv(index=False).encode("utf-8"),
        file_name=f"cloudsentinel_{name}.csv",
        mime="text/csv",
        key=f"download_{name}",
    )


def severity_name(finding):
    return str(finding.get("severity", "Informational")).strip().capitalize()


def finding_title(finding):
    return finding.get("title", "Untitled finding")


# ==========================================================
# SIDEBAR NAVIGATION
# ==========================================================
with st.sidebar:
    st.markdown('<div class="brand">☁️ CloudSentinel</div>', unsafe_allow_html=True)
    st.markdown('<div class="brand-subtitle">AWS Security & Diagnostics</div>', unsafe_allow_html=True)
    st.divider()

    page = st.radio(
        "Workspace",
        ["Overview", "Security Findings", "Resource Explorer"],
        label_visibility="visible",
    )

    st.divider()
    st.markdown("#### AWS Connection")
    st.caption("Profile")
    st.code("netdoctor", language=None)
    st.caption("Region")
    st.code("ap-south-1", language=None)
    st.info(
        "Read-only scanning\n\n"
        "CloudSentinel collects AWS inventory and analyzes potential issues "
        "without intentionally modifying resources."
    )
    st.divider()

    scan_clicked = st.button("↻  Scan AWS", type="primary", use_container_width=True)
    if st.button("Clear displayed results", use_container_width=True):
        for key in ("scan_results", "scan_error", "scan_timestamp"):
            st.session_state.pop(key, None)
        st.rerun()

    st.divider()
    st.caption("CloudSentinel · v1.0")


# ==========================================================
# AWS SCAN
# ==========================================================
if scan_clicked:
    with st.spinner("Inspecting your AWS network..."):
        try:
            st.session_state["scan_results"] = run_scan()
            st.session_state["scan_error"] = None
            st.session_state["scan_timestamp"] = datetime.now().astimezone().strftime(
                "%d %b %Y · %I:%M:%S %p %Z"
            )
        except Exception as error:
            st.session_state["scan_error"] = str(error)

results = st.session_state.get("scan_results")
error_message = st.session_state.get("scan_error")


# ==========================================================
# PAGE HEADER
# ==========================================================
st.markdown(
    """
    <div class="eyebrow">CLOUD INFRASTRUCTURE · SECURITY · VISIBILITY</div>
    <div class="hero-title">Your cloud, at a glance.</div>
    <div class="hero-description">
        Explore your AWS network, review security findings, and understand
        potential configuration issues — all in one place.
    </div>
    """,
    unsafe_allow_html=True,
)


# ==========================================================
# EMPTY STATE / ERROR STATE
# ==========================================================
if error_message:
    st.error("The AWS scan could not be completed.")
    st.code(error_message)

elif results is None:
    st.markdown('<div class="eyebrow">WELCOME TO CLOUDSENTINEL</div>', unsafe_allow_html=True)
    st.markdown("## Your cloud workspace is ready.")
    st.write(
        "Discover your AWS network, review potential security issues, "
        "and explore your resources from one place."
    )
    st.info("Select **Scan AWS** in the sidebar to inspect your AWS resources.")

    st.markdown("### Everything you need, in one place")
    col1, col2, col3 = st.columns(3)
    with col1:
        render_card("NETWORK", "Infrastructure", "Explore VPCs, subnets, routes and gateways.")
    with col2:
        render_card("SECURITY", "Findings", "Review potential security issues.", "#c47a00", "#fff6e5")
    with col3:
        render_card("INVENTORY", "Resources", "Search and export your AWS inventory.", "#21865b", "#eaf8f0")

else:
    st.success("AWS scan completed successfully.")
    col1, col2 = st.columns(2)
    with col1:
        st.caption(f"Region: {results.get('region', 'Unknown')}")
    with col2:
        st.caption("Last scan: " + st.session_state.get("scan_timestamp", "Unavailable"))

    st.caption("Authenticated identity: " + str(results.get("identity", "Unknown")))
    st.divider()

    # ------------------------------------------------------
    # OVERVIEW
    # ------------------------------------------------------
    if page == "Overview":
        st.markdown('<div class="section-title">Network overview</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="section-description">Resources discovered in your AWS region.</div>',
            unsafe_allow_html=True,
        )

        resource_items = [
            ("VPCs", "vpcs"),
            ("Subnets", "subnets"),
            ("EC2 Instances", "instances"),
            ("Security Groups", "security_groups"),
            ("Route Tables", "route_tables"),
            ("Network ACLs", "network_acls"),
            ("Internet Gateways", "internet_gateways"),
            ("VPC Peerings", "peering_connections"),
        ]

        resource_columns = st.columns(4, gap="medium")
        for index, (label, key) in enumerate(resource_items):
            with resource_columns[index % 4]:
                render_card(
                    label.upper(),
                    len(results.get(key, []) or []),
                    "Resources discovered",
                )

        st.divider()
        st.markdown('<div class="section-title">Security overview</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="section-description">Findings returned by the current analysis rules.</div>',
            unsafe_allow_html=True,
        )

        summary = results.get("summary", {}) or {}
        findings = results.get("findings", []) or []

        severity_cards = [
            ("Total Findings", "total", "#2878f0", "#edf4ff"),
            ("Critical", "critical", "#c62828", "#fff0f0"),
            ("High", "high", "#dc4545", "#fff1f1"),
            ("Medium", "medium", "#c47a00", "#fff6e5"),
            ("Low", "low", "#2878f0", "#edf4ff"),
        ]
        severity_columns = st.columns(5, gap="small")
        for column, (label, key, color, background) in zip(severity_columns, severity_cards):
            with column:
                value = summary.get(key, len(findings) if key == "total" else 0)
                render_card(label, value, "Security status", color, background)

        if findings:
            st.markdown("#### Findings by severity")
            severity_order = ["Critical", "High", "Medium", "Low", "Informational"]

            severity_counts = (
                pd.Series([severity_name(item) for item in findings])
                .value_counts()
                .reindex(severity_order, fill_value=0)
            )

            chart_data = pd.DataFrame({
                "Severity": severity_counts.index,
                "Findings": severity_counts.values,
            })

            st.bar_chart(
                chart_data.set_index("Severity"),
                y="Findings",
                horizontal=True,
                height=260,
            )

            st.markdown("#### Recent findings")
            for finding in findings[:5]:
                severity = severity_name(finding).upper()
                with st.expander(f"{severity} · {finding_title(finding)}"):
                    st.write(finding.get("description", "No description available."))
                    st.caption("Resource: " + str(finding.get("resource_id", "Unknown")))
                    st.markdown("**Recommended action**")
                    st.write(finding.get("recommendation", "Review the resource configuration."))
        else:
            st.success("No findings were returned by the current analyzers.")

    # ------------------------------------------------------
    # SECURITY FINDINGS
    # ------------------------------------------------------
    elif page == "Security Findings":
        st.markdown('<div class="section-title">Security findings</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="section-description">Search, filter, and investigate potential issues.</div>',
            unsafe_allow_html=True,
        )

        findings = results.get("findings", []) or []
        if not findings:
            st.success("No findings were returned by the current analyzers.")
        else:
            severity_options = ["Critical", "High", "Medium", "Low", "Informational"]
            col1, col2 = st.columns([1, 2])
            with col1:
                selected_severities = st.multiselect(
                    "Filter by severity", severity_options, default=severity_options
                )
            with col2:
                query = st.text_input(
                    "Search findings",
                    placeholder="Search title, resource ID or description...",
                )

            filtered = []
            for finding in findings:
                severity = severity_name(finding)
                searchable = " ".join(str(value) for value in finding.values()).lower()
                if severity not in selected_severities:
                    continue
                if query.lower().strip() not in searchable:
                    continue
                filtered.append(finding)

            st.caption(f"Showing {len(filtered)} of {len(findings)} findings")
            if not filtered:
                st.info("No findings match the selected filters.")
            else:
                for finding in filtered:
                    severity = severity_name(finding).upper()
                    with st.expander(f"{severity} · {finding_title(finding)}"):
                        st.markdown(f"**Resource:** `{finding.get('resource_id', 'Unknown')}`")
                        st.write(finding.get("description", "No description available."))
                        st.markdown("**Recommended action**")
                        st.write(finding.get("recommendation", "Review the resource configuration."))

            st.download_button(
                "↓ Download findings as JSON",
                data=json.dumps(findings, indent=2, default=str),
                file_name="cloudsentinel_findings.json",
                mime="application/json",
            )

    # ------------------------------------------------------
    # RESOURCE EXPLORER
    # ------------------------------------------------------
    elif page == "Resource Explorer":
        st.markdown('<div class="section-title">Resource explorer</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="section-description">Browse and download the resources discovered by your scan.</div>',
            unsafe_allow_html=True,
        )

        tabs = st.tabs(
            [
                "VPCs", "Subnets", "EC2", "Security Groups", "Routes",
                "NACLs", "Interfaces", "Gateways", "Peerings",
            ]
        )
        keys = [
            "vpcs", "subnets", "instances", "security_groups", "route_tables",
            "network_acls", "network_interfaces", "internet_gateways", "peering_connections",
        ]

        for tab, key in zip(tabs, keys):
            with tab:
                data = results.get(key, []) or []
                if data:
                    query = st.text_input(
                        "Search resources",
                        key=f"search_{key}",
                        placeholder="Filter by any resource field...",
                    )
                    if query.strip():
                        data = [
                            item for item in data
                            if query.lower().strip() in json.dumps(item, default=str).lower()
                        ]
                st.caption(f"{len(data)} resources")
                render_table(data, key)


# ==========================================================
# FOOTER
# ==========================================================
st.markdown(
    """
    <div class="footer">
        ☁️ <b>CloudSentinel</b> · AWS Network Security & Diagnostics Platform
        <br>Read-only inventory · Local dashboard
    </div>
    """,
    unsafe_allow_html=True,
)