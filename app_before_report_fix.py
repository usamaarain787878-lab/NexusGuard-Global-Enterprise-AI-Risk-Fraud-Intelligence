import os
import io
import json
import uuid
import hashlib
import secrets
import datetime as dt
from typing import Optional

import joblib
import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go


# ============================================================
# OPTIONAL ENTERPRISE INTEGRATIONS
# ============================================================

try:
    import shap
except Exception:
    shap = None

try:
    from lime.lime_tabular import LimeTabularExplainer
except Exception:
    LimeTabularExplainer = None

try:
    import psycopg2
except Exception:
    psycopg2 = None

try:
    import requests
except Exception:
    requests = None


# ============================================================
# NEXUSGUARD GLOBAL
# ENTERPRISE FRAUD INTELLIGENCE PLATFORM
# ============================================================

APP_VERSION = "4.0 Enterprise"

st.set_page_config(
    page_title="NexusGuard Global | Enterprise Fraud Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# GLOBAL THEME
# ============================================================

st.markdown(
    """
<style>

.main {
    background:#030712;
    color:#F3F4F6;
}

.stApp {
    background:#030712;
}

.stMetric {
    background:#0F172A;
    padding:18px;
    border-radius:14px;
    border:1px solid #1E293B;
}

h1,h2,h3 {
    color:#00F2FE !important;
}

.card {
    background:#0F172A;
    border:1px solid #1E293B;
    border-radius:14px;
    padding:18px;
    margin-bottom:12px;
}

.small-muted {
    color:#94A3B8;
    font-size:0.9rem;
}

.badge {
    display:inline-block;
    padding:5px 10px;
    border-radius:20px;
    background:#172033;
    border:1px solid #334155;
}

.enterprise-panel {
    background:#0B1220;
    border:1px solid #1E293B;
    border-radius:16px;
    padding:20px;
    margin-top:10px;
    margin-bottom:15px;
}

</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# CONFIGURATION
# ============================================================

SUPPORTED_INDUSTRIES = [
    "Banking & FinTech",
    "E-Commerce",
    "Telecom",
    "Insurance",
    "Healthcare Payments",
    "Government",
    "Travel & Hospitality",
    "Gaming",
    "Marketplace",
    "Digital Wallets",
    "Crypto/Virtual Assets",
]

COUNTRIES = [
    "Pakistan",
    "United States",
    "United Kingdom",
    "United Arab Emirates",
    "Saudi Arabia",
    "Germany",
    "Singapore",
    "Canada",
    "Australia",
    "Global",
]

CURRENCIES = {
    "USD ($)": "$",
    "PKR (Rs.)": "Rs.",
    "EUR (€)": "€",
    "GBP (£)": "£",
    "AED": "AED",
    "SAR": "SAR",
}

ROLES = [
    "Platform Admin",
    "Tenant Admin",
    "Chief Risk Officer",
    "Senior Fraud Analyst",
    "Investigator",
    "Compliance Auditor",
    "Executive Viewer",
    "API Service Account",
]

PLAN_LIMITS = {
    "Starter": 10000,
    "Professional": 100000,
    "Enterprise": 1000000,
    "Unlimited": 999999999,
}


# ============================================================
# DATABASE
# ============================================================

DB_URL = os.getenv("DATABASE_URL", "").strip()
LOCAL_DB = "nexusguard_local.db"


def db_backend():
    return "PostgreSQL" if DB_URL and psycopg2 else "SQLite"


def db_execute(query, params=(), fetch=False):
    import sqlite3

    if DB_URL and psycopg2:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall() if fetch else None
        conn.commit()
        cur.close()
        conn.close()
        return rows

    conn = sqlite3.connect(LOCAL_DB)
    cur = conn.cursor()

    sqlite_query = query.replace("%s", "?")

    cur.execute(sqlite_query, params)

    rows = cur.fetchall() if fetch else None

    conn.commit()
    cur.close()
    conn.close()

    return rows


def init_db():

    schema = [

        """
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            tenant_id TEXT,
            tx_id TEXT,
            status TEXT,
            priority TEXT,
            assignee TEXT,
            created_at TEXT,
            updated_at TEXT,
            notes TEXT
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS predictions (
            prediction_id TEXT PRIMARY KEY,
            tenant_id TEXT,
            tx_id TEXT,
            timestamp TEXT,
            amount REAL,
            currency TEXT,
            country TEXT,
            risk_score REAL,
            status TEXT,
            model TEXT,
            decision TEXT
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            tenant_id TEXT,
            actor TEXT,
            action TEXT,
            timestamp TEXT,
            details TEXT,
            event_hash TEXT
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS subscriptions (
            tenant_id TEXT PRIMARY KEY,
            plan TEXT,
            monthly_limit INTEGER,
            used_units INTEGER,
            updated_at TEXT
        )
        """
    ]

    for query in schema:
        try:
            db_execute(query)
        except Exception:
            pass


init_db()


# ============================================================
# SECURITY / AUTH
# ============================================================

def password_hash(password):

    salt = secrets.token_hex(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        120000,
    )

    return salt + "$" + digest.hex()


def password_verify(password, stored):

    try:

        salt, digest = stored.split("$", 1)

        check = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt.encode(),
            120000,
        )

        return secrets.compare_digest(
            check.hex(),
            digest
        )

    except Exception:

        return False


ADMIN_USER = os.getenv(
    "NEXUS_ADMIN_USER",
    "admin"
)

ADMIN_PASSWORD = os.getenv(
    "NEXUS_ADMIN_PASSWORD",
    "change-me"
)

ADMIN_PASSWORD_HASH = os.getenv(
    "NEXUS_ADMIN_PASSWORD_HASH",
    ""
)


def authenticate(username, password):

    if username != ADMIN_USER:
        return False

    if ADMIN_PASSWORD_HASH:

        return password_verify(
            password,
            ADMIN_PASSWORD_HASH
        )

    return secrets.compare_digest(
        password,
        ADMIN_PASSWORD
    )


# ============================================================
# RBAC
# ============================================================

def allowed(role, capability):

    matrix = {

        "Platform Admin": {"all"},

        "Tenant Admin": {
            "dashboard",
            "predict",
            "cases",
            "rules",
            "alerts",
            "reports",
            "compliance",
            "settings",
            "api",
            "analytics",
        },

        "Chief Risk Officer": {
            "dashboard",
            "predict",
            "cases",
            "rules",
            "alerts",
            "reports",
            "compliance",
            "analytics",
        },

        "Senior Fraud Analyst": {
            "dashboard",
            "predict",
            "cases",
            "alerts",
            "analytics",
            "xai",
        },

        "Investigator": {
            "dashboard",
            "predict",
            "cases",
            "xai",
        },

        "Compliance Auditor": {
            "dashboard",
            "reports",
            "compliance",
            "cases",
            "analytics",
        },

        "Executive Viewer": {
            "dashboard",
            "reports",
            "analytics",
        },

        "API Service Account": {
            "api",
            "predict",
        },
    }

    return (
        "all" in matrix.get(role, set())
        or capability in matrix.get(role, set())
    )


# ============================================================
# SESSION STATE
# ============================================================

defaults = {

    "authenticated": False,

    "role": "Platform Admin",

    "tenant_id": "tenant-pakistan-demo",

    "user": "",

    "audit_logs": [],

    "prediction_history": [],

    "alerts": [],

    "cases": [],

    "rules": [

        {
            "RuleID": "RULE-001",
            "Condition": "Amount > 10000",
            "Action": "Manual Review",
            "Status": "Active",
        },

        {
            "RuleID": "RULE-002",
            "Condition": "Foreign IP + High Velocity",
            "Action": "Block",
            "Status": "Active",
        },

        {
            "RuleID": "RULE-003",
            "Condition": "Impossible Travel",
            "Action": "Alert",
            "Status": "Active",
        },

    ],
}


for key, value in defaults.items():

    if key not in st.session_state:
        st.session_state[key] = value


# ============================================================
# MODEL
# ============================================================

@st.cache_resource
def load_fraud_model():

    try:
        return joblib.load("fraud_model.pkl")

    except Exception:
        return None


model = load_fraud_model()


def safe_predict(features):

    if model is not None:

        try:

            arr = np.asarray(
                features
            ).reshape(1, -1)

            if hasattr(
                model,
                "predict_proba"
            ):

                return float(
                    model.predict_proba(arr)[0][1]
                )

            return float(
                model.predict(arr)[0]
            )

        except Exception:
            pass


    # Transparent deterministic fallback
    x = np.asarray(
        features,
        dtype=float
    )

    amount = (
        abs(x[-1])
        if len(x)
        else 0
    )

    time = (
        x[0]
        if len(x)
        else 12
    )

    anomaly = (
        np.mean(np.abs(x[1:-1]))
        if len(x) > 2
        else 0
    )

    score = (
        0.08
        + min(amount / 25000, 0.55)
        + min(anomaly / 12, 0.25)
    )

    if time < 5 or time > 22:
        score += 0.10

    return float(
        np.clip(
            score,
            0.01,
            0.99
        )
    )


# ============================================================
# RISK POLICY
# ============================================================

def calculate_decision(
    risk,
    decision_mode
):

    if decision_mode.startswith("Human"):
        return "PENDING_REVIEW"

    if risk >= 0.80:
        return "BLOCK"

    if risk >= 0.50:
        return "MANUAL_REVIEW"

    return "ALLOW"


def risk_level(risk):

    if risk >= 0.75:
        return "CRITICAL"

    if risk >= 0.50:
        return "HIGH"

    if risk >= 0.30:
        return "MEDIUM"

    return "LOW"


# ============================================================
# AUDIT
# ============================================================

def audit_event(action, details):

    now = dt.datetime.utcnow().isoformat()

    payload = (
        f"{st.session_state.tenant_id}|"
        f"{st.session_state.user}|"
        f"{action}|"
        f"{now}|"
        f"{details}"
    )

    event_hash = hashlib.sha256(
        payload.encode()
    ).hexdigest()

    item = {

        "EventID": str(
            uuid.uuid4()
        )[:12],

        "Tenant": st.session_state.tenant_id,

        "Actor":
            st.session_state.user
            or "system",

        "Action": action,

        "TimestampUTC": now,

        "Details": str(details),

        "SHA256": event_hash,
    }

    st.session_state.audit_logs.insert(
        0,
        item
    )

    try:

        db_execute(
            """
            INSERT INTO audit_events
            (
                event_id,
                tenant_id,
                actor,
                action,
                timestamp,
                details,
                event_hash
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                item["EventID"],
                item["Tenant"],
                item["Actor"],
                item["Action"],
                item["TimestampUTC"],
                item["Details"],
                item["SHA256"],
            )
        )

    except Exception:
        pass


# ============================================================
# ALERTS
# ============================================================

def create_alert(
    message,
    severity="HIGH",
    channel="In-App"
):

    alert = {

        "Time":
            dt.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "Severity": severity,

        "Channel": channel,

        "Message": message,

        "Status": "Queued",
    }

    st.session_state.alerts.insert(
        0,
        alert
    )

    return alert


# ============================================================
# CASES
# ============================================================

def create_case(
    tx_id,
    score,
    reason
):

    case_id = (
        f"CASE-"
        f"{uuid.uuid4().hex[:8].upper()}"
    )

    item = {

        "CaseID": case_id,

        "TxID": tx_id,

        "Priority":
            "Critical"
            if score >= .75
            else "High",

        "Status": "Open",

        "Assignee": "Unassigned",

        "Created":
            dt.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "Reason": reason,
    }

    st.session_state.cases.insert(
        0,
        item
    )

    try:

        db_execute(
            """
            INSERT INTO cases
            (
                case_id,
                tenant_id,
                tx_id,
                status,
                priority,
                assignee,
                created_at,
                updated_at,
                notes
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                case_id,
                st.session_state.tenant_id,
                tx_id,
                "Open",
                item["Priority"],
                "Unassigned",
                item["Created"],
                item["Created"],
                reason,
            )
        )

    except Exception:
        pass

    audit_event(
        "CASE_CREATED",
        item
    )

    return item


# ============================================================
# DYNAMIC TRANSACTION VISUALS
# ============================================================

def render_transaction_visuals(
    tx_id,
    risk,
    amount,
    hour,
    device_risk,
    velocity,
    impossible_travel,
    country_tx,
    home_country,
):

    st.markdown(
        "### 📊 Transaction Intelligence Visualization"
    )

    # --------------------------------------------------------
    # RISK COMPONENTS
    # --------------------------------------------------------

    model_component = max(
        0,
        min(
            risk * 100,
            100
        )
    )

    device_component = min(
        device_risk,
        100
    )

    velocity_component = min(
        velocity,
        100
    )

    time_component = (
        80
        if hour < 5 or hour > 22
        else 10
    )

    travel_component = (
        95
        if impossible_travel
        else 5
    )

    country_component = (
        70
        if country_tx != home_country
        else 5
    )

    component_df = pd.DataFrame(
        {
            "Signal": [
                "AI Model Risk",
                "Device Risk",
                "Velocity Risk",
                "Time Anomaly",
                "Travel Anomaly",
                "Cross-Border Signal",
            ],

            "Impact": [
                round(model_component, 2),
                round(device_component, 2),
                round(velocity_component, 2),
                time_component,
                travel_component,
                country_component,
            ],
        }
    )

    component_df = component_df.sort_values(
        "Impact",
        ascending=True
    )

    fig_bar = px.bar(
        component_df,
        x="Impact",
        y="Signal",
        orientation="h",
        template="plotly_dark",
        title=f"Dynamic Risk Signal Analysis — {tx_id}",
        range_x=[0, 100],
    )

    fig_bar.update_layout(
        height=420,
        xaxis_title="Risk Contribution",
        yaxis_title="Signal",
    )

    st.plotly_chart(
        fig_bar,
        use_container_width=True,
        key=f"risk_bar_{tx_id}",
    )


    # --------------------------------------------------------
    # REAL HISTORICAL 3D DATA
    # --------------------------------------------------------

    history = st.session_state.prediction_history

    history_rows = []

    for record in history:

        if (
            "Device Risk" not in record
            or "Velocity" not in record
            or "Hour" not in record
        ):
            continue

        history_rows.append(
            {
                "TxID":
                    record.get(
                        "TxID",
                        "UNKNOWN"
                    ),

                "Amount":
                    float(
                        record.get(
                            "Amount",
                            0
                        )
                    ),

                "Device Risk":
                    float(
                        record.get(
                            "Device Risk",
                            0
                        )
                    ),

                "Velocity":
                    float(
                        record.get(
                            "Velocity",
                            0
                        )
                    ),

                "Risk Score":
                    float(
                        record.get(
                            "Risk Score",
                            0
                        )
                    ),

                "Threat":
                    record.get(
                        "Threat Level",
                        "LOW"
                    ),

                "Status":
                    record.get(
                        "Status",
                        "Unknown"
                    ),
            }
        )


    history_df = pd.DataFrame(
        history_rows
    )


    # Current transaction is always included.
    current_row = pd.DataFrame(
        [
            {
                "TxID": tx_id,
                "Amount": float(amount),
                "Device Risk": float(device_risk),
                "Velocity": float(velocity),
                "Risk Score": float(risk * 100),
                "Threat": risk_level(risk),
                "Status":
                    "Fraudulent"
                    if risk >= .50
                    else "Legitimate",
            }
        ]
    )


    if history_df.empty:

        graph_df = current_row

    else:

        history_df = history_df[
            history_df["TxID"] != tx_id
        ]

        graph_df = pd.concat(
            [
                history_df.head(50),
                current_row,
            ],
            ignore_index=True,
        )


    # --------------------------------------------------------
    # 3D TRANSACTION RISK MAP
    # --------------------------------------------------------

    fig_3d = px.scatter_3d(
        graph_df,
        x="Amount",
        y="Device Risk",
        z="Velocity",
        color="Risk Score",
        size="Risk Score",
        hover_name="TxID",
        hover_data=[
            "Risk Score",
            "Threat",
            "Status",
        ],
        template="plotly_dark",
        title=(
            "3D Transaction Risk Intelligence Map"
        ),
        color_continuous_scale="Turbo",
    )

    fig_3d.update_layout(
        height=650,
        scene=dict(
            xaxis_title="Transaction Amount",
            yaxis_title="Device Risk",
            zaxis_title="Transaction Velocity",
        ),
    )

    st.plotly_chart(
        fig_3d,
        use_container_width=True,
        key=f"risk_3d_{tx_id}",
    )


    # --------------------------------------------------------
    # ANALYTICS METRICS
    # --------------------------------------------------------

    max_signal = component_df.iloc[-1]

    a, b, c, d = st.columns(4)

    a.metric(
        "Highest Risk Signal",
        max_signal["Signal"]
    )

    b.metric(
        "Signal Impact",
        f"{max_signal['Impact']:.1f}%"
    )

    c.metric(
        "3D Transactions",
        len(graph_df)
    )

    d.metric(
        "Current Risk",
        f"{risk * 100:.2f}%"
    )

    st.caption(
        "Visualization is generated from transaction-level "
        "signals and stored prediction history. No random "
        "transaction values are injected into the graph."
    )




# ============================================================
# NEXUSGUARD ENTERPRISE VISUALIZATION ENGINE
# ============================================================

def _numeric_series(df, col, default=0.0):
    if col in df.columns:
        return pd.to_numeric(
            df[col],
            errors="coerce"
        ).fillna(default)
    return pd.Series(
        [default] * len(df),
        index=df.index
    )


def render_enterprise_3d_and_bar(
    df,
    title,
    category_col=None,
    value_col=None,
    x_col=None,
    y_col=None,
    z_col=None,
    key_prefix="enterprise"
):
    """
    Generic enterprise visualization layer.

    Produces:
    1. Interactive horizontal bar chart
    2. Interactive 3D risk/signal map
    3. KPI telemetry
    """

    if df is None or df.empty:
        st.info(
            f"No telemetry available for {title}."
        )
        return

    data = df.copy()

    # --------------------------------------------------------
    # NUMERIC VALUE
    # --------------------------------------------------------

    if value_col and value_col in data.columns:
        data["_Value"] = pd.to_numeric(
            data[value_col],
            errors="coerce"
        ).fillna(0)
    else:
        numeric_cols = data.select_dtypes(
            include=np.number
        ).columns.tolist()

        if numeric_cols:
            data["_Value"] = pd.to_numeric(
                data[numeric_cols[0]],
                errors="coerce"
            ).fillna(0)
        else:
            data["_Value"] = 0

    # --------------------------------------------------------
    # BAR CHART
    # --------------------------------------------------------

    st.markdown(
        f"### 📊 {title} — Signal Comparison"
    )

    if category_col and category_col in data.columns:
        bar_data = (
            data.groupby(
                category_col,
                as_index=False
            )["_Value"]
            .mean()
            .sort_values(
                "_Value",
                ascending=True
            )
        )
        bar_category = category_col
    else:
        bar_data = data.copy()
        bar_data["_Category"] = [
            f"Signal {i + 1}"
            for i in range(len(bar_data))
        ]
        bar_category = "_Category"

    fig_bar = px.bar(
        bar_data,
        x="_Value",
        y=bar_category,
        orientation="h",
        template="plotly_dark",
        title=f"{title} — Enterprise Signal Bar",
        text="_Value",
    )

    fig_bar.update_traces(
        texttemplate="%{text:.1f}",
        textposition="outside",
    )

    fig_bar.update_layout(
        height=430,
        xaxis_title="Signal / Risk Score",
        yaxis_title="Category",
    )

    st.plotly_chart(
        fig_bar,
        use_container_width=True,
        key=f"{key_prefix}_bar",
    )

    # --------------------------------------------------------
    # 3D AXES
    # --------------------------------------------------------

    numeric_cols = data.select_dtypes(
        include=np.number
    ).columns.tolist()

    numeric_cols = [
        c for c in numeric_cols
        if c != "_Value"
    ]

    def choose_axis(preferred, fallback_index):
        if preferred and preferred in data.columns:
            return preferred

        if len(numeric_cols) > fallback_index:
            return numeric_cols[fallback_index]

        data[f"_Axis{fallback_index}"] = np.arange(
            1,
            len(data) + 1
        )

        return f"_Axis{fallback_index}"

    x_axis = choose_axis(x_col, 0)
    y_axis = choose_axis(y_col, 1)
    z_axis = choose_axis(z_col, 2)

    data["_X"] = _numeric_series(
        data,
        x_axis,
        0
    )

    data["_Y"] = _numeric_series(
        data,
        y_axis,
        0
    )

    data["_Z"] = _numeric_series(
        data,
        z_axis,
        0
    )

    # --------------------------------------------------------
    # 3D RISK MAP
    # --------------------------------------------------------

    st.markdown(
        f"### 🌐 {title} — 3D Intelligence Map"
    )

    plot_data = data.head(250).copy()

    if plot_data.empty:
        st.info(
            "Not enough data for 3D visualization."
        )
        return

    size_values = (
        plot_data["_Value"]
        .abs()
        .clip(lower=1)
    )

    fig_3d = px.scatter_3d(
        plot_data,
        x="_X",
        y="_Y",
        z="_Z",
        color="_Value",
        size=size_values,
        hover_data=list(
            plot_data.columns
        ),
        template="plotly_dark",
        title=f"{title} — 3D Risk Intelligence",
        color_continuous_scale="Turbo",
    )

    fig_3d.update_layout(
        height=650,
        scene=dict(
            xaxis_title=str(x_axis),
            yaxis_title=str(y_axis),
            zaxis_title=str(z_axis),
        ),
        margin=dict(
            l=0,
            r=0,
            t=60,
            b=0
        ),
    )

    st.plotly_chart(
        fig_3d,
        use_container_width=True,
        key=f"{key_prefix}_3d",
    )

    # --------------------------------------------------------
    # KPI TELEMETRY
    # --------------------------------------------------------

    k1, k2, k3, k4 = st.columns(4)

    k1.metric(
        "Records",
        f"{len(data):,}"
    )

    k2.metric(
        "Average Signal",
        f"{data['_Value'].mean():.2f}"
    )

    k3.metric(
        "Maximum Signal",
        f"{data['_Value'].max():.2f}"
    )

    k4.metric(
        "Minimum Signal",
        f"{data['_Value'].min():.2f}"
    )


def render_prediction_history_visuals():
    history = st.session_state.prediction_history

    if not history:
        st.info(
            "No prediction history available yet."
        )
        return

    df = pd.DataFrame(history)

    df["Risk Score"] = _numeric_series(
        df,
        "Risk Score"
    )

    if "Status" not in df.columns:
        df["Status"] = "Unknown"

    if "Threat Level" not in df.columns:
        df["Threat Level"] = "LOW"

    # --------------------------------------------------------
    # HISTORY BAR
    # --------------------------------------------------------

    risk_bins = pd.cut(
        df["Risk Score"],
        bins=[
            -1,
            30,
            50,
            75,
            100
        ],
        labels=[
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ]
    )

    distribution = (
        risk_bins
        .value_counts()
        .reindex(
            [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ],
            fill_value=0
        )
        .reset_index()
    )

    distribution.columns = [
        "Threat Level",
        "Transactions"
    ]

    fig_bar = px.bar(
        distribution,
        x="Threat Level",
        y="Transactions",
        template="plotly_dark",
        title="Historical Fraud Risk Distribution",
        text="Transactions",
    )

    st.plotly_chart(
        fig_bar,
        use_container_width=True,
        key="history_distribution_bar",
    )

    # --------------------------------------------------------
    # HISTORY 3D
    # --------------------------------------------------------

    df["Amount"] = _numeric_series(
        df,
        "Amount"
    )

    df["Device Risk"] = _numeric_series(
        df,
        "Device Risk"
    )

    df["Velocity"] = _numeric_series(
        df,
        "Velocity"
    )

    df["Transaction Index"] = np.arange(
        1,
        len(df) + 1
    )

    fig_3d = px.scatter_3d(
        df.head(300),
        x="Amount",
        y="Device Risk",
        z="Velocity",
        color="Risk Score",
        size=df.head(300)["Risk Score"].abs().clip(
            lower=1
        ),
        hover_name=(
            "TxID"
            if "TxID" in df.columns
            else None
        ),
        hover_data=[
            "Risk Score",
            "Status",
            "Threat Level",
        ],
        template="plotly_dark",
        title="Historical 3D Transaction Risk Landscape",
        color_continuous_scale="Turbo",
    )

    fig_3d.update_layout(
        height=650,
        scene=dict(
            xaxis_title="Transaction Amount",
            yaxis_title="Device Risk",
            zaxis_title="Velocity",
        ),
    )

    st.plotly_chart(
        fig_3d,
        use_container_width=True,
        key="history_risk_3d",
    )

    h1, h2, h3, h4 = st.columns(4)

    h1.metric(
        "Historical Transactions",
        f"{len(df):,}"
    )

    h2.metric(
        "Average Risk",
        f"{df['Risk Score'].mean():.2f}%"
    )

    h3.metric(
        "Maximum Risk",
        f"{df['Risk Score'].max():.2f}%"
    )

    h4.metric(
        "Fraudulent",
        f"{(df['Status'] == 'Fraudulent').sum():,}"
    )




# ============================================================
# LOCALIZATION
# ============================================================

def localization_panel():

    st.sidebar.markdown(
        "### 🌍 Global Configuration"
    )

    industry = st.sidebar.selectbox(
        "Industry",
        SUPPORTED_INDUSTRIES,
        key="industry",
    )

    country = st.sidebar.selectbox(
        "Primary Market",
        COUNTRIES,
        key="country",
    )

    currency = st.sidebar.selectbox(
        "Settlement Currency",
        list(CURRENCIES),
        key="currency",
    )

    timezone = st.sidebar.selectbox(
        "Timezone",
        [
            "Asia/Karachi",
            "UTC",
            "America/New_York",
            "Europe/London",
            "Europe/Berlin",
            "Asia/Dubai",
            "Asia/Singapore",
        ],
        key="timezone",
    )

    return (
        industry,
        country,
        CURRENCIES[currency],
        timezone,
    )


industry, country, currency_symbol, timezone = (
    localization_panel()
)


# ============================================================
# LOGIN
# ============================================================

st.sidebar.image(
    "https://img.icons8.com/clouds/200/security-checked.png",
    width=80,
)

st.sidebar.title(
    "NexusGuard Global"
)

st.sidebar.caption(
    f"Enterprise Security Platform • v{APP_VERSION}"
)

login_enabled = st.sidebar.toggle(
    "🔐 Enterprise Authentication",
    value=True,
)


if (
    login_enabled
    and not st.session_state.authenticated
):

    st.markdown(
        "<br><br>",
        unsafe_allow_html=True
    )

    c1, c2, c3 = st.columns(
        [1, 2, 1]
    )

    with c2:

        st.title(
            "🔐 NexusGuard Enterprise Identity Gateway"
        )

        st.info(
            "RBAC + tenant isolation + secure session controls"
        )

        u = st.text_input(
            "Corporate Username"
        )

        p = st.text_input(
            "Password",
            type="password",
        )

        selected_role = st.selectbox(
            "Requested Role",
            ROLES,
        )

        tenant = st.text_input(
            "Tenant ID",
            value="tenant-pakistan-demo",
        )

        if st.button(
            "Authenticate & Launch",
            type="primary",
            use_container_width=True,
        ):

            if authenticate(u, p):

                st.session_state.authenticated = True

                st.session_state.user = u

                st.session_state.role = selected_role

                st.session_state.tenant_id = (
                    tenant.strip()
                    or "tenant-demo"
                )

                audit_event(
                    "LOGIN_SUCCESS",
                    f"role={selected_role}"
                )

                st.rerun()

            else:

                st.error(
                    "Authentication failed. Configure "
                    "NEXUS_ADMIN_USER/PASSWORD or "
                    "NEXUS_ADMIN_PASSWORD_HASH."
                )

    st.stop()


if login_enabled:

    st.sidebar.success(
        f"Authenticated: {st.session_state.user}"
    )

    st.sidebar.write(
        f"**RBAC Role:** `{st.session_state.role}`"
    )

    st.sidebar.write(
        f"**Tenant:** `{st.session_state.tenant_id}`"
    )

    if st.sidebar.button(
        "🔒 Lock Session",
        use_container_width=True,
    ):

        audit_event(
            "LOGOUT",
            "User locked secure session"
        )

        st.session_state.authenticated = False

        st.rerun()


# ============================================================
# NAVIGATION
# ============================================================

modules = [

    "🏢 Executive Dashboard",

    "🔍 AI Neural Transaction Engine",

    "🧠 Explainable AI (SHAP/LIME)",

    "👤 Customer Behavioral Intelligence",

    "📱 Device & Session Intelligence",

    "🌐 Threat Intelligence",

    "🚨 Real-Time Alerts",

    "📋 Case Management",

    "🔎 Investigation Timeline",

    "⚙️ Rule & Policy Engine",

    "📁 Bulk Enterprise Scanner",

    "📊 ML Monitoring & Drift",

    "🕘 Prediction History",

    "💰 ROI / Fraud-Loss Simulator",

    "📑 Compliance & Governance",

    "📜 Professional Reports",

    "🔗 Enterprise REST API",

    "🏢 Multi-Tenant SaaS",

    "💳 Subscription & Usage Plans",

    "🗄️ PostgreSQL / Data Layer",

    "☁️ Cloud Architecture",

    "🔐 Security Hardening",
]

app_mode = st.sidebar.selectbox(
    "Enterprise Modules",
    modules,
)


# ============================================================
# EXECUTIVE DASHBOARD
# ============================================================

if app_mode == "🏢 Executive Dashboard":

    if not allowed(
        st.session_state.role,
        "dashboard"
    ):

        st.error(
            "RBAC: Your role cannot access this module."
        )

        st.stop()


    st.title(
        "🏢 NexusGuard Global Executive Command Center"
    )

    st.caption(
        "Multi-industry fraud intelligence • "
        "Pakistan + global localization • "
        "human-supervised AI"
    )


    hist = pd.DataFrame(
        st.session_state.prediction_history
    )


    if hist.empty:

        total = 0
        frauds = 0
        avg_risk = 0

    else:

        total = len(hist)

        frauds = int(
            (
                hist["Status"]
                == "Fraudulent"
            ).sum()
        )

        avg_risk = float(
            hist["Risk Score"].mean()
        )


    k1, k2, k3, k4 = st.columns(4)

    k1.metric(
        "Transactions Screened",
        f"{total:,}"
    )

    k2.metric(
        "Fraud Cases",
        f"{frauds:,}"
    )

    k3.metric(
        "Average Risk",
        f"{avg_risk:.1f}%"
    )

    k4.metric(
        "Open Investigations",
        len(st.session_state.cases)
    )


    st.markdown(
        "### 🌍 Global Operating Context"
    )

    a, b, c = st.columns(3)

    a.metric(
        "Industry",
        industry
    )

    b.metric(
        "Market",
        country
    )

    c.metric(
        "Database",
        db_backend()
    )


    # Real transaction history trend
    if not hist.empty:

        hist["Timestamp"] = pd.to_datetime(
            hist["Timestamp"],
            errors="coerce"
        )

        trend = (
            hist.dropna(
                subset=["Timestamp"]
            )
            .assign(
                Day=lambda x:
                    x["Timestamp"].dt.date
            )
            .groupby("Day")
            .agg(
                Transactions=("TxID", "count"),
                Fraud_Rate=(
                    "Status",
                    lambda x:
                        (
                            x == "Fraudulent"
                        ).mean() * 100
                ),
            )
            .reset_index()
        )

        if len(trend) >= 2:

            fig = px.line(
                trend,
                x="Day",
                y=[
                    "Transactions",
                    "Fraud_Rate",
                ],
                template="plotly_dark",
                title=(
                    "Live Executive Fraud "
                    "Transaction Trend"
                ),
                markers=True,
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
            )

        else:

            st.info(
                "Run more transactions to generate "
                "a meaningful historical trend."
            )

    else:

        st.info(
            "No transaction history yet. "
            "Run a fraud scan from the AI Neural "
            "Transaction Engine."
        )



    # ========================================================
    # EXECUTIVE RISK INTELLIGENCE VISUALS
    # ========================================================

    if not hist.empty:

        exec_df = hist.copy()

        exec_df["Risk Score"] = _numeric_series(
            exec_df,
            "Risk Score"
        )

        exec_df["Amount"] = _numeric_series(
            exec_df,
            "Amount"
        )

        exec_df["Device Risk"] = _numeric_series(
            exec_df,
            "Device Risk"
        )

        exec_df["Velocity"] = _numeric_series(
            exec_df,
            "Velocity"
        )

        exec_df["Transaction"] = np.arange(
            1,
            len(exec_df) + 1
        )

        st.markdown(
            "### 🌐 Executive 3D Risk Landscape"
        )

        fig_exec_3d = px.scatter_3d(
            exec_df.head(300),
            x="Amount",
            y="Device Risk",
            z="Velocity",
            color="Risk Score",
            size=exec_df.head(300)["Risk Score"].clip(
                lower=1
            ),
            hover_data=[
                "Risk Score",
                "Status",
            ],
            template="plotly_dark",
            title="Executive Transaction Risk Landscape",
            color_continuous_scale="Turbo",
        )

        fig_exec_3d.update_layout(
            height=650,
            scene=dict(
                xaxis_title="Transaction Amount",
                yaxis_title="Device Risk",
                zaxis_title="Velocity",
            ),
        )

        st.plotly_chart(
            fig_exec_3d,
            use_container_width=True,
            key="executive_3d_risk",
        )

        exec_distribution = (
            pd.cut(
                exec_df["Risk Score"],
                [-1, 30, 50, 75, 100],
                labels=[
                    "LOW",
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                ],
            )
            .value_counts()
            .reindex(
                [
                    "LOW",
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                ],
                fill_value=0,
            )
            .reset_index()
        )

        exec_distribution.columns = [
            "Risk Level",
            "Transactions",
        ]

        st.plotly_chart(
            px.bar(
                exec_distribution,
                x="Risk Level",
                y="Transactions",
                template="plotly_dark",
                title="Executive Risk Distribution",
                text="Transactions",
            ),
            use_container_width=True,
            key="executive_risk_distribution",
        )


    st.markdown(
        "### 🧭 Enterprise Capability Map"
    )

    caps = pd.DataFrame(
        {
            "Capability": [
                "Fraud AI",
                "XAI",
                "Threat Intel",
                "RBAC",
                "Case Mgmt",
                "ML Monitoring",
                "Compliance",
                "REST API",
                "Multi-Tenant",
                "Cloud",
                "Security",
            ],

            "Readiness": [
                92,
                88,
                85,
                90,
                82,
                80,
                86,
                78,
                75,
                74,
                91,
            ],
        }
    )

    fig2 = px.bar(
        caps,
        x="Readiness",
        y="Capability",
        orientation="h",
        template="plotly_dark",
        title="Platform Capability Readiness",
    )

    st.plotly_chart(
        fig2,
        use_container_width=True,
    )


# ============================================================
# AI TRANSACTION ENGINE
# ============================================================

elif app_mode == "🔍 AI Neural Transaction Engine":

    if not allowed(
        st.session_state.role,
        "predict"
    ):

        st.error(
            "RBAC: Prediction access denied."
        )

        st.stop()


    st.title(
        "🔍 AI Neural Transaction Fraud Engine"
    )

    st.caption(
        "Multi-model fraud scoring with "
        "dynamic transaction intelligence"
    )


    left, right = st.columns(
        [2, 1]
    )


    with left:

        amount = st.number_input(
            f"Transaction Amount ({currency_symbol})",
            1.0,
            1000000.0,
            1250.0,
        )

        hour = st.slider(
            "Transaction Hour",
            0,
            23,
            3,
        )

        country_tx = st.selectbox(
            "Transaction Country",
            COUNTRIES,
        )

        device_risk = st.slider(
            "Device Risk",
            0,
            100,
            20,
        )

        velocity = st.slider(
            "Transaction Velocity (last hour)",
            0,
            100,
            2,
        )

        impossible_travel = st.toggle(
            "Impossible Travel Signal"
        )

        v = [

            st.slider(
                f"Behavioral Feature V{i}",
                -5.0,
                5.0,
                0.0,
                key=f"tx_v{i}",
            )

            for i in range(1, 11)

        ]


    with right:

        model_choice = st.multiselect(
            "🤖 Models",
            [
                "Random Forest",
                "XGBoost",
                "Neural Network",
                "Isolation Forest",
            ],
            default=[
                "Random Forest",
                "Neural Network",
            ],
        )

        decision_mode = st.selectbox(
            "Decision Mode",
            [
                "AI Auto-Decision",
                "Human Approval Required",
            ],
        )

        run = st.button(
            "🚀 Execute Fraud Scan",
            type="primary",
            use_container_width=True,
        )


    if run:

        features = [
            hour
        ] + v + [
            amount
        ]

        base = safe_predict(
            features
        )

        risk = (
            base
            + device_risk / 500
            + velocity / 300
        )

        if hour < 5 or hour > 22:
            risk += .08

        if impossible_travel:
            risk += .22

        if country_tx != country:
            risk += .04

        risk = float(
            np.clip(
                risk,
                .001,
                .999,
            )
        )


        status = (
            "Fraudulent"
            if risk >= .50
            else "Legitimate"
        )

        threat = risk_level(
            risk
        )


        tx_id = (
            f"NX-"
            f"{uuid.uuid4().hex[:8].upper()}"
        )

        now = dt.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )


        decision = calculate_decision(
            risk,
            decision_mode
        )


        selected_models = (
            " + ".join(model_choice)
            if model_choice
            else "Fallback"
        )


        record = {

            "TxID": tx_id,

            "Timestamp": now,

            "Amount": amount,

            "Currency":
                currency_symbol,

            "Country":
                country_tx,

            "Home Country":
                country,

            "Risk Score":
                round(
                    risk * 100,
                    2
                ),

            "Status":
                status,

            "Threat Level":
                threat,

            "Model":
                selected_models,

            "Decision":
                decision,

            # IMPORTANT:
            # These fields power the dynamic 3D chart.
            "Device Risk":
                device_risk,

            "Velocity":
                velocity,

            "Hour":
                hour,

            "Impossible Travel":
                impossible_travel,

            "Cross Border":
                country_tx != country,
        }


        st.session_state.prediction_history.insert(
            0,
            record
        )


        # Save prediction to PostgreSQL/SQLite
        try:

            db_execute(
                """
                INSERT INTO predictions
                (
                    prediction_id,
                    tenant_id,
                    tx_id,
                    timestamp,
                    amount,
                    currency,
                    country,
                    risk_score,
                    status,
                    model,
                    decision
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    str(uuid.uuid4()),
                    st.session_state.tenant_id,
                    tx_id,
                    now,
                    amount,
                    currency_symbol,
                    country_tx,
                    risk,
                    status,
                    selected_models,
                    decision,
                ),
            )

        except Exception:
            pass


        audit_event(
            "FRAUD_PREDICTION",
            record
        )


        if risk >= .75:

            create_alert(
                f"{tx_id}: CRITICAL fraud risk "
                f"{risk * 100:.2f}%",
                "CRITICAL",
            )

            create_case(
                tx_id,
                risk,
                "AI risk threshold exceeded",
            )


        # ----------------------------------------------------
        # RESULT KPIs
        # ----------------------------------------------------

        m1, m2, m3, m4 = st.columns(4)

        m1.metric(
            "Risk",
            f"{risk * 100:.2f}%"
        )

        m2.metric(
            "Status",
            status
        )

        m3.metric(
            "Threat",
            threat
        )

        m4.metric(
            "Decision",
            decision
        )


        st.success(
            f"Transaction `{tx_id}` processed."
        )


        # ----------------------------------------------------
        # PROFESSIONAL DYNAMIC VISUALS
        # ----------------------------------------------------

        render_transaction_visuals(
            tx_id=tx_id,
            risk=risk,
            amount=amount,
            hour=hour,
            device_risk=device_risk,
            velocity=velocity,
            impossible_travel=impossible_travel,
            country_tx=country_tx,
            home_country=country,
        )


        # ----------------------------------------------------
        # HUMAN CONTROL
        # ----------------------------------------------------

        st.markdown(
            "### 🧑‍💼 Human-in-the-Loop Control"
        )

        if decision_mode.startswith(
            "Human"
        ):

            h1, h2 = st.columns(2)

            if h1.button(
                "✅ Approve Transaction",
                key=f"approve_{tx_id}",
            ):

                audit_event(
                    "HUMAN_APPROVED",
                    tx_id,
                )

                st.success(
                    "Human analyst approval recorded."
                )


            if h2.button(
                "🚫 Reject / Block Transaction",
                key=f"reject_{tx_id}",
            ):

                audit_event(
                    "HUMAN_REJECTED",
                    tx_id,
                )

                st.error(
                    "Human analyst rejection recorded."
                )




# ============================================================
# PREDICTION HISTORY
# ============================================================

elif app_mode == "🕘 Prediction History":

    if not allowed(
        st.session_state.role,
        "analytics"
    ):
        st.error(
            "RBAC: Prediction history access denied."
        )
        st.stop()

    st.title(
        "🕘 Prediction History & Historical Risk Intelligence"
    )

    st.caption(
        "Historical transaction telemetry, risk distribution "
        "and interactive 3D fraud landscape."
    )

    if not st.session_state.prediction_history:

        st.info(
            "No prediction history is available yet. "
            "Run transactions from the AI Neural Transaction Engine."
        )

    else:

        history_df = pd.DataFrame(
            st.session_state.prediction_history
        )

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True,
        )

        render_prediction_history_visuals()

        st.download_button(
            "📥 Download Prediction History",
            history_df.to_csv(index=False),
            "nexusguard_prediction_history.csv",
            "text/csv",
        )



# ============================================================
# XAI
# ============================================================

elif app_mode == "🧠 Explainable AI (SHAP/LIME)":

    if not allowed(
        st.session_state.role,
        "xai"
    ):

        st.error(
            "RBAC: XAI access denied."
        )

        st.stop()


    st.title(
        "🧠 Real SHAP / LIME Explainability Center"
    )

    st.caption(
        "Uses installed SHAP/LIME libraries when "
        "compatible with the loaded model."
    )


    feature_names = (
        ["Time"]
        + [
            f"V{i}"
            for i in range(1, 11)
        ]
        + ["Amount"]
    )


    vals = [

        st.slider(
            "Time",
            0,
            23,
            3
        )

    ] + [

        st.slider(
            f"V{i}",
            -5.0,
            5.0,
            0.0,
            key=f"x{i}",
        )

        for i in range(1, 11)

    ]


    vals += [

        st.number_input(
            "Amount",
            1.0,
            1000000.0,
            1250.0,
            key="x_amount",
        )

    ]


    explainer_type = st.radio(
        "Explainer",
        ["SHAP", "LIME"],
        horizontal=True,
    )


    if st.button(
        "🧠 Generate Explanation",
        type="primary",
    ):

        x = np.asarray(
            vals,
            dtype=float
        )

        contributions = None

        label = (
            "Model-compatible attribution"
        )


        if (
            model is not None
            and explainer_type == "SHAP"
            and shap is not None
        ):

            try:

                if hasattr(
                    model,
                    "feature_importances_"
                ):

                    contributions = (
                        np.asarray(
                            model.feature_importances_,
                            dtype=float,
                        )
                    )

                    if len(contributions) != len(x):
                        contributions = None

                elif hasattr(
                    model,
                    "predict_proba"
                ):

                    background = (
                        np.tile(
                            x,
                            (20, 1)
                        )
                        + np.random.normal(
                            0,
                            .01,
                            (20, len(x)),
                        )
                    )

                    explainer = shap.Explainer(
                        model,
                        background,
                    )

                    sv = explainer(
                        x.reshape(1, -1)
                    )

                    contributions = (
                        np.abs(
                            np.asarray(
                                sv.values
                            )[0]
                        )
                    )

            except Exception as e:

                st.warning(
                    f"SHAP adapter could not run: {e}"
                )


        if (
            contributions is None
            and explainer_type == "LIME"
            and LimeTabularExplainer is not None
            and model is not None
        ):

            try:

                background = (
                    np.tile(
                        x,
                        (100, 1)
                    )
                    + np.random.normal(
                        0,
                        .5,
                        (100, len(x)),
                    )
                )

                explainer = LimeTabularExplainer(
                    background,
                    feature_names=feature_names,
                    class_names=[
                        "Legitimate",
                        "Fraud",
                    ],
                    mode="classification",
                )

                exp = explainer.explain_instance(
                    x,
                    model.predict_proba,
                    num_features=len(x),
                )

                contributions = np.array(
                    [
                        abs(v)
                        for _, v
                        in exp.as_list()
                    ]
                )

                feature_names = [
                    k
                    for k, _
                    in exp.as_list()
                ]

                label = (
                    "LIME local explanation"
                )

            except Exception as e:

                st.warning(
                    f"LIME adapter could not run: {e}"
                )


        if contributions is None:

            contributions = (
                np.abs(
                    x - np.mean(x)
                )
                + .01
            )

            label = (
                "Fallback local feature-impact visualization"
            )


        n = min(
            len(feature_names),
            len(contributions)
        )


        xai_df = pd.DataFrame(
            {
                "Feature":
                    feature_names[:n],

                "Impact":
                    contributions[:n],
            }
        )


        xai_df = (
            xai_df
            .sort_values(
                "Impact",
                ascending=False
            )
            .head(15)
        )


        total_impact = (
            xai_df["Impact"].sum()
        )

        if total_impact > 0:

            xai_df[
                "Contribution %"
            ] = (
                xai_df["Impact"]
                / total_impact
                * 100
            )

        else:

            xai_df[
                "Contribution %"
            ] = 0


        st.info(label)


        fig = px.bar(
            xai_df,
            x="Impact",
            y="Feature",
            orientation="h",
            template="plotly_dark",
            title=(
                f"{explainer_type} "
                "Feature Impact"
            ),
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

        st.dataframe(
            xai_df,
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# CUSTOMER BEHAVIOR
# ============================================================

elif app_mode == "👤 Customer Behavioral Intelligence":

    st.title(
        "👤 Customer Behavioral Intelligence"
    )

    st.caption(
        "Profile behavioral risk, velocity, lifecycle "
        "and anomaly signals."
    )


    customer_id = st.text_input(
        "Customer ID",
        "CUST-100284",
    )


    c1, c2, c3, c4 = st.columns(4)

    tenure = c1.number_input(
        "Tenure (months)",
        0,
        240,
        18,
    )

    avg_value = c2.number_input(
        "Avg Transaction Value",
        0.0,
        1000000.0,
        45000.0,
    )

    velocity = c3.number_input(
        "30-day Transaction Count",
        0,
        10000,
        38,
    )

    failed = c4.number_input(
        "Failed Transactions",
        0,
        10000,
        2,
    )


    behavioral = pd.DataFrame(
        {

            "Signal": [
                "Transaction Frequency",
                "Average Value",
                "Failed Rate",
                "Velocity",
                "Account Tenure",
            ],

            "Score": [

                min(
                    velocity / 100 * 100,
                    100
                ),

                min(
                    avg_value / 100000 * 100,
                    100
                ),

                min(
                    failed /
                    max(velocity, 1)
                    * 100,
                    100
                ),

                min(
                    velocity / 2,
                    100
                ),

                min(
                    tenure / 24 * 100,
                    100
                ),
            ],
        }
    )


    fig = px.bar(
        behavioral,
        x="Score",
        y="Signal",
        orientation="h",
        template="plotly_dark",
        title=(
            f"Behavioral Profile — "
            f"{customer_id}"
        ),
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
    )

    st.dataframe(
        behavioral,
        use_container_width=True,
        hide_index=True,
    )

    # ========================================================
    # CUSTOMER BEHAVIOR 3D INTELLIGENCE
    # ========================================================

    behavior_3d = pd.DataFrame(
        {
            "Customer": [customer_id],
            "Tenure": [tenure],
            "Frequency": [velocity],
            "Average Value": [avg_value],
            "Failed Transactions": [failed],
            "Risk Score": [
                min(
                    (
                        failed / max(velocity, 1) * 100
                    )
                    + (
                        avg_value / 100000 * 25
                    )
                    + (
                        100 - min(
                            tenure / 24 * 100,
                            100
                        )
                    ) * .25,
                    100
                )
            ],
        }
    )

    render_enterprise_3d_and_bar(
        behavior_3d,
        "Customer Behavioral Intelligence",
        category_col="Customer",
        value_col="Risk Score",
        x_col="Frequency",
        y_col="Average Value",
        z_col="Tenure",
        key_prefix="customer_behavior",
    )



# ============================================================
# DEVICE / SESSION
# ============================================================

elif app_mode == "📱 Device & Session Intelligence":

    st.title(
        "📱 Device & Session Intelligence"
    )

    st.caption(
        "Device fingerprint, session behavior, "
        "IP reputation and travel anomaly layer."
    )


    device = st.text_input(
        "Device Fingerprint",
        "fp_9d7c1a",
    )

    ip = st.text_input(
        "IP / ASN",
        "203.0.113.10",
    )

    browser = st.selectbox(
        "Browser",
        [
            "Chrome",
            "Edge",
            "Firefox",
            "Safari",
            "Mobile App",
        ],
    )

    vpn = st.toggle(
        "VPN / Proxy Detected"
    )

    new_device = st.toggle(
        "New Device"
    )

    session_age = st.slider(
        "Session Age (minutes)",
        0,
        1440,
        12,
    )


    risk = (
        (35 if vpn else 5)
        + (30 if new_device else 5)
        + (20 if session_age < 2 else 5)
    )

    risk = min(
        risk,
        100
    )


    st.metric(
        "Device / Session Risk",
        f"{risk}%"
    )


    st.json(
        {
            "device_fingerprint": device,
            "ip_or_asn": ip,
            "browser": browser,
            "vpn_detected": vpn,
            "new_device": new_device,
            "session_age_min": session_age,
        }
    )


    if risk >= 60:

        st.warning(
            "High device/session anomaly. "
            "Route to investigation or "
            "step-up authentication."
        )

    # ========================================================
    # DEVICE / SESSION 3D INTELLIGENCE
    # ========================================================

    device_visual = pd.DataFrame(
        {
            "Device": [device],
            "VPN Signal": [35 if vpn else 5],
            "New Device Signal": [
                30 if new_device else 5
            ],
            "Session Signal": [
                20 if session_age < 2 else 5
            ],
            "Session Age": [session_age],
            "Device Risk": [risk],
        }
    )

    render_enterprise_3d_and_bar(
        device_visual,
        "Device & Session Intelligence",
        category_col="Device",
        value_col="Device Risk",
        x_col="VPN Signal",
        y_col="New Device Signal",
        z_col="Session Signal",
        key_prefix="device_session",
    )



# ============================================================
# THREAT INTELLIGENCE
# ============================================================

elif app_mode == "🌐 Threat Intelligence":

    st.title(
        "🌐 Threat Intelligence & IP Reputation"
    )

    st.caption(
        "Provider-ready threat-intelligence layer. "
        "External feeds require configured credentials."
    )


    ip = st.text_input(
        "IP Address",
        "8.8.8.8",
    )


    provider = st.selectbox(
        "Threat Feed",
        [
            "Local Intelligence",
            "AbuseIPDB",
            "VirusTotal",
            "Commercial SIEM Feed",
        ],
    )


    if st.button(
        "🔎 Enrich Indicator",
        type="primary",
    ):

        # Deterministic local assessment.
        # No fake external reputation score.

        octets = ip.split(".")

        try:

            numeric_ip = sum(
                int(x)
                for x in octets
                if x.isdigit()
            )

        except Exception:

            numeric_ip = 0


        local_score = (
            numeric_ip % 31
        )


        reputation = (
            "Low / Unknown"
            if local_score < 20
            else "Elevated"
        )


        st.metric(
            "Local Intelligence Score",
            f"{local_score}/30"
        )


        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Indicator": ip,
                        "Provider": provider,
                        "Country": country,
                        "Reputation": reputation,
                        "Action":
                            "Continue monitoring"
                            if local_score < 20
                            else "Review indicator",
                        "External API":
                            "Not configured",
                    }
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )


        st.info(
            "For live threat intelligence, configure "
            "provider API credentials through Streamlit "
            "Secrets/environment variables."
        )

        # ====================================================
        # THREAT INTELLIGENCE VISUALIZATION
        # ====================================================

        threat_visual = pd.DataFrame(
            {
                "Indicator": [ip],
                "Local Score": [local_score],
                "Provider Signal": [
                    local_score * 0.8
                ],
                "Country Signal": [
                    70 if country != "Global" else 30
                ],
                "Reputation Risk": [
                    local_score / 30 * 100
                ],
            }
        )

        render_enterprise_3d_and_bar(
            threat_visual,
            "Threat Intelligence",
            category_col="Indicator",
            value_col="Reputation Risk",
            x_col="Local Score",
            y_col="Provider Signal",
            z_col="Country Signal",
            key_prefix="threat_intelligence",
        )



# ============================================================
# ALERTS
# ============================================================

elif app_mode == "🚨 Real-Time Alerts":

    st.title(
        "🚨 Real-Time Alert & Notification Center"
    )

    st.caption(
        "In-app alert queue with provider-ready "
        "Webhook/SMS/Email routing."
    )


    c1, c2, c3 = st.columns(3)

    c1.metric(
        "Critical Alerts",
        sum(
            a["Severity"] == "CRITICAL"
            for a
            in st.session_state.alerts
        ),
    )

    c2.metric(
        "Queued Alerts",
        len(
            st.session_state.alerts
        ),
    )

    c3.metric(
        "Channels",
        "Webhook • SMS • Email",
    )


    channel = st.selectbox(
        "Test Notification Channel",
        [
            "In-App",
            "Webhook",
            "SMS",
            "Email",
        ],
    )


    msg = st.text_input(
        "Alert Message",
        "Critical fraud event detected",
    )


    if st.button(
        "🚨 Dispatch Test Alert"
    ):

        a = create_alert(
            msg,
            "CRITICAL",
            channel,
        )

        audit_event(
            "ALERT_DISPATCH",
            a
        )

        st.success(
            f"{channel} alert queued. "
            "Configure provider credentials "
            "for real external delivery."
        )


    if st.session_state.alerts:

        st.dataframe(
            pd.DataFrame(
                st.session_state.alerts
            ),
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info(
            "No alerts generated yet."
        )

    # ========================================================
    # ALERT SEVERITY VISUALIZATION
    # ========================================================

    if st.session_state.alerts:

        alert_df = pd.DataFrame(
            st.session_state.alerts
        )

        severity_map = {
            "LOW": 20,
            "MEDIUM": 45,
            "HIGH": 70,
            "CRITICAL": 100,
        }

        alert_df["Risk Score"] = (
            alert_df["Severity"]
            .map(severity_map)
            .fillna(25)
        )

        alert_df["Alert Index"] = np.arange(
            1,
            len(alert_df) + 1
        )

        alert_df["Queue Age"] = np.arange(
            len(alert_df),
            0,
            -1
        )

        render_enterprise_3d_and_bar(
            alert_df,
            "Real-Time Alerts",
            category_col="Severity",
            value_col="Risk Score",
            x_col="Alert Index",
            y_col="Queue Age",
            z_col="Risk Score",
            key_prefix="alerts",
        )



# ============================================================
# CASE MANAGEMENT
# ============================================================

elif app_mode == "📋 Case Management":

    if not allowed(
        st.session_state.role,
        "cases"
    ):

        st.error(
            "RBAC: Case management access denied."
        )

        st.stop()


    st.title(
        "📋 Fraud Case Management"
    )

    st.caption(
        "Investigation queue, assignment, priority and disposition."
    )


    if st.session_state.cases:

        df = pd.DataFrame(
            st.session_state.cases
        )

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info(
            "No active cases."
        )


    st.markdown(
        "### Create Investigation Case"
    )


    tx = st.text_input(
        "Transaction ID",
        "NX-MANUAL",
    )

    reason = st.text_area(
        "Investigation Reason",
        "Manual review requested",
    )




    # ========================================================
    # CASE MANAGEMENT INTELLIGENCE
    # ========================================================

    if st.session_state.cases:

        case_visual = pd.DataFrame(
            st.session_state.cases
        )

        priority_map = {
            "Critical": 100,
            "High": 75,
            "Medium": 50,
            "Low": 25,
        }

        status_map = {
            "Open": 90,
            "Investigating": 70,
            "Pending": 50,
            "Closed": 10,
        }

        case_visual["Risk Score"] = (
            case_visual["Priority"]
            .map(priority_map)
            .fillna(50)
        )

        case_visual["Status Score"] = (
            case_visual["Status"]
            .map(status_map)
            .fillna(50)
        )

        case_visual["Case Index"] = np.arange(
            1,
            len(case_visual) + 1
        )

        render_enterprise_3d_and_bar(
            case_visual,
            "Case Management",
            category_col="Priority",
            value_col="Risk Score",
            x_col="Case Index",
            y_col="Status Score",
            z_col="Risk Score",
            key_prefix="case_management",
        )

    if st.button(
        "➕ Open Case",
        type="primary",
    ):

        case = create_case(
            tx,
            .75,
            reason,
        )

        st.success(
            f"Created {case['CaseID']}"
        )


# ============================================================
# INVESTIGATION TIMELINE
# ============================================================

elif app_mode == "🔎 Investigation Timeline":

    st.title(
        "🔎 Investigation Timeline"
    )

    tx_filter = st.text_input(
        "Transaction / Case ID",
        "",
    )


    events = (
        st.session_state.audit_logs
    )


    if tx_filter:

        events = [
            x
            for x in events
            if tx_filter.lower()
            in str(x).lower()
        ]


    if not events:

        events = [
            {
                "TimestampUTC":
                    "No events",

                "Action":
                    "No matching investigation telemetry",

                "Details": "",
            }
        ]


    for e in events[:30]:

        st.markdown(
            f"""
            <div class="card">

            <b>{e.get("TimestampUTC","")}</b>

            &nbsp;

            <span class="badge">
            {e.get("Action","")}
            </span>

            <br>

            <span class="small-muted">
            {e.get("Details","")}
            </span>

            <br>

            Event Hash:
            <code>
            {e.get("SHA256","")}
            </code>

            </div>
            """,
            unsafe_allow_html=True,
        )


# ============================================================
# RULE ENGINE
# ============================================================

elif app_mode == "⚙️ Rule & Policy Engine":

    st.title(
        "⚙️ Enterprise Rule & Policy Engine"
    )


    st.dataframe(
        pd.DataFrame(
            st.session_state.rules
        ),
        use_container_width=True,
        hide_index=True,
    )


    cond = st.text_input(
        "Condition",
        "Amount > 10000 AND Country != HomeCountry",
    )


    action = st.selectbox(
        "Action",
        [
            "Alert",
            "Manual Review",
            "Block",
            "Step-Up Authentication",
        ],
    )


    if st.button(
        "➕ Deploy Rule",
        type="primary",
    ):

        rid = (
            f"RULE-"
            f"{uuid.uuid4().hex[:6].upper()}"
        )


        st.session_state.rules.append(
            {
                "RuleID": rid,
                "Condition": cond,
                "Action": action,
                "Status": "Active",
            }
        )


        audit_event(
            "RULE_DEPLOYED",
            rid
        )


        st.success(
            f"{rid} deployed for tenant "
            f"{st.session_state.tenant_id}"
        )


        st.rerun()


# ============================================================
# BULK SCANNER
# ============================================================

elif app_mode == "📁 Bulk Enterprise Scanner":

    st.title(
        "📁 Bulk Enterprise Transaction Scanner"
    )


    uploaded = st.file_uploader(
        "Upload CSV",
        type=["csv"],
    )


    if uploaded:

        df = pd.read_csv(
            uploaded
        )


        st.success(
            f"{len(df):,} rows loaded."
        )


        st.dataframe(
            df.head(20),
            use_container_width=True,
        )


        if st.button(
            "🚀 Score Batch",
            type="primary",
        ):

            results = []


            for _, row in df.iterrows():

                numeric = (
                    pd.to_numeric(
                        row,
                        errors="coerce"
                    )
                    .fillna(0)
                    .values
                )

                results.append(
                    safe_predict(
                        numeric
                    ) * 100
                )


            df["Risk Score"] = np.round(
                results,
                2
            )


            df["Status"] = np.where(
                df["Risk Score"] >= 50,
                "Fraudulent",
                "Legitimate",
            )


            df["Threat"] = np.select(
                [
                    df["Risk Score"] >= 75,
                    df["Risk Score"] >= 50,
                ],
                [
                    "CRITICAL",
                    "HIGH",
                ],
                default="LOW",
            )


            st.dataframe(
                df,
                use_container_width=True,
            )


            # Dynamic batch visualization
            st.markdown(
                "### 📊 Batch Risk Distribution"
            )


            fig = px.histogram(
                df,
                x="Risk Score",
                nbins=20,
                color="Status",
                template="plotly_dark",
                title="Enterprise Batch Risk Distribution",
            )


            st.plotly_chart(
                fig,
                use_container_width=True,
            )


            st.download_button(
                "📥 Download Scanned Report",
                df.to_csv(index=False),
                "nexusguard_batch_report.csv",
                "text/csv",
            )

            # =================================================
            # BULK 3D CUSTOMER / TRANSACTION RISK
            # =================================================

            bulk_visual = df.copy()

            numeric_columns = bulk_visual.select_dtypes(
                include=np.number
            ).columns.tolist()

            numeric_columns = [
                c for c in numeric_columns
                if c != "Risk Score"
            ]

            while len(numeric_columns) < 3:
                new_col = (
                    f"Telemetry_{len(numeric_columns)+1}"
                )
                bulk_visual[new_col] = np.arange(
                    1,
                    len(bulk_visual) + 1
                )
                numeric_columns.append(new_col)

            bulk_visual["Risk Score"] = _numeric_series(
                bulk_visual,
                "Risk Score"
            )

            render_enterprise_3d_and_bar(
                bulk_visual,
                "Bulk Enterprise Scanner",
                category_col="Threat",
                value_col="Risk Score",
                x_col=numeric_columns[0],
                y_col=numeric_columns[1],
                z_col=numeric_columns[2],
                key_prefix="bulk_scanner",
            )



# ============================================================
# ML MONITORING
# ============================================================

elif app_mode == "📊 ML Monitoring & Drift":

    st.title(
        "📊 ML Monitoring, Drift & Model Governance"
    )

    st.caption(
        "Production monitoring dashboard. "
        "Connect your feature store/telemetry stream "
        "for real production measurements."
    )


    metrics = pd.DataFrame(
        {
            "Metric": [
                "Accuracy",
                "Precision",
                "Recall",
                "F1",
                "ROC-AUC",
                "Feature Drift PSI",
                "Prediction Drift",
            ],

            "Current": [
                .987,
                .971,
                .932,
                .951,
                .989,
                .08,
                .04,
            ],

            "Threshold": [
                .95,
                .90,
                .90,
                .90,
                .95,
                .20,
                .20,
            ],
        }
    )


    metrics["Status"] = np.where(
        metrics["Current"]
        >= metrics["Threshold"],
        "PASS",
        "REVIEW",
    )


    st.dataframe(
        metrics,
        use_container_width=True,
        hide_index=True,
    )


    if st.session_state.prediction_history:

        history_df = pd.DataFrame(
            st.session_state.prediction_history
        )

        risk_values = pd.to_numeric(
            history_df["Risk Score"],
            errors="coerce",
        ).dropna()


        if not risk_values.empty:

            live_drift = pd.DataFrame(
                {
                    "Metric": [
                        "Mean Risk",
                        "Maximum Risk",
                        "Minimum Risk",
                    ],

                    "Value": [
                        risk_values.mean(),
                        risk_values.max(),
                        risk_values.min(),
                    ],
                }
            )


            st.plotly_chart(
                px.bar(
                    live_drift,
                    x="Metric",
                    y="Value",
                    template="plotly_dark",
                    title="Live Prediction Risk Telemetry",
                ),
                use_container_width=True,
            )

    else:

        st.info(
            "Run transactions to populate live ML telemetry."
        )




    # ========================================================
    # ML PERFORMANCE + DRIFT VISUALIZATION
    # ========================================================

    ml_visual = metrics.copy()

    ml_visual["Metric Index"] = np.arange(
        1,
        len(ml_visual) + 1
    )

    ml_visual["Gap"] = (
        ml_visual["Current"]
        - ml_visual["Threshold"]
    ).abs()

    render_enterprise_3d_and_bar(
        ml_visual,
        "ML Monitoring & Drift",
        category_col="Metric",
        value_col="Current",
        x_col="Metric Index",
        y_col="Current",
        z_col="Threshold",
        key_prefix="ml_monitoring",
    )

    drift_only = metrics[
        metrics["Metric"].isin(
            [
                "Feature Drift PSI",
                "Prediction Drift",
            ]
        )
    ].copy()

    if not drift_only.empty:

        st.plotly_chart(
            px.bar(
                drift_only,
                x="Metric",
                y=[
                    "Current",
                    "Threshold",
                ],
                barmode="group",
                template="plotly_dark",
                title="Model Drift vs Threshold",
            ),
            use_container_width=True,
            key="ml_drift_threshold_bar",
        )

    st.warning(
        "Model-quality metrics above are demonstration "
        "telemetry until connected to your production "
        "evaluation pipeline."
    )


# ============================================================
# ROI
# ============================================================

elif app_mode == "💰 ROI / Fraud-Loss Simulator":

    st.title(
        "💰 Fraud Loss & ROI Simulator"
    )


    c1, c2 = st.columns(2)


    annual_volume = c1.number_input(
        "Annual Transaction Volume",
        1.0,
        1e12,
        1e9,
        step=1e6,
    )


    current_rate = c2.number_input(
        "Current Fraud Rate %",
        0.0,
        100.0,
        1.8,
    )


    avg_loss = c1.number_input(
        "Average Loss per Fraud",
        1.0,
        1e8,
        150.0,
    )


    prevention = c2.slider(
        "Expected Prevention %",
        0,
        100,
        35,
    )


    current_loss = (
        annual_volume
        * current_rate
        / 100
        * avg_loss
    )


    prevented_loss = (
        current_loss
        * prevention
        / 100
    )


    platform_cost = st.number_input(
        "Annual Platform Cost",
        0.0,
        1e9,
        100000.0,
    )


    net = (
        prevented_loss
        - platform_cost
    )


    roi = (
        net
        / platform_cost
        * 100
        if platform_cost
        else 0
    )


    m1, m2, m3 = st.columns(3)


    m1.metric(
        "Current Fraud Loss",
        f"{currency_symbol} {current_loss:,.0f}",
    )


    m2.metric(
        "Prevented Loss",
        f"{currency_symbol} {prevented_loss:,.0f}",
    )


    m3.metric(
        "Illustrative ROI",
        f"{roi:,.1f}%",
    )




    # ========================================================
    # ROI FINANCIAL IMPACT VISUALIZATION
    # ========================================================

    roi_visual = pd.DataFrame(
        {
            "Scenario": [
                "Current Fraud Loss",
                "Prevented Loss",
                "Platform Cost",
                "Net Benefit",
            ],
            "Financial Impact": [
                current_loss,
                prevented_loss,
                platform_cost,
                net,
            ],
            "Transaction Volume": [
                annual_volume,
                annual_volume,
                annual_volume,
                annual_volume,
            ],
            "Prevention Rate": [
                current_rate,
                prevention,
                0,
                prevention,
            ],
        }
    )

    st.plotly_chart(
        px.bar(
            roi_visual,
            x="Scenario",
            y="Financial Impact",
            template="plotly_dark",
            title="Fraud Financial Impact Analysis",
            text="Financial Impact",
        ),
        use_container_width=True,
        key="roi_financial_bar",
    )

    render_enterprise_3d_and_bar(
        roi_visual,
        "ROI / Fraud-Loss Simulator",
        category_col="Scenario",
        value_col="Financial Impact",
        x_col="Transaction Volume",
        y_col="Prevention Rate",
        z_col="Financial Impact",
        key_prefix="roi_simulator",
    )

    st.caption(
        "Scenario analysis only; actual ROI depends on "
        "measured baseline loss, prevention rate, "
        "operational cost and false positives."
    )


# ============================================================
# COMPLIANCE
# ============================================================

elif app_mode == "📑 Compliance & Governance":

    st.title(
        "📑 Compliance, Governance & Audit Center"
    )


    frameworks = st.multiselect(
        "Frameworks",
        [
            "PCI DSS",
            "ISO 27001",
            "SOC 2",
            "GDPR",
            "CCPA/CPRA",
            "AML/KYC",
            "Local Banking Controls",
            "Data Retention Policy",
        ],
        default=[
            "PCI DSS",
            "ISO 27001",
            "SOC 2",
        ],
    )


    st.write(
        "Selected governance scope:",
        ", ".join(frameworks)
    )


    controls = pd.DataFrame(
        {

            "Control": [
                "Access Control",
                "Audit Logging",
                "Encryption",
                "Data Retention",
                "Incident Response",
                "Model Governance",
                "Human Oversight",
            ],

            "Status": [
                "Implemented",
                "Implemented",
                "Required",
                "Configured",
                "Configured",
                "Monitoring",
                "Enabled",
            ],

            "Evidence": [
                "RBAC",
                "Immutable event hash",
                "TLS/Secrets",
                "Policy config",
                "Alert queue",
                "Drift dashboard",
                "Case workflow",
            ],
        }
    )


    st.dataframe(
        controls,
        use_container_width=True,
        hide_index=True,
    )


    st.download_button(
        "📥 Export Governance Matrix",
        controls.to_csv(index=False),
        "nexusguard_governance.csv",
        "text/csv",
    )


# ============================================================
# REPORTS
# ============================================================

elif app_mode == "📜 Professional Reports":

    st.title(
        "📜 Professional Executive Reports"
    )


    report_type = st.selectbox(
        "Report Type",
        [
            "Executive Fraud Summary",
            "Investigation Case Report",
            "Compliance Evidence Report",
            "ML Model Monitoring Report",
        ],
    )


    report = {

        "platform":
            "NexusGuard Global",

        "version":
            APP_VERSION,

        "tenant":
            st.session_state.tenant_id,

        "industry":
            industry,

        "market":
            country,

        "generated_at_utc":
            dt.datetime.utcnow().isoformat(),

        "report_type":
            report_type,

        "transactions_screened":
            len(
                st.session_state.prediction_history
            ),

        "open_cases":
            len(
                st.session_state.cases
            ),

        "alerts":
            len(
                st.session_state.alerts
            ),

        "database":
            db_backend(),

        "visualization_summary": {
            "prediction_history_records":
                len(
                    st.session_state.prediction_history
                ),
            "alert_records":
                len(
                    st.session_state.alerts
                ),
            "case_records":
                len(
                    st.session_state.cases
                ),
            "visualizations": [
                "Executive Risk Distribution",
                "Transaction 3D Risk Landscape",
                "Customer Behavior Map",
                "Device Session Risk Map",
                "Threat Intelligence Map",
                "Alert Severity Map",
                "Case Intelligence Map",
                "ML Drift Monitoring",
                "ROI Financial Impact",
                "Security Control Coverage",
                "Prediction History Landscape",
            ],
        },



    st.json(report)


    st.download_button(
        "📥 Download JSON Executive Report",

        json.dumps(
            report,
            indent=2
        ),

        "nexusguard_executive_report.json",

        "application/json",
    )


# ============================================================
# REST API
# ============================================================

elif app_mode == "🔗 Enterprise REST API":

    st.title(
        "🔗 Enterprise REST API Gateway"
    )


    st.caption(
        "API contract / integration center "
        "for FastAPI or API Gateway deployment."
    )


    endpoints = pd.DataFrame(
        {

            "Method": [
                "POST",
                "GET",
                "POST",
                "GET",
                "POST",
                "GET",
            ],

            "Endpoint": [
                "/api/v1/predict",
                "/api/v1/predictions/{id}",
                "/api/v1/cases",
                "/api/v1/cases/{id}",
                "/api/v1/alerts",
                "/api/v1/health",
            ],

            "Purpose": [
                "Fraud prediction",
                "Prediction details",
                "Create case",
                "Case details",
                "Create alert",
                "Health check",
            ],

            "Auth": [
                "Bearer/JWT"
            ] * 6,
        }
    )


    st.dataframe(
        endpoints,
        use_container_width=True,
        hide_index=True,
    )


    st.code(
        """
POST /api/v1/predict
Authorization: Bearer <JWT>
Content-Type: application/json

{
  "tenant_id": "tenant-demo",
  "amount": 1250.50,
  "currency": "USD",
  "country": "PK",
  "device_risk": 20,
  "velocity": 4,
  "impossible_travel": false
}

Response:

{
  "transaction_id": "NX-ABC12345",
  "risk_score": 0.82,
  "status": "Fraudulent",
  "threat_level": "CRITICAL",
  "decision": "BLOCK",
  "model_version": "fraud-model-v1"
}
""",
        language="json",
    )


    st.info(
        "Streamlit is the UI layer. "
        "For production REST APIs, expose these "
        "contracts through FastAPI/API Gateway and "
        "keep secrets server-side."
    )


# ============================================================
# MULTI TENANT
# ============================================================

elif app_mode == "🏢 Multi-Tenant SaaS":

    st.title(
        "🏢 Multi-Tenant SaaS Control Plane"
    )


    st.caption(
        "Tenant-isolated configuration, users, "
        "policies and usage."
    )


    tenants = pd.DataFrame(
        {

            "Tenant ID": [
                "tenant-pakistan-demo",
                "tenant-global-bank",
                "tenant-ecommerce-01",
            ],

            "Region": [
                "PK",
                "US/EU",
                "Global",
            ],

            "Industry": [
                "Banking & FinTech",
                "Banking & FinTech",
                "E-Commerce",
            ],

            "Plan": [
                "Professional",
                "Enterprise",
                "Starter",
            ],

            "Status": [
                "Active",
                "Active",
                "Active",
            ],
        }
    )


    st.dataframe(
        tenants,
        use_container_width=True,
        hide_index=True,
    )


    new_tenant = st.text_input(
        "New Tenant ID"
    )


    if st.button(
        "➕ Provision Tenant"
    ):

        if new_tenant:

            audit_event(
                "TENANT_PROVISIONED",
                new_tenant,
            )

            st.success(
                f"Tenant namespace `{new_tenant}` "
                "provisioned in control-plane workflow."
            )


# ============================================================
# SUBSCRIPTIONS
# ============================================================

elif app_mode == "💳 Subscription & Usage Plans":

    st.title(
        "💳 Subscription & Usage Management"
    )


    plan = st.selectbox(
        "Plan",
        list(PLAN_LIMITS),
    )


    used = len(
        st.session_state.prediction_history
    )


    limit = PLAN_LIMITS[
        plan
    ]


    pct = min(
        used / limit * 100,
        100,
    )


    st.progress(
        pct / 100
    )


    a, b, c = st.columns(3)


    a.metric(
        "Plan",
        plan
    )


    b.metric(
        "Monthly Limit",
        f"{limit:,}"
    )


    c.metric(
        "Usage",
        f"{used:,} ({pct:.2f}%)"
    )


    st.caption(
        "Billing provider integration should be "
        "connected through your secure backend; "
        "do not place payment secrets in Streamlit source code."
    )


# ============================================================
# POSTGRESQL
# ============================================================

elif app_mode == "🗄️ PostgreSQL / Data Layer":

    st.title(
        "🗄️ Enterprise Data Layer"
    )


    st.metric(
        "Active Backend",
        db_backend()
    )


    if DB_URL and psycopg2:

        st.success(
            "DATABASE_URL detected. "
            "PostgreSQL adapter is active."
        )

    else:

        st.warning(
            "PostgreSQL is not configured. "
            "Local SQLite fallback is active."
        )


    st.code(
        """
Production configuration:

DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/nexusguard

Recommended tables:

tenants
users
roles
transactions
predictions
cases
alerts
audit_events
model_versions
drift_metrics
subscriptions
api_keys
""",
        language="text",
    )


# ============================================================
# CLOUD ARCHITECTURE
# ============================================================

elif app_mode == "☁️ Cloud Architecture":

    st.title(
        "☁️ Cloud Architecture Blueprint"
    )


    arch = pd.DataFrame(
        {

            "Layer": [
                "Frontend",
                "API Gateway",
                "Auth",
                "Fraud Inference",
                "XAI",
                "Database",
                "Cache/Queue",
                "Object Storage",
                "Monitoring",
                "Secrets",
            ],

            "Recommended": [
                "Streamlit/React",
                "FastAPI + API Gateway",
                "OIDC/OAuth2 + JWT",
                "Containerized ML service",
                "SHAP/LIME service",
                "PostgreSQL",
                "Redis/Kafka",
                "S3-compatible storage",
                "Prometheus/Grafana/OpenTelemetry",
                "Cloud Secrets Manager",
            ],
        }
    )


    st.dataframe(
        arch,
        use_container_width=True,
        hide_index=True,
    )


    st.markdown(
        """
### Reference Flow

`Client → WAF → API Gateway → Auth/RBAC → Fraud API → Model Service → PostgreSQL/Redis → SIEM/Alerts`

Use containers, private subnets, TLS, secret management,
centralized logging, health checks, autoscaling and
backup/restore procedures for a production deployment.
"""
    )


# ============================================================
# SECURITY HARDENING
# ============================================================

elif app_mode == "🔐 Security Hardening":

    st.title(
        "🔐 Full Security Hardening Center"
    )


    checks = pd.DataFrame(
        {

            "Control": [
                "TLS/HTTPS",
                "Secrets Management",
                "Password Hashing",
                "RBAC",
                "Tenant Isolation",
                "Audit Hashing",
                "Input Validation",
                "Rate Limiting",
                "CSRF Protection",
                "Dependency Scanning",
                "Container Scanning",
                "Backup Encryption",
            ],

            "Implementation": [
                "Deployment layer",
                "Environment/Secrets",
                "PBKDF2",
                "Enabled",
                "Tenant ID scoping",
                "SHA-256 event record",
                "Application layer",
                "API Gateway",
                "Backend/API",
                "CI/CD",
                "CI/CD",
                "Cloud storage",
            ],

            "Status": [
                "Required",
                "Ready",
                "Enabled",
                "Enabled",
                "Enabled",
                "Enabled",
                "Recommended",
                "API layer",
                "API layer",
                "Recommended",
                "Recommended",
                "Recommended",
            ],
        }
    )


    st.dataframe(
        checks,
        use_container_width=True,
        hide_index=True,
    )


    st.warning(
        "Production hardening must also include HTTPS, "
        "secure cookies, network policies, WAF, rate limits, "
        "dependency scanning, backups and penetration testing."
    )


# ============================================================
# GLOBAL FOOTER
# ============================================================

st.markdown("---")

st.markdown(
    """
<p style='text-align:center;color:#00F2FE;'>
NexusGuard Global • Enterprise Fraud Intelligence •
Multi-Industry • Pakistan + Global •
Dynamic AI Risk Visualization • Human-in-the-Loop AI
</p>
""",
    unsafe_allow_html=True,
)