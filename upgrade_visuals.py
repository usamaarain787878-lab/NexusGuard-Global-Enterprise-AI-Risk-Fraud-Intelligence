from pathlib import Path

APP = Path("app.py")
BACKUP = Path("app_backup_visuals.py")

source = APP.read_text(encoding="utf-8")

if not BACKUP.exists():
    BACKUP.write_text(source, encoding="utf-8")

# ============================================================
# UNIVERSAL ENTERPRISE VISUALIZATION ENGINE
# ============================================================

visual_engine = r'''

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


'''

# Insert visualization engine before localization section.
marker = "# ============================================================\n# LOCALIZATION"

if "NEXUSGUARD ENTERPRISE VISUALIZATION ENGINE" not in source:
    source = source.replace(
        marker,
        visual_engine + "\n\n" + marker,
        1
    )

# ============================================================
# ADD PREDICTION HISTORY MODULE
# ============================================================

navigation_old = '''    "📊 ML Monitoring & Drift",'''

navigation_new = '''    "📊 ML Monitoring & Drift",

    "🕘 Prediction History",'''

if '"🕘 Prediction History"' not in source:
    source = source.replace(
        navigation_old,
        navigation_new,
        1
    )

# ============================================================
# EXECUTIVE DASHBOARD VISUALS
# ============================================================

executive_marker = '''    st.markdown(
        "### 🧭 Enterprise Capability Map"
    )'''

executive_visuals = r'''
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

'''

if executive_marker in source and "executive_3d_risk" not in source:
    source = source.replace(
        executive_marker,
        executive_visuals + "\n" + executive_marker,
        1
    )

# ============================================================
# CUSTOMER BEHAVIOR VISUALS
# ============================================================

customer_marker = '''    st.dataframe(
        behavioral,
        use_container_width=True,
        hide_index=True,
    )'''

customer_visuals = r'''

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
'''

if "customer_behavior_3d" not in source:
    source = source.replace(
        customer_marker,
        customer_marker + customer_visuals,
        1
    )

# ============================================================
# DEVICE VISUALS
# ============================================================

device_marker = '''    if risk >= 60:

        st.warning(
            "High device/session anomaly. "
            "Route to investigation or "
            "step-up authentication."
        )'''

device_visuals = r'''

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
'''

if "device_session_3d" not in source:
    source = source.replace(
        device_marker,
        device_marker + device_visuals,
        1
    )

# ============================================================
# THREAT INTELLIGENCE VISUALS
# ============================================================

threat_marker = '''        st.info(
            "For live threat intelligence, configure "
            "provider API credentials through Streamlit "
            "Secrets/environment variables."
        )'''

threat_visuals = r'''

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
'''

if "threat_intelligence_3d" not in source:
    source = source.replace(
        threat_marker,
        threat_marker + threat_visuals,
        1
    )

# ============================================================
# ALERT VISUALS
# ============================================================

alerts_marker = '''    else:

        st.info(
            "No alerts generated yet."
        )'''

alerts_visuals = r'''

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
'''

if "alerts_3d" not in source:
    source = source.replace(
        alerts_marker,
        alerts_marker + alerts_visuals,
        1
    )

# ============================================================
# CASE VISUALS
# ============================================================

case_marker = '''    if st.button(
        "➕ Open Case",
        type="primary",
    ):'''

case_visuals = r'''

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
'''

if "case_management_3d" not in source:
    source = source.replace(
        case_marker,
        case_visuals + "\n" + case_marker,
        1
    )

# ============================================================
# BULK SCANNER VISUALS
# ============================================================

bulk_marker = '''            st.download_button(
                "📥 Download Scanned Report",
                df.to_csv(index=False),
                "nexusguard_batch_report.csv",
                "text/csv",
            )'''

bulk_visuals = r'''

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
'''

if "bulk_scanner_3d" not in source:
    source = source.replace(
        bulk_marker,
        bulk_marker + bulk_visuals,
        1
    )

# ============================================================
# ML MONITORING VISUALS
# ============================================================

ml_marker = '''    st.warning(
        "Model-quality metrics above are demonstration "
        "telemetry until connected to your production "
        "evaluation pipeline."
    )'''

ml_visuals = r'''

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
'''

if "ml_monitoring_3d" not in source:
    source = source.replace(
        ml_marker,
        ml_visuals + "\n" + ml_marker,
        1
    )

# ============================================================
# ROI VISUALS
# ============================================================

roi_marker = '''    st.caption(
        "Scenario analysis only; actual ROI depends on "
        "measured baseline loss, prevention rate, "
        "operational cost and false positives."
    )'''

roi_visuals = r'''

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
'''

if "roi_simulator_3d" not in source:
    source = source.replace(
        roi_marker,
        roi_visuals + "\n" + roi_marker,
        1
    )

# ============================================================
# SECURITY VISUALS
# ============================================================

security_marker = '''    st.warning(
        "Production hardening must also include HTTPS, "
        "secure cookies, WAF, rate limits, "
        "dependency scanning, backups and penetration testing."
    )'''

security_visuals = r'''

    # ========================================================
    # SECURITY CONTROL COVERAGE
    # ========================================================

    security_map = {
        "Enabled": 100,
        "Ready": 90,
        "Configured": 85,
        "API layer": 70,
        "Deployment layer": 70,
        "Environment/Secrets": 90,
        "Tenant ID scoping": 95,
        "SHA-256 event record": 95,
        "Application layer": 85,
        "Recommended": 50,
        "CI/CD": 65,
        "Cloud storage": 70,
    }

    security_visual = checks.copy()

    security_visual["Coverage"] = (
        security_visual["Status"]
        .map(security_map)
        .fillna(50)
    )

    security_visual["Control Index"] = np.arange(
        1,
        len(security_visual) + 1
    )

    security_visual["Residual Risk"] = (
        100 - security_visual["Coverage"]
    )

    st.plotly_chart(
        px.bar(
            security_visual.sort_values(
                "Coverage"
            ),
            x="Coverage",
            y="Control",
            orientation="h",
            template="plotly_dark",
            title="Security Control Coverage",
            text="Coverage",
        ),
        use_container_width=True,
        key="security_coverage_bar",
    )

    render_enterprise_3d_and_bar(
        security_visual,
        "Security Hardening Center",
        category_col="Status",
        value_col="Coverage",
        x_col="Control Index",
        y_col="Coverage",
        z_col="Residual Risk",
        key_prefix="security_hardening",
    )
'''

if "security_hardening_3d" not in source:
    source = source.replace(
        security_marker,
        security_visuals + "\n" + security_marker,
        1
    )

# ============================================================
# REPORT VISUALIZATION DATA
# ============================================================

report_marker = '''        "database":
            db_backend(),
    }'''

report_upgrade = r'''        "database":
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
'''

if '"visualization_summary"' not in source:
    source = source.replace(
        report_marker,
        report_upgrade,
        1
    )

# ============================================================
# PREDICTION HISTORY MODULE
# ============================================================

history_module = r'''

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

'''

# Insert before XAI branch.
xai_marker = '''# ============================================================
# XAI
# ============================================================'''

if '"🕘 Prediction History"' in source and "Historical Risk Intelligence" not in source:
    source = source.replace(
        xai_marker,
        history_module + "\n\n" + xai_marker,
        1
    )

# ============================================================
# WRITE
# ============================================================

APP.write_text(
    source,
    encoding="utf-8"
)

print("")
print("=" * 70)
print("NEXUSGUARD VISUAL UPGRADE COMPLETE")
print("=" * 70)
print("")
print("Backup created:")
print("  app_backup_visuals.py")
print("")
print("Updated:")
print("  app.py")
print("")
print("Added enterprise visualization engine:")
print("  3D Risk Maps")
print("  Risk/Security/Threat Bar Charts")
print("  Executive Risk Landscape")
print("  Customer Behavior 3D")
print("  Device & Session 3D")
print("  Threat Intelligence 3D")
print("  Real-Time Alert 3D")
print("  Case Management 3D")
print("  Bulk Scanner 3D")
print("  ML Monitoring 3D")
print("  ROI Financial Charts")
print("  Security Coverage Charts")
print("  Prediction History 3D")
print("  Prediction History Module")
print("")
print("=" * 70)