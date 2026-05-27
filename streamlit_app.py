"""
streamlit_app.py — Ransomware AI Early Warning System
=======================================================
Nâng cấp toàn diện so với bản gốc (72 lines → 500+ lines):

Tabs:
  1. 📊 Overview        — KPI cards + label distribution + event timeline
  2. 🔬 Early Detection — Risk score timeline + alert table + detection lead
  3. 🛡️ MITRE Mapping   — ATT&CK matrix + technique breakdown + severity
  4. 📈 Model Analysis  — ROC curves + confusion matrix + feature importance
  5. 🔍 Live Predict    — Upload CSV / nhập tay → predict realtime
  6. 📋 Raw Tables      — Full data tables

Run: streamlit run streamlit_app.py
"""

import os
import io
import warnings
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import joblib
import streamlit as st

warnings.filterwarnings("ignore")

# ============================================================
# CONFIG
# ============================================================
st.set_page_config(
    page_title="Ransomware AI Early Warning",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

METRICS_PATH = "reports/behavior_metrics.csv"
SCORED_PATH  = "reports/behavior_scored_windows.csv"
MITRE_PATH   = "reports/mitre_alerts.csv"
FI_PATH      = "reports/feature_importance.csv"
ROC_PATH     = "reports/roc_data.csv"

MODEL_FILES = {
    "Random Forest":    "models/random_forest_behavior.joblib",
    "XGBoost":          "models/xgboost_behavior.joblib",
    "Isolation Forest": "models/isolation_forest_behavior.joblib",
}

SEVERITY_COLOR = {
    "Critical": "#e74c3c",
    "High":     "#e67e22",
    "Medium":   "#f1c40f",
    "Low":      "#2ecc71",
}

MITRE_COLOR = {
    "T1486": "#e74c3c",
    "T1490": "#c0392b",
    "T1489": "#e67e22",
    "T1112": "#f39c12",
    "T1071": "#3498db",
    "T1622": "#9b59b6",
}

# ============================================================
# HELPERS
# ============================================================

@st.cache_data
def load_csv(path, fallback_cols=None):
    if os.path.exists(path):
        return pd.read_csv(path)
    if fallback_cols:
        return pd.DataFrame(columns=fallback_cols)
    return pd.DataFrame()


@st.cache_resource
def load_models():
    models = {}
    for name, path in MODEL_FILES.items():
        if os.path.exists(path):
            try:
                models[name] = joblib.load(path)
            except Exception as e:
                st.sidebar.warning(f"Cannot load {name}: {e}")
    return models


def kpi_card(col, label, value, delta=None, color="#1f77b4"):
    with col:
        st.markdown(
            f"""
            <div style="background:#1e2130;border-radius:10px;padding:18px 20px;
                        border-left:5px solid {color};margin-bottom:8px">
              <div style="color:#aaa;font-size:13px">{label}</div>
              <div style="color:#fff;font-size:28px;font-weight:700">{value}</div>
              {f'<div style="color:#aaa;font-size:12px">{delta}</div>' if delta else ''}
            </div>
            """,
            unsafe_allow_html=True,
        )


def alert_badge(severity):
    colors = SEVERITY_COLOR
    c = colors.get(severity, "#888")
    return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{severity}</span>'


# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=60)
    st.title("🛡️ Ransomware AI")
    st.caption("Early Warning & Behavior Analysis")
    st.divider()

    st.subheader("⚙️ Thresholds")
    rf_thresh  = st.slider("RF Alert Threshold",  0.0, 1.0, 0.5, 0.05)
    xgb_thresh = st.slider("XGB Alert Threshold", 0.0, 1.0, 0.5, 0.05)
    ens_thresh = st.slider("Ensemble Threshold",  0.0, 1.0, 0.5, 0.05)
    st.divider()

    st.subheader("📂 Data files")
    for path in [METRICS_PATH, SCORED_PATH, MITRE_PATH, FI_PATH, ROC_PATH]:
        icon = "✅" if os.path.exists(path) else "❌"
        st.caption(f"{icon} {os.path.basename(path)}")

    st.divider()
    st.caption("Mô phỏng LockBit 3.0 — MITRE ATT&CK S1202")


# ============================================================
# LOAD DATA
# ============================================================
metrics = load_csv(METRICS_PATH)
scored  = load_csv(SCORED_PATH)
mitre   = load_csv(MITRE_PATH)
fi_df   = load_csv(FI_PATH)
roc_df  = load_csv(ROC_PATH)
models  = load_models()

# Apply thresholds to scored
if len(scored) > 0:
    if "rf_score" in scored.columns:
        scored["rf_alert"]  = (scored["rf_score"]  >= rf_thresh).astype(int)
    if "xgb_score" in scored.columns:
        scored["xgb_alert"] = (scored["xgb_score"] >= xgb_thresh).astype(int)
    if "ensemble_score" in scored.columns:
        scored["ens_alert"] = (scored["ensemble_score"] >= ens_thresh).astype(int)

# ============================================================
# TABS
# ============================================================
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📊 Overview",
    "🔬 Early Detection",
    "🛡️ MITRE Mapping",
    "📈 Model Analysis",
    "🔍 Live Predict",
    "📋 Raw Tables",
])


# ============================================================
# TAB 1 — OVERVIEW
# ============================================================
with tab1:
    st.header("📊 Tổng quan hệ thống")

    if len(scored) > 0:
        total_windows  = len(scored)
        ransom_windows = (scored["label"] == "ransomware").sum() if "label" in scored.columns else 0
        benign_windows = total_windows - ransom_windows
        alert_windows  = scored.get("ens_alert", scored.get("rf_alert", pd.Series([0]*total_windows))).sum()
        lead_val       = scored["rf_detection_lead_events"].dropna().iloc[0] if "rf_detection_lead_events" in scored.columns and scored["rf_detection_lead_events"].notna().any() else "N/A"

        c1, c2, c3, c4, c5 = st.columns(5)
        kpi_card(c1, "Tổng windows",      f"{total_windows:,}",  color="#3498db")
        kpi_card(c2, "Ransomware windows", f"{ransom_windows:,}", color="#e74c3c")
        kpi_card(c3, "Benign windows",     f"{benign_windows:,}", color="#2ecc71")
        kpi_card(c4, "Windows bị alert",   f"{int(alert_windows):,}", color="#e67e22")
        kpi_card(c5, "Detection Lead",
                 f"{int(lead_val)} events" if lead_val != "N/A" else "N/A",
                 delta="sớm hơn ngưỡng 20 files", color="#9b59b6")

        st.divider()

        col_a, col_b = st.columns(2)

        with col_a:
            st.subheader("Phân phối nhãn theo window")
            if "label" in scored.columns:
                label_counts = scored["label"].value_counts().reset_index()
                label_counts.columns = ["label", "count"]
                fig = px.pie(label_counts, names="label", values="count",
                             color="label",
                             color_discrete_map={"ransomware": "#e74c3c", "benign": "#2ecc71"},
                             hole=0.4)
                fig.update_layout(margin=dict(t=20, b=20))
                st.plotly_chart(fig, use_container_width=True)

        with col_b:
            st.subheader("Timeline sự kiện hành vi")
            timeline_cols = [c for c in
                ["file_write_count", "file_rename_count", "dns_query_count",
                 "service_stop_count", "shadow_copy_delete_count"]
                if c in scored.columns]
            if timeline_cols and "first_event_index" in scored.columns:
                fig2 = px.line(scored, x="first_event_index", y=timeline_cols,
                               labels={"value": "count", "first_event_index": "Event index"},
                               color_discrete_sequence=px.colors.qualitative.Bold)
                fig2.update_layout(margin=dict(t=20, b=20), legend_title="Event type")
                st.plotly_chart(fig2, use_container_width=True)

        st.subheader("Entropy trước/sau theo window")
        if "avg_entropy_before" in scored.columns and "avg_entropy_after" in scored.columns:
            ent_df = scored[["first_event_index", "avg_entropy_before", "avg_entropy_after", "label"]].copy()
            fig3 = px.line(ent_df, x="first_event_index",
                           y=["avg_entropy_before", "avg_entropy_after"],
                           color_discrete_map={
                               "avg_entropy_before": "#3498db",
                               "avg_entropy_after":  "#e74c3c",
                           })
            fig3.add_hline(y=7.0, line_dash="dash", line_color="orange",
                           annotation_text="Ngưỡng mã hóa (7.0)")
            st.plotly_chart(fig3, use_container_width=True)
    else:
        st.warning("⚠️ Chưa có data. Chạy pipeline trước:\n```\npython generate_safe_behavior_logs.py\npython build_behavior_features.py\npython train_behavior_models.py\npython mitre_mapping.py\n```")


# ============================================================
# TAB 2 — EARLY DETECTION
# ============================================================
with tab2:
    st.header("🔬 Phát hiện sớm Ransomware")

    if len(scored) > 0:
        # Risk score timeline
        st.subheader("Risk Score Timeline (3 mô hình)")
        score_cols = [c for c in ["rf_score", "xgb_score", "if_score", "ensemble_score"] if c in scored.columns]
        if score_cols and "first_event_index" in scored.columns:
            fig_risk = px.line(
                scored, x="first_event_index", y=score_cols,
                color_discrete_sequence=["#3498db", "#e67e22", "#9b59b6", "#e74c3c"],
                labels={"value": "Risk score", "first_event_index": "Event index"},
            )
            fig_risk.add_hline(y=ens_thresh, line_dash="dash", line_color="#e74c3c",
                               annotation_text=f"Threshold ({ens_thresh})")
            # Mark ransomware zone
            if "label" in scored.columns:
                ransom_start = scored[scored["label"] == "ransomware"]["first_event_index"].min()
                if pd.notna(ransom_start):
                    fig_risk.add_vline(x=ransom_start, line_dash="dot", line_color="red",
                                       annotation_text="Ransomware bắt đầu", annotation_position="top left")
            st.plotly_chart(fig_risk, use_container_width=True)

        # Detection lead metric
        if "rf_detection_lead_events" in scored.columns:
            lead_val = scored["rf_detection_lead_events"].dropna()
            if len(lead_val) > 0:
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("🏆 RF Detection Lead", f"{int(lead_val.iloc[0])} events",
                              help="Phát hiện sớm bao nhiêu events trước khi 20 files bị ảnh hưởng")
                with col2:
                    st.metric("🎯 Ransomware windows detected",
                              f"{scored.get('rf_alert', pd.Series([0]*len(scored))).sum()}")
                with col3:
                    st.metric("⚡ Ensemble alerts",
                              f"{scored.get('ens_alert', pd.Series([0]*len(scored))).sum()}")

        st.divider()

        # Alert table
        st.subheader("Danh sách windows bị cảnh báo")
        alert_cols = [c for c in
            ["window_id", "first_event_index", "label",
             "rf_pred", "rf_score", "xgb_pred", "xgb_score", "if_pred", "if_score",
             "ensemble_score", "ensemble_pred",
             "file_write_count", "file_rename_count", "entropy_spike_count",
             "shadow_copy_delete_count", "lockbit_ext_count"]
            if c in scored.columns]

        alert_mask = (
            scored.get("rf_alert",  pd.Series([0]*len(scored))) == 1
        ) | (
            scored.get("ens_alert", pd.Series([0]*len(scored))) == 1
        )
        alert_df = scored[alert_mask][alert_cols] if any(alert_mask) else scored[alert_cols].head(20)

        st.dataframe(
            alert_df.style.background_gradient(subset=[c for c in ["rf_score","xgb_score","ensemble_score"] if c in alert_df.columns], cmap="Reds"),
            use_container_width=True, height=350
        )

        # Entropy spike scatter
        st.subheader("Phân bố Entropy spike vs File rename")
        if "entropy_spike_count" in scored.columns and "file_rename_count" in scored.columns:
            fig_sc = px.scatter(
                scored,
                x="entropy_spike_count", y="file_rename_count",
                color="label",
                size="affected_file_events" if "affected_file_events" in scored.columns else None,
                color_discrete_map={"ransomware": "#e74c3c", "benign": "#2ecc71"},
                hover_data=["window_id", "rf_score"] if "rf_score" in scored.columns else ["window_id"],
                labels={"entropy_spike_count": "Entropy spikes (>7.0)", "file_rename_count": "File renames"},
            )
            st.plotly_chart(fig_sc, use_container_width=True)
    else:
        st.info("Không có dữ liệu. Chạy pipeline trước.")


# ============================================================
# TAB 3 — MITRE MAPPING
# ============================================================
with tab3:
    st.header("🛡️ MITRE ATT&CK Mapping")

    MITRE_REFERENCE = [
        {"ID": "T1486", "Technique": "Data Encrypted for Impact", "Tactic": "Impact",
         "Feature": "entropy_spike_count, file_rename_count, lockbit_ext_count",
         "Description": "Mã hóa hàng loạt file bằng AES-256/RSA-2048. Entropy file tăng từ ~4.5 lên ~7.8"},
        {"ID": "T1490", "Technique": "Inhibit System Recovery",   "Tactic": "Impact",
         "Feature": "shadow_copy_delete_count",
         "Description": "Xóa Volume Shadow Copies bằng vssadmin, bcdedit để ngăn khôi phục"},
        {"ID": "T1489", "Technique": "Service Stop",              "Tactic": "Impact",
         "Feature": "service_stop_count",
         "Description": "Dừng backup, antivirus, database services trước khi mã hóa"},
        {"ID": "T1112", "Technique": "Modify Registry",           "Tactic": "Defense Evasion",
         "Feature": "registry_set_count",
         "Description": "Vô hiệu hóa Windows Defender, thêm persistence key"},
        {"ID": "T1071", "Technique": "Application Layer Protocol","Tactic": "C2",
         "Feature": "dns_query_count, suspicious_domain_flag",
         "Description": "Liên lạc C2 qua DNS, HTTP/HTTPS với domain ngẫu nhiên"},
        {"ID": "T1622", "Technique": "Debugger Evasion",          "Tactic": "Defense Evasion",
         "Feature": "unique_process_count",
         "Description": "Phát hiện và thoát khỏi môi trường sandbox / debugger"},
    ]

    col1, col2 = st.columns([3, 2])

    with col1:
        st.subheader("ATT&CK Techniques Reference")
        ref_df = pd.DataFrame(MITRE_REFERENCE)
        st.dataframe(ref_df, use_container_width=True, height=280)

    with col2:
        if len(mitre) > 0 and "technique_id" in mitre.columns:
            st.subheader("Tần suất technique bị kích hoạt")
            tech_counts = mitre["technique_id"].value_counts().reset_index()
            tech_counts.columns = ["technique_id", "count"]
            tech_counts["color"] = tech_counts["technique_id"].map(MITRE_COLOR).fillna("#888")
            fig_tc = px.bar(tech_counts, x="technique_id", y="count",
                            color="technique_id",
                            color_discrete_map=MITRE_COLOR,
                            text="count")
            fig_tc.update_layout(showlegend=False, margin=dict(t=20, b=20))
            st.plotly_chart(fig_tc, use_container_width=True)

    st.divider()

    if len(mitre) > 0:
        # Severity breakdown
        st.subheader("Phân bố mức độ nghiêm trọng (Severity)")
        col_sev1, col_sev2 = st.columns(2)
        with col_sev1:
            if "severity" in mitre.columns:
                sev_counts = mitre["severity"].value_counts().reset_index()
                sev_counts.columns = ["severity", "count"]
                fig_sev = px.bar(sev_counts, x="severity", y="count",
                                 color="severity",
                                 color_discrete_map=SEVERITY_COLOR,
                                 text="count")
                fig_sev.update_layout(showlegend=False)
                st.plotly_chart(fig_sev, use_container_width=True)

        with col_sev2:
            if "risk_score" in mitre.columns and "technique_id" in mitre.columns:
                fig_box = px.box(mitre, x="technique_id", y="risk_score",
                                 color="technique_id",
                                 color_discrete_map=MITRE_COLOR,
                                 labels={"risk_score": "Risk Score", "technique_id": "Technique"},
                                 title="Risk score phân phối theo technique")
                fig_box.update_layout(showlegend=False)
                st.plotly_chart(fig_box, use_container_width=True)

        st.subheader("Chi tiết MITRE Alerts")
        display_cols = [c for c in
            ["window_id", "first_event_idx", "technique_id", "technique",
             "tactic", "severity", "risk_score", "evidence_detail", "explanation"]
            if c in mitre.columns]
        st.dataframe(mitre[display_cols], use_container_width=True, height=300)
    else:
        st.info("Chưa có MITRE alerts. Chạy mitre_mapping.py trước.")


# ============================================================
# TAB 4 — MODEL ANALYSIS
# ============================================================
with tab4:
    st.header("📈 Phân tích mô hình AI")

    col1, col2 = st.columns(2)

    # Metrics table
    with col1:
        st.subheader("Bảng so sánh hiệu năng")
        if len(metrics) > 0:
            st.dataframe(
                metrics.style.highlight_max(
                    subset=[c for c in ["f1", "precision", "recall", "auc_roc"] if c in metrics.columns],
                    color="#2ecc71"
                ).highlight_min(
                    subset=[c for c in ["false_positive_rate"] if c in metrics.columns],
                    color="#2ecc71"
                ),
                use_container_width=True,
            )
        else:
            st.info("Chưa có metrics.")

    # ROC curves
    with col2:
        st.subheader("ROC Curves")
        if len(roc_df) > 0 and "fpr" in roc_df.columns:
            fig_roc = px.line(roc_df, x="fpr", y="tpr", color="model",
                              color_discrete_sequence=["#3498db", "#e67e22", "#9b59b6"],
                              labels={"fpr": "False Positive Rate", "tpr": "True Positive Rate"})
            fig_roc.add_shape(type="line", x0=0, y0=0, x1=1, y1=1,
                              line=dict(dash="dash", color="gray"))
            fig_roc.update_layout(margin=dict(t=20, b=20))
            st.plotly_chart(fig_roc, use_container_width=True)
        else:
            st.info("Chưa có ROC data.")

    # Feature importance
    st.divider()
    st.subheader("Feature Importance (Random Forest) — Top 15")
    if len(fi_df) > 0 and "feature" in fi_df.columns:
        top_fi = fi_df.head(15)
        fig_fi = px.bar(top_fi.sort_values("importance"),
                        x="importance", y="feature", orientation="h",
                        color="importance",
                        color_continuous_scale="Reds",
                        labels={"importance": "Importance score", "feature": ""})
        fig_fi.update_layout(coloraxis_showscale=False, margin=dict(t=10, b=10))
        st.plotly_chart(fig_fi, use_container_width=True)
    else:
        st.info("Chưa có feature importance.")

    # Model explanation
    st.divider()
    st.subheader("Mô tả các mô hình")
    model_info = {
        "Random Forest": {
            "icon": "🌲",
            "desc": "Ensemble 200 cây quyết định. Phù hợp phát hiện hành vi bất thường có nhãn (supervised). "
                    "Tốt nhất cho classification với feature importance rõ ràng.",
            "params": "n_estimators=200, max_depth=12, class_weight=balanced",
        },
        "XGBoost": {
            "icon": "⚡",
            "desc": "Gradient boosting. Xử lý tốt imbalanced data với scale_pos_weight. "
                    "Thường cho AUC-ROC cao nhất trong bộ 3.",
            "params": "n_estimators=300, max_depth=5, learning_rate=0.05",
        },
        "Isolation Forest": {
            "icon": "🔍",
            "desc": "Unsupervised anomaly detection. Chỉ train trên benign data. "
                    "Phù hợp khi không có nhãn ransomware, phát hiện outlier.",
            "params": "n_estimators=300, contamination=0.15",
        },
    }
    cols = st.columns(3)
    for i, (name, info) in enumerate(model_info.items()):
        with cols[i]:
            st.markdown(f"""
            <div style="background:#1e2130;border-radius:10px;padding:16px;height:180px">
              <div style="font-size:24px">{info['icon']} <b>{name}</b></div>
              <div style="color:#ccc;font-size:13px;margin-top:8px">{info['desc']}</div>
              <div style="color:#888;font-size:11px;margin-top:8px;font-family:monospace">{info['params']}</div>
            </div>
            """, unsafe_allow_html=True)


# ============================================================
# TAB 5 — LIVE PREDICT
# ============================================================
with tab5:
    st.header("🔍 Live Prediction")
    st.caption("Nhập thông số hành vi hoặc upload CSV để dự đoán realtime")

    if not models:
        st.error("❌ Không tìm thấy model. Chạy train_behavior_models.py trước.")
    else:
        method = st.radio("Phương thức nhập", ["✏️ Nhập tay", "📁 Upload CSV"], horizontal=True)

        FEATURE_COLS = [
            "file_read_count", "file_write_count", "file_rename_count", "file_delete_count",
            "shadow_copy_delete_count", "service_stop_count", "registry_set_count",
            "dns_query_count", "network_connect_count", "process_create_count",
            "unique_object_count", "unique_process_count", "unique_extension_count",
            "total_bytes_written", "avg_entropy_before", "avg_entropy_after",
            "entropy_delta", "max_entropy_after",
            "rename_burst_score", "write_burst_score", "rename_to_write_ratio",
            "entropy_spike_count", "high_entropy_flag", "lockbit_ext_count",
            "suspicious_domain_flag", "defense_evasion_score", "affected_file_events",
        ]

        if method == "✏️ Nhập tay":
            st.subheader("Điền thông số (window 50 events)")

            with st.form("predict_form"):
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.markdown("**📁 File operations**")
                    file_write   = st.number_input("file_write_count",   0, 10000, 50)
                    file_rename  = st.number_input("file_rename_count",  0, 10000, 30)
                    file_read    = st.number_input("file_read_count",    0, 10000, 10)
                    file_delete  = st.number_input("file_delete_count",  0, 10000, 0)

                with c2:
                    st.markdown("**🛡️ Defense Evasion**")
                    shadow_del   = st.number_input("shadow_copy_delete", 0, 100, 0)
                    svc_stop     = st.number_input("service_stop_count", 0, 100, 0)
                    reg_set      = st.number_input("registry_set_count", 0, 200, 0)

                with c3:
                    st.markdown("**🌐 Network & Process**")
                    dns_q        = st.number_input("dns_query_count",    0, 1000, 2)
                    net_conn     = st.number_input("network_connect",    0, 1000, 2)
                    proc_create  = st.number_input("process_create",     0, 500,  1)

                c4, c5 = st.columns(2)
                with c4:
                    st.markdown("**📊 Entropy**")
                    ent_before = st.slider("avg_entropy_before", 0.0, 8.0, 4.0, 0.1)
                    ent_after  = st.slider("avg_entropy_after",  0.0, 8.0, 4.5, 0.1)
                    max_ent    = st.slider("max_entropy_after",  0.0, 8.0, 5.0, 0.1)
                with c5:
                    st.markdown("**🔢 Derived**")
                    lockbit_ext = st.number_input("lockbit_ext_count",   0, 1000, 0)
                    susp_domain = st.selectbox("suspicious_domain_flag", [0, 1])
                    uniq_ext    = st.number_input("unique_extension_count", 1, 20, 5)
                    total_bytes = st.number_input("total_bytes_written (KB)", 0, 100000, 100) * 1000

                submitted = st.form_submit_button("🚀 Predict", use_container_width=True)

            if submitted:
                total_file = max(file_read + file_write + file_rename, 1)
                input_data = {
                    "file_read_count":        file_read,
                    "file_write_count":       file_write,
                    "file_rename_count":      file_rename,
                    "file_delete_count":      file_delete,
                    "shadow_copy_delete_count": shadow_del,
                    "service_stop_count":     svc_stop,
                    "registry_set_count":     reg_set,
                    "dns_query_count":        dns_q,
                    "network_connect_count":  net_conn,
                    "process_create_count":   proc_create,
                    "unique_object_count":    file_write + file_read,
                    "unique_process_count":   2,
                    "unique_extension_count": uniq_ext,
                    "total_bytes_written":    total_bytes,
                    "avg_entropy_before":     ent_before,
                    "avg_entropy_after":      ent_after,
                    "entropy_delta":          max(0, ent_after - ent_before),
                    "max_entropy_after":      max_ent,
                    "rename_burst_score":     file_rename / total_file,
                    "write_burst_score":      file_write / max(50, 1),
                    "rename_to_write_ratio":  file_rename / max(file_write, 1),
                    "entropy_spike_count":    1 if ent_after > 7.0 else 0,
                    "high_entropy_flag":      1 if (ent_after - ent_before) > 2.0 or ent_after > 7.0 else 0,
                    "lockbit_ext_count":      lockbit_ext,
                    "suspicious_domain_flag": susp_domain,
                    "defense_evasion_score":  shadow_del * 3 + svc_stop * 2 + reg_set,
                    "affected_file_events":   file_write + file_rename + file_delete,
                }

                st.divider()
                st.subheader("🎯 Kết quả dự đoán")
                pred_cols = st.columns(len(models))
                probs = []

                for i, (model_name, model_obj) in enumerate(models.items()):
                    try:
                        fc = model_obj.get("feature_cols", list(input_data.keys()))
                        row_df = pd.DataFrame([input_data]).reindex(columns=fc, fill_value=0)
                        mdl = model_obj["model"]

                        if hasattr(mdl, "predict_proba"):
                            prob = mdl.predict_proba(row_df)[0][1]
                        else:
                            raw = mdl.predict(row_df)[0]
                            score = -mdl.score_samples(row_df)[0]
                            prob = min(score / 3.0, 1.0)

                        probs.append(prob)
                        label = "🚨 RANSOMWARE" if prob > 0.5 else "✅ BENIGN"
                        color = "#e74c3c" if prob > 0.5 else "#2ecc71"

                        with pred_cols[i]:
                            st.markdown(f"""
                            <div style="background:#1e2130;border-radius:10px;padding:16px;text-align:center">
                              <div style="color:#aaa;font-size:13px">{model_name}</div>
                              <div style="color:{color};font-size:26px;font-weight:700">{label}</div>
                              <div style="color:#fff;font-size:20px">{prob:.1%}</div>
                            </div>
                            """, unsafe_allow_html=True)
                    except Exception as e:
                        with pred_cols[i]:
                            st.error(f"{model_name}: {e}")

                # Ensemble
                if probs:
                    ens = sum(probs) / len(probs)
                    st.markdown(f"""
                    <div style="background:#1e2130;border-radius:12px;padding:20px;text-align:center;margin-top:16px;
                                border:2px solid {'#e74c3c' if ens > 0.5 else '#2ecc71'}">
                      <div style="color:#aaa">Ensemble Score</div>
                      <div style="color:{'#e74c3c' if ens > 0.5 else '#2ecc71'};font-size:36px;font-weight:700">
                        {'🚨 RANSOMWARE DETECTED' if ens > 0.5 else '✅ NORMAL BEHAVIOR'}
                      </div>
                      <div style="color:#fff;font-size:22px">{ens:.1%} confidence</div>
                    </div>
                    """, unsafe_allow_html=True)

                    # Gauge chart
                    fig_gauge = go.Figure(go.Indicator(
                        mode="gauge+number",
                        value=ens * 100,
                        title={"text": "Ransomware Risk Score"},
                        gauge={
                            "axis": {"range": [0, 100]},
                            "bar": {"color": "#e74c3c" if ens > 0.5 else "#2ecc71"},
                            "steps": [
                                {"range": [0, 40],  "color": "#1e3a2f"},
                                {"range": [40, 70], "color": "#3a2a1e"},
                                {"range": [70, 100],"color": "#3a1e1e"},
                            ],
                            "threshold": {"line": {"color": "white", "width": 3}, "value": 50},
                        },
                        number={"suffix": "%"},
                    ))
                    fig_gauge.update_layout(height=300, margin=dict(t=40, b=10))
                    st.plotly_chart(fig_gauge, use_container_width=True)

        else:  # Upload CSV
            uploaded = st.file_uploader("Upload file CSV chứa behavior features", type=["csv"])
            if uploaded:
                try:
                    up_df = pd.read_csv(uploaded)
                    st.write(f"Đọc {len(up_df)} rows, {up_df.shape[1]} columns")
                    st.dataframe(up_df.head(5))

                    if st.button("🚀 Run Prediction"):
                        result_rows = []
                        for _, model_obj in models.items():
                            name = list(models.keys())[list(models.values()).index(model_obj)]
                            fc   = model_obj.get("feature_cols", [])
                            available = [c for c in fc if c in up_df.columns]
                            if not available:
                                continue
                            X_up = up_df.reindex(columns=fc, fill_value=0)
                            mdl  = model_obj["model"]
                            if hasattr(mdl, "predict_proba"):
                                probs_up = mdl.predict_proba(X_up)[:, 1]
                            else:
                                probs_up = (-mdl.score_samples(X_up))
                                probs_up = (probs_up - probs_up.min()) / max(probs_up.max() - probs_up.min(), 1e-9)
                            up_df[f"{name.replace(' ','_')}_score"] = probs_up
                            up_df[f"{name.replace(' ','_')}_pred"]  = (probs_up > 0.5).astype(int)

                        st.success("✅ Prediction hoàn tất!")
                        st.dataframe(up_df, use_container_width=True)

                        csv_out = up_df.to_csv(index=False).encode("utf-8")
                        st.download_button("⬇️ Download kết quả CSV", csv_out,
                                           "prediction_result.csv", "text/csv")
                except Exception as e:
                    st.error(f"Lỗi: {e}")


# ============================================================
# TAB 6 — RAW TABLES
# ============================================================
with tab6:
    st.header("📋 Raw Data Tables")

    with st.expander("📊 Model Metrics", expanded=True):
        if len(metrics) > 0:
            st.dataframe(metrics, use_container_width=True)
        else:
            st.info("No data")

    with st.expander("🔬 Scored Windows"):
        if len(scored) > 0:
            st.dataframe(scored, use_container_width=True, height=400)
            csv = scored.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download scored_windows.csv", csv,
                               "scored_windows.csv", "text/csv")

    with st.expander("🛡️ MITRE Alerts"):
        if len(mitre) > 0:
            st.dataframe(mitre, use_container_width=True, height=400)
            csv2 = mitre.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download mitre_alerts.csv", csv2,
                               "mitre_alerts.csv", "text/csv")

    with st.expander("📈 Feature Importance"):
        if len(fi_df) > 0:
            st.dataframe(fi_df, use_container_width=True)
