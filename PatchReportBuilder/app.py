import os
import streamlit as st
import pandas as pd
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from src.parser import parse_json, parse_csv
from src.validator import validate_cves
from src.nvd_client import NVDClient
from src.risk_ranker import rank_vulnerabilities, get_top_vulnerabilities, calculate_statistics
from src.ai_summary import AISummaryEngine
from src.report_generator import generate_markdown_report, generate_pdf_report
from src.charts import create_severity_pie, create_severity_bar, SEVERITY_COLORS

# Set Streamlit Page Configuration
st.set_page_config(
    page_title="AI-Powered Patch & Vulnerability Report Builder",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom premium styling using CSS
st.markdown("""
<style>
    .main {
        background-color: #f8fafc;
    }
    .metric-card {
        background-color: white;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
        text-align: center;
        border-top: 5px solid #64748b;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #1e293b;
        margin-bottom: 5px;
    }
    .metric-label {
        font-size: 0.875rem;
        color: #64748b;
        font-weight: 500;
    }
    .status-box {
        background-color: white;
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 15px;
        border-left: 5px solid #3b82f6;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- SIDEBAR CONFIGURATION -----------------
st.sidebar.title("🛡️ Configuration")
st.sidebar.markdown("---")

# Setup environment overrides directly in UI
st.sidebar.subheader("🔑 API Keys")
api_source = st.sidebar.radio("Load API Keys From:", ("Environment (.env)", "Manual Override"))

if api_source == "Manual Override":
    user_gemini_key = st.sidebar.text_input("Gemini API Key", type="password", help="Enter your Google Gemini API key")
    user_nvd_key = st.sidebar.text_input("NVD API Key", type="password", help="Enter your NVD API key (Optional, but increases rate limits)")
else:
    user_gemini_key = os.getenv("GEMINI_API_KEY", "")
    user_nvd_key = os.getenv("NVD_API_KEY", "")

model_name = st.sidebar.selectbox(
    "Select Gemini Model",
    ("gemini-1.5-flash", "gemini-1.5-pro"),
    index=0
)

st.sidebar.markdown("---")

# API Keys validation indicator
gemini_valid = user_gemini_key and not user_gemini_key.startswith("your_") and len(user_gemini_key) > 10
nvd_valid = user_nvd_key and not user_nvd_key.startswith("your_") and len(user_nvd_key) > 10

st.sidebar.subheader("📡 Connection Status")
if gemini_valid:
    st.sidebar.success("🟢 Gemini API: Configured")
else:
    st.sidebar.warning("🟡 Gemini API: Mock Mode Active")

if nvd_valid:
    st.sidebar.success("🟢 NVD API: Configured (High Limit)")
else:
    st.sidebar.info("🔵 NVD API: Configured (Low Limit)")

st.sidebar.markdown("---")

# Clear cache utilities
if st.sidebar.button("🗑️ Clear Local NVD Cache"):
    cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input", "nvd_cache.json")
    if os.path.exists(cache_path):
        try:
            os.remove(cache_path)
            st.sidebar.success("Cache cleared successfully!")
        except Exception as e:
            st.sidebar.error(f"Error clearing cache: {e}")
    else:
        st.sidebar.info("No cache file found.")

# ----------------- APP HEADER -----------------
st.title("🛡️ AI-Powered Patch/Vulnerability Report Builder")
st.markdown(
    "Transform raw CVE scan exports into high-quality, prioritized, "
    "and executive-ready mitigation briefs using public NVD details and Google Gemini."
)
st.markdown("---")

# ----------------- STATE MANAGEMENT -----------------
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None

# ----------------- A. UPLOAD FILE -----------------
st.header("1. Upload Vulnerability Scan")
uploaded_file = st.file_uploader("Choose a vulnerability scan export file (JSON or CSV)", type=["json", "csv"])

parsed_cves = []
valid_cves = []
invalid_cves = []

if uploaded_file is not None:
    try:
        # Determine file type and parse
        if uploaded_file.name.endswith(".json"):
            parsed_cves = parse_json(uploaded_file)
        elif uploaded_file.name.endswith(".csv"):
            parsed_cves = parse_csv(uploaded_file)
            
        # Validate CVEs
        valid_cves, invalid_cves = validate_cves(parsed_cves)
        
        # Display feedback
        st.success(
            f"Successfully parsed **{len(parsed_cves)}** CVE tags from `{uploaded_file.name}`. "
            f"Found **{len(valid_cves)}** unique valid CVEs."
        )
        
        if invalid_cves:
            with st.expander(f"⚠️ View {len(invalid_cves)} Malformed/Invalid Entries"):
                st.write(invalid_cves)
                
    except Exception as e:
        st.error(f"Failed to process file: {e}")

# ----------------- B. PROCESSING RUNNER -----------------
if valid_cves:
    st.markdown("---")
    st.header("2. Process Report")
    
    col1, col2 = st.columns([1, 4])
    with col1:
        force_refresh = st.checkbox("Force NVD Refresh", value=False, help="Bypass cache and pull fresh data from NVD API")
    with col2:
        start_analysis = st.button("🚀 Analyze Vulnerabilities & Generate Report", type="primary")

    if start_analysis:
        st.session_state.analysis_results = None # Reset previous run
        
        # Initialization
        nvd_client = NVDClient(api_key=user_nvd_key)
        ai_engine = AISummaryEngine(api_key=user_gemini_key, model_name=model_name)
        
        enriched_cves = []
        progress_text = st.empty()
        pbar = st.progress(0.0)
        
        # 1. NVD API Fetching
        status_container = st.container()
        with status_container:
            st.markdown("### 🔍 Enriching CVE Data from NVD...")
            
            total_valid = len(valid_cves)
            for idx, cve_id in enumerate(valid_cves):
                pbar.progress((idx) / total_valid)
                progress_text.text(f"Fetching {cve_id} ({idx + 1}/{total_valid})...")
                
                details = nvd_client.get_cve_details(cve_id, force_refresh=force_refresh)
                enriched_cves.append(details)
                
            pbar.progress(1.0)
            progress_text.text("NVD enrichment complete.")
            st.success("Successfully fetched all CVE details!")
            
        # 2. Sorting and Ranking
        ranked_cves = rank_vulnerabilities(enriched_cves)
        top_20 = get_top_vulnerabilities(ranked_cves, limit=20)
        stats = calculate_statistics(ranked_cves)
        
        # 3. AI Analysis
        ai_analyses = {}
        with st.container():
            st.markdown("### 🧠 Running AI Risk Analysis (Gemini)...")
            ai_pbar = st.progress(0.0)
            ai_progress_text = st.empty()
            
            total_top = len(top_20)
            for idx, item in enumerate(top_20):
                cve_id = item["CVE_ID"]
                ai_pbar.progress((idx) / total_top)
                ai_progress_text.text(f"Analyzing {cve_id} with Gemini ({idx + 1}/{total_top})...")
                
                analysis = ai_engine.analyze_cve(item)
                ai_analyses[cve_id] = analysis
                
            ai_pbar.progress(1.0)
            ai_progress_text.text("AI analyses complete.")
            
        # 4. Generate Executive Summary
        with st.spinner("Writing Executive Summary..."):
            exec_summary = ai_engine.generate_executive_summary(stats, top_20)
            
        # 5. Build Reports
        with st.spinner("Compiling downloadable reports..."):
            markdown_report = generate_markdown_report(stats, top_20, ai_analyses, exec_summary)
            
            pdf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "report.pdf")
            generate_pdf_report(stats, top_20, ai_analyses, exec_summary, pdf_path)
            
            # Write markdown file locally too
            md_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "report.md")
            os.makedirs(os.path.dirname(md_path), exist_ok=True)
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(markdown_report)

        # Save to Session State
        st.session_state.analysis_results = {
            "stats": stats,
            "top_20": top_20,
            "ai_analyses": ai_analyses,
            "executive_summary": exec_summary,
            "markdown_report": markdown_report,
            "pdf_path": pdf_path
        }
        
        # Trigger page refresh to display results
        st.rerun()

# ----------------- DISPLAY RESULTS -----------------
if st.session_state.analysis_results is not None:
    results = st.session_state.analysis_results
    stats = results["stats"]
    top_20 = results["top_20"]
    ai_analyses = results["ai_analyses"]
    exec_summary = results["executive_summary"]
    markdown_report = results["markdown_report"]
    pdf_path = results["pdf_path"]
    
    st.markdown("---")
    st.header("🎯 Dashboard & Insights")
    
    # C. SUMMARY STATISTICS
    col_t, col_c, col_h, col_m, col_l = st.columns(5)
    
    with col_t:
        st.markdown(
            f'<div class="metric-card"><div class="metric-value">{stats["Total"]}</div><div class="metric-label">Total CVEs</div></div>',
            unsafe_allow_html=True
        )
    with col_c:
        st.markdown(
            f'<div class="metric-card" style="border-top-color: {SEVERITY_COLORS["Critical"]}"><div class="metric-value" style="color: {SEVERITY_COLORS["Critical"]}">{stats["Critical"]}</div><div class="metric-label">Critical</div></div>',
            unsafe_allow_html=True
        )
    with col_h:
        st.markdown(
            f'<div class="metric-card" style="border-top-color: {SEVERITY_COLORS["High"]}"><div class="metric-value" style="color: {SEVERITY_COLORS["High"]}">{stats["High"]}</div><div class="metric-label">High</div></div>',
            unsafe_allow_html=True
        )
    with col_m:
        st.markdown(
            f'<div class="metric-card" style="border-top-color: {SEVERITY_COLORS["Medium"]}"><div class="metric-value" style="color: {SEVERITY_COLORS["Medium"]}">{stats["Medium"]}</div><div class="metric-label">Medium</div></div>',
            unsafe_allow_html=True
        )
    with col_l:
        st.markdown(
            f'<div class="metric-card" style="border-top-color: {SEVERITY_COLORS["Low"]}"><div class="metric-value" style="color: {SEVERITY_COLORS["Low"]}">{stats["Low"]}</div><div class="metric-label">Low</div></div>',
            unsafe_allow_html=True
        )
        
    st.ln = st.markdown("<br>", unsafe_allow_html=True) # visual spacer
    
    # 9. VISUALIZATIONS (PLOTLY CHARTS SIDE BY SIDE)
    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        pie_fig = create_severity_pie(stats)
        st.plotly_chart(pie_fig, use_container_width=True)
    with col_chart2:
        bar_fig = create_severity_bar(stats)
        st.plotly_chart(bar_fig, use_container_width=True)
        
    st.markdown("---")
    
    # D. TOP 20 RISK TABLE
    st.subheader("📊 Top 20 Risk Matrix")
    
    # Convert Top 20 to a formatted Pandas DataFrame
    df_rows = []
    for item in top_20:
        df_rows.append({
            "Rank": item["Rank"],
            "CVE ID": item["CVE_ID"],
            "Severity": item["Severity"],
            "CVSS Score": item["CVSS_Score"],
            "Published Date": item["Published_Date"],
            "Status": item["Status"]
        })
        
    df = pd.DataFrame(df_rows)
    st.dataframe(df.set_index("Rank"), use_container_width=True)
    
    st.markdown("---")
    
    # E. EXECUTIVE SUMMARY & DETAILS TAB
    tab_summary, tab_details = st.tabs(["📝 Executive Summary", "🔍 Detailed CVE Deep Dive"])
    
    with tab_summary:
        st.markdown(exec_summary)
        
    with tab_details:
        st.markdown("Below is the detailed vulnerability analysis enriched by NVD and interpreted by Gemini LLM:")
        for item in top_20:
            cve_id = item["CVE_ID"]
            analysis = ai_analyses.get(cve_id, {})
            
            severity_badge_color = SEVERITY_COLORS.get(item["Severity"], "#64748b")
            
            with st.expander(f"{item['Rank']}. {cve_id} — CVSS: {item['CVSS_Score']} ({item['Severity']})"):
                st.markdown(f"**Description:** {item['Description']}")
                
                # Layout the AI columns
                c_imp, c_exp = st.columns(2)
                with c_imp:
                    st.info(f"💼 **Business Impact**\n\n{analysis.get('business_impact', 'N/A')}")
                with c_exp:
                    st.success(f"👥 **Executive-Friendly Explanation**\n\n{analysis.get('executive_explanation', 'N/A')}")
                    
                c_rem, c_pri = st.columns(2)
                with c_rem:
                    st.warning(f"🔧 **Recommended Remediation**\n\n{analysis.get('remediation', 'N/A')}")
                with c_pri:
                    st.error(f"⚖️ **Priority Justification**\n\n{analysis.get('priority_justification', 'N/A')}")
                    
                if item.get("References"):
                    st.markdown("**References:**")
                    for r in item["References"][:4]:
                        st.markdown(f"- [{r}]({r})")

    st.markdown("---")
    
    # F. DOWNLOAD SECTION
    st.subheader("📥 Export Reports")
    col_dl1, col_dl2 = st.columns(2)
    
    with col_dl1:
        st.download_button(
            label="Download Markdown Report (.md)",
            data=markdown_report,
            file_name="Vulnerability_Patch_Report.md",
            mime="text/markdown",
            use_container_width=True
        )
        
    with col_dl2:
        if os.path.exists(pdf_path):
            with open(pdf_path, "rb") as pdf_file:
                pdf_bytes = pdf_file.read()
            st.download_button(
                label="Download PDF Report (.pdf)",
                data=pdf_bytes,
                file_name="Vulnerability_Patch_Report.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        else:
            st.error("PDF Report file not found. Please re-run analysis.")
