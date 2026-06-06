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
    cache_path = os.path.join(os.getcwd(), "input", "nvd_cache.json")
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
                
                analysis = ai_engine.analyze_cve(item) or {}
                ai_analyses[cve_id] = analysis
                
            ai_pbar.progress(1.0)
            ai_progress_text.text("AI analyses complete.")
            
        # 4. Generate Executive Summary
        with st.spinner("Writing Executive Summary..."):
            exec_summary = ai_engine.generate_executive_summary(stats, top_20)
            
        # 5. Build Reports
        with st.spinner("Compiling downloadable reports..."):
            markdown_report = generate_markdown_report(stats, top_20, ai_analyses, exec_summary)
            
            pdf_path = os.path.join(os.getcwd(), "output", "report.pdf")
            generate_pdf_report(stats, top_20, ai_analyses, exec_summary, pdf_path)
            
            # Write markdown file locally too
            md_path = os.path.join(os.getcwd(), "output", "report.md")
            os.makedirs(os.path.dirname(md_path), exist_ok=True)
            with open(md_path, "w", encoding="utf-8") as f:
