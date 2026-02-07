import streamlit as st
import requests
import google.generativeai as genai
from fpdf import FPDF # type: ignore
import os
from dotenv import load_dotenv # type: ignore

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")


# ---------- CONFIG ---------

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-3-flash-preview")



st.set_page_config(page_title="Cyber Risk Intelligence", layout="wide")

st.title("🛡️ Cyber Risk Intelligence Platform")

# ---------- INPUT ----------

software = st.text_input("Software Name (e.g. WordPress, Apache)")
cves=[]
company_size = st.selectbox("Company Size", ["Startup","SME","Enterprise"])

# ---------- CVE FETCH ----------

def get_cves(keyword):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    headers = {
        "apiKey": NVD_API_KEY,
        "User-Agent": "cyber-risk-app"
    }

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5
    }

    try:
        r = requests.get(url, headers=headers, params=params)
        data = r.json()

        return data.get("vulnerabilities", [])

    except Execption as e: # type: ignore
        st.error("⚠️ Could not fetch CVE data")
        return []


# ---------- MAIN ----------

if st.button("Run Risk Intelligence"):
    risk_score=0
    owasp_tags=[]
    cvss_scores=[]
    avg_cvss=0

    cves = get_cves(software)

    if not cves:
     st.warning("No CVEs found")
    else:
     st.subheader("🔍 Live CVEs")

    for item in cves:
        cve = item["cve"]

        cve_id = cve["id"]
        desc = cve["descriptions"][0]["value"]

        score = "N/A"
        severity = "N/A"

        if "metrics" in cve and "cvssMetricV31" in cve["metrics"]:
            metric = cve["metrics"]["cvssMetricV31"][0]
            score = metric["cvssData"]["baseScore"]
            severity = metric["cvssData"]["baseSeverity"]
            cvss_scores.append(float(score))
            
        st.markdown(f"""
        **{cve_id}**
        - Severity: {severity}
        - Score: {score}
        - {desc[:200]}...
        """)

    if cvss_scores:
     avg_cvss = sum(cvss_scores) / len(cvss_scores)
    else:
     avg_cvss = 0

    st.write(f"📊 Average CVSS: {round(avg_cvss,2)}")


    # ---------- OWASP ----------

    if "login" in software.lower():
        owasp_tags.append("A07 Authentication Failures")
        risk_score += 2

    if "payment" in software.lower():
        owasp_tags.append("A02 Cryptographic Failures")
        risk_score += 3

    # ---------- HUMAN VALIDATION ----------

    st.subheader("👨‍💻 Analyst Validation")

    confidence = st.slider("Analyst Confidence %",0,100,80)
    final_score = int((risk_score + avg_cvss)/2 * confidence/100)
    


    # ---------- RISK LEVEL ----------

    if final_score<4:
        level="LOW"
    elif final_score<7:
        level="MEDIUM"
    else:
        level="HIGH"
    st.session_state.final_score = final_score
    st.session_state.level = level # type: ignore

    # ---------- DASHBOARD ----------

    col1,col2,col3 = st.columns(3)

    col1.metric("Final Risk Score", f"{final_score}/10")
    col2.metric("Avg CVSS", avg_cvss)
    col3.metric("Risk Level", level)

    st.progress(final_score/10)

    # ---------- ATTACK CHAIN ----------

    st.subheader("⚔️ Likely Attack Chain")

    chain = [
        "Reconnaissance",
        "Initial Access",
        "Privilege Escalation",
        "Lateral Movement",
        "Data Exfiltration"
    ]

    for step in chain:
        st.write("➡️", step)

    # ---------- AI ANALYSIS ----------

    prompt=f"""
    You are a senior cybersecurity SOC analyst.

    Software: {software}
    Company Size: {company_size}
    Risk Score: {final_score}/10
    Average CVSS: {avg_cvss}

    Provide:
    • Realistic attack scenario
    • Business impact
    • Defensive actions
    Keep it professional and concise.
    """

    response = model.generate_content(prompt)

    st.subheader("🤖 AI Threat Brief")
    st.write(response.text)




