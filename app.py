import re
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

# TRACELESS — AI-assisted digital privacy exposure analyser
# Privacy-first demo: submitted text is analysed in memory and is not saved.

st.set_page_config(
    page_title="TRACELESS | Digital Shadow Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- FUTURISTIC UI ----------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root { --cyan:#5cecff; --violet:#a78bfa; --muted:#91a4bd; }
.stApp {
    background:
      radial-gradient(ellipse at 12% 0%, rgba(0,210,255,.13), transparent 34%),
      radial-gradient(ellipse at 88% 10%, rgba(139,92,246,.15), transparent 32%),
      #070b14;
    color:#eaf4ff;
    font-family:'Inter',sans-serif;
}
.block-container {padding-top:2rem; max-width:1250px;}
h1,h2,h3,.brand {font-family:'Space Grotesk',sans-serif;}
.hero {
    padding:25px 28px; border:1px solid rgba(92,236,255,.25);
    border-radius:22px; background:linear-gradient(120deg,rgba(12,32,52,.92),rgba(22,17,48,.88));
    box-shadow:0 0 35px rgba(0,210,255,.08); margin-bottom:18px;
}
.kicker {color:#5cecff; letter-spacing:3px; font-size:11px; font-weight:800;}
.hero h1 {font-size:46px; margin:5px 0 0; letter-spacing:2px;}
.hero p {color:#a8bad0; margin:5px 0 0;}
.metric {
    background:linear-gradient(145deg,rgba(17,31,51,.95),rgba(14,20,38,.95));
    border:1px solid rgba(120,170,220,.18); border-radius:16px;
    padding:17px 18px; min-height:105px;
}
.metric-label {color:#91a4bd; font-size:11px; letter-spacing:1.5px; text-transform:uppercase;}
.metric-value {font-family:'Space Grotesk';font-size:30px;font-weight:700;margin-top:5px;color:#f2fbff;}
.panel {
    background:rgba(13,23,39,.78); border:1px solid rgba(120,170,220,.18);
    border-radius:17px; padding:18px 20px; margin:10px 0;
}
.tag {display:inline-block;padding:4px 9px;border-radius:99px;font-size:11px;
      border:1px solid rgba(92,236,255,.3);color:#5cecff;background:rgba(92,236,255,.08);}
.small-muted {color:#91a4bd;font-size:12px;}
div.stButton > button {
    background:linear-gradient(90deg,#0daec7,#6656d9); color:white; border:0;
    border-radius:12px; padding:.65rem 1.1rem; font-weight:700;
}
div.stButton > button:hover {border:1px solid #5cecff;color:white;box-shadow:0 0 18px rgba(92,236,255,.25);}
[data-testid="stSidebar"] {background:#0a1120;border-right:1px solid rgba(120,170,220,.15);}
textarea {background:#0c1626 !important;color:#eaf4ff !important;}
</style>
""", unsafe_allow_html=True)

# ---------- DETECTION ENGINE ----------
PATTERNS = [
    ("Email address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "HIGH", 22,
     "Email addresses can be used for account discovery, phishing and unwanted contact."),
    ("Phone number", re.compile(r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3,5}\)?[\s.-]?)\d{5,8}(?!\w)"), "HIGH", 24,
     "A phone number can enable unwanted calls, messaging or account-recovery attacks."),
    ("URL / profile link", re.compile(r"\b(?:https?://|www\.)[^\s<>]+", re.I), "MEDIUM", 10,
     "A link may reveal a profile, personal website or other connected information."),
    ("Date of birth / date", re.compile(
        r"\b(?:\d{1,2}[/-]\d{1,2}[/-](?:19|20)?\d{2}|"
        r"(?:0?[1-9]|[12]\d|3[01])\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
        r"(?:\s+(?:19|20)\d{2})?)\b", re.I), "MEDIUM", 14,
     "A birth date can help someone guess security answers or correlate accounts."),
    ("Street address", re.compile(
        r"\b\d{1,5}\s+[A-Z0-9.'-]+(?:\s+[A-Z0-9.'-]+){0,4}\s"
        r"(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Boulevard|Blvd)\b", re.I),
     "CRITICAL", 30, "A street address can expose where someone lives or receives deliveries."),
]

LOCATION_TERMS = [
    "live in", "lives in", "living in", "from", "based in", "stay in", "reside in",
    "located in", "at school in", "near"
]
SCHOOL_TERMS = ["school", "college", "university", "academy", "kendriya vidyalaya", "kv "]
AGE_RE = re.compile(r"\b(?:i am|i'm|aged|age is|turning)\s+(\d{1,2})\b", re.I)
NAME_RE = re.compile(r"\b(?:my name is|i am called|call me)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)", re.I)

def add_finding(findings, category, value, severity, points, explanation, start=-1, end=-1):
    findings.append({
        "category": category, "value": value.strip(".,;:!?()[]{}\"'"),
        "severity": severity, "points": points, "explanation": explanation,
        "start": start, "end": end
    })

def analyse_text(text):
    findings = []
    for category, pattern, severity, points, explanation in PATTERNS:
        for match in pattern.finditer(text):
            add_finding(findings, category, match.group(), severity, points, explanation,
                        match.start(), match.end())

    for match in AGE_RE.finditer(text):
        age = int(match.group(1))
        if 1 <= age <= 110:
            add_finding(findings, "Age reference", match.group(), "MEDIUM", 10,
                        "Age can contribute to identity profiling, especially when combined with other details.",
                        match.start(), match.end())

    for match in NAME_RE.finditer(text):
        add_finding(findings, "Name reference", match.group(1), "MEDIUM", 12,
                    "A name can make it easier to connect this text with a real person.",
                    match.start(1), match.end(1))

    lower = text.lower()
    for term in LOCATION_TERMS:
        idx = lower.find(term)
        if idx >= 0:
            snippet = text[idx:min(len(text), idx + len(term) + 45)].split("\n")[0]
            add_finding(findings, "Possible location clue", snippet, "MEDIUM", 12,
                        "A location phrase may reveal a city, neighbourhood or routine. Review the surrounding text.",
                        idx, min(len(text), idx + len(snippet)))
            break

    for term in SCHOOL_TERMS:
        idx = lower.find(term)
        if idx >= 0:
            snippet = text[max(0, idx-18):min(len(text), idx+42)].strip()
            add_finding(findings, "School / workplace clue", snippet, "MEDIUM", 12,
                        "School or workplace details can help identify a person's routine or community.",
                        max(0, idx-18), min(len(text), idx+42))
            break

    # Remove near-identical duplicate findings while preserving order.
    unique, seen = [], set()
    for item in findings:
        key = (item["category"], item["value"].lower())
        if key not in seen:
            unique.append(item); seen.add(key)
    return unique

def calculate_score(findings):
    # A transparent heuristic score, not a probability of being hacked.
    raw = sum(x["points"] for x in findings)
    return min(100, raw)

def mask_text(text, findings):
    replacements = []
    for f in findings:
        if f["start"] >= 0 and f["end"] > f["start"]:
            replacements.append((f["start"], f["end"], f"[{f['category'].upper()} REMOVED]"))
    # Replace from right to left so indexes remain valid.
    result = text
    for start, end, replacement in sorted(replacements, reverse=True):
        result = result[:start] + replacement + result[end:]
    return result

def risk_label(score):
    if score >= 60: return "HIGH", "A number of identifying clues were found."
    if score >= 30: return "MODERATE", "Some identifying clues were found."
    if score > 0: return "LOW", "A few possible identifying clues were found."
    return "MINIMAL", "No supported pattern was detected. This does not guarantee privacy."

# ---------- SIDEBAR ----------
with st.sidebar:
    st.markdown("## 🛡️ TRACELESS")
    st.markdown("<span class='tag'>PRIVACY INTELLIGENCE // v1.0</span>", unsafe_allow_html=True)
    st.markdown("---")
    page = st.radio("NAVIGATION", ["Scanner", "How it works", "About the project"])
    st.markdown("---")
    st.markdown("**SYSTEM STATUS**")
    st.markdown("🟢 Local analysis active")
    st.markdown("🟢 No account required")
    st.markdown("🟢 Text not stored by this app")
    st.markdown("<p class='small-muted'>Prototype for educational demonstration.</p>", unsafe_allow_html=True)

# ---------- HEADER ----------
st.markdown("""
<div class="hero">
  <div class="kicker">PERSONAL DATA EXPOSURE INTELLIGENCE // 2035</div>
  <h1>TRACELESS<span style="color:#5cecff">.</span></h1>
  <p>Your digital shadow, revealed. Discover the personal information hidden in the text you share.</p>
  <div style="margin-top:14px"><span class="tag">AI-ASSISTED NLP</span> &nbsp; <span class="tag">PRIVACY-FIRST</span> &nbsp; <span class="tag">LIVE TEXT ANALYSIS</span></div>
</div>
""", unsafe_allow_html=True)

if page == "Scanner":
    st.markdown("### ◈ Digital Footprint Scanner")
    st.caption("Paste a bio, caption, message or sample paragraph. Use fictional information for demonstrations.")
    examples = {
        "Choose a sample": "",
        "Sample 1 — Social bio": "Hi, my name is Alex. I am 17 and I study at Central Valley School. I live in Lakeview. Contact me at alex.demo@example.com.",
        "Sample 2 — Contact details": "You can reach me at +1 202-555-0147 or email alex.demo@example.com. My birthday is 12/09/2008.",
        "Sample 3 — Lower exposure": "I enjoy reading science fiction, listening to music and learning Python."
    }
    selected = st.selectbox("LOAD A DEMO EXAMPLE", list(examples.keys()))
    default_text = examples[selected]
    user_text = st.text_area("TEXT INPUT", value=default_text, height=180,
        placeholder="Paste text here to scan for possible personal information...")
    col_a, col_b = st.columns([1, 1])
    with col_a:
        scan = st.button("⚡ SCAN MY DIGITAL SHADOW", use_container_width=True)
    with col_b:
        clear = st.button("CLEAR INPUT", use_container_width=True)

    if clear:
        st.rerun()

    if scan:
        if not user_text.strip():
            st.warning("Enter some text or choose a sample before scanning.")
        else:
            findings = analyse_text(user_text)
            score = calculate_score(findings)
            label, summary = risk_label(score)
            st.session_state["scan_result"] = {
                "text": user_text, "findings": findings, "score": score, "label": label, "summary": summary
            }

    result = st.session_state.get("scan_result")
    if result:
        st.markdown("---")
        st.markdown("### ◈ Scan intelligence report")
        score = result["score"]
        label = result["label"]
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"<div class='metric'><div class='metric-label'>PRIVACY EXPOSURE SCORE</div><div class='metric-value'>{score}<span style='font-size:15px;color:#91a4bd'> / 100</span></div></div>", unsafe_allow_html=True)
        with c2:
            st.markdown(f"<div class='metric'><div class='metric-label'>EXPOSURE LEVEL</div><div class='metric-value' style='color:#5cecff'>{label}</div></div>", unsafe_allow_html=True)
        with c3:
            st.markdown(f"<div class='metric'><div class='metric-label'>POTENTIAL CLUES FOUND</div><div class='metric-value'>{len(result['findings'])}</div></div>", unsafe_allow_html=True)

        st.progress(score / 100, text="Heuristic exposure indicator — not a security probability")
        st.info(result["summary"])

        left, right = st.columns([1.15, .85])
        with left:
            st.markdown("#### Detected information")
            if result["findings"]:
                for i, finding in enumerate(result["findings"], 1):
                    color = {"CRITICAL":"#ff647c","HIGH":"#ff9b62","MEDIUM":"#f6d365","LOW":"#5cecff"}.get(finding["severity"], "#5cecff")
                    st.markdown(
                        f"<div class='panel'><span class='tag'>{finding['severity']}</span>"
                        f"<b style='margin-left:9px'>{i:02d} // {finding['category']}</b>"
                        f"<p style='color:{color};margin:9px 0 4px'>{finding['value']}</p>"
                        f"<p class='small-muted'>{finding['explanation']}</p></div>",
                        unsafe_allow_html=True)
            else:
                st.success("No supported personal-information patterns were detected in this text.")
        with right:
            st.markdown("#### Exposure breakdown")
            if result["findings"]:
                counts = Counter(x["category"] for x in result["findings"])
                fig, ax = plt.subplots(figsize=(5, 3.5))
                fig.patch.set_facecolor("#0d1727")
                ax.set_facecolor("#0d1727")
                ax.barh(list(counts.keys()), list(counts.values()))
                ax.tick_params(colors="#c8d8e8", labelsize=8)
                for spine in ax.spines.values(): spine.set_color("#31445c")
                ax.set_xlabel("Detected clues", color="#91a4bd")
                ax.grid(axis="x", alpha=.15)
                st.pyplot(fig, use_container_width=True)
                plt.close(fig)
            else:
                st.markdown("<div class='panel'>Nothing to chart yet. Try a demo sample.</div>", unsafe_allow_html=True)

        st.markdown("#### ◈ Privacy rewrite")
        st.caption("A simple masking preview. Review it before sharing; masking may remove useful context.")
        st.text_area("SAFER TEXT PREVIEW", value=mask_text(result["text"], result["findings"]), height=120)
        st.download_button("⬇ DOWNLOAD SCAN REPORT (TXT)",
            data=("TRACELESS SCAN REPORT\n"
                  f"Exposure score: {score}/100\nLevel: {label}\n\n"
                  + "\n".join(f"- {x['category']}: {x['value']} ({x['severity']})" for x in result["findings"])
                  + "\n\nNote: This is an educational heuristic, not a guarantee of safety.\n"),
            file_name="traceless_report.txt", mime="text/plain")

    st.markdown("<p class='small-muted'>Privacy note: This prototype analyses text during the current session. It does not intentionally save submitted text to a database. Avoid entering real passwords, financial details, or highly sensitive personal information.</p>", unsafe_allow_html=True)

elif page == "How it works":
    st.markdown("### ◈ Inside the intelligence engine")
    st.markdown("""
    <div class='panel'>
    <h4>01 / INPUT</h4><p class='small-muted'>The user submits a sample bio, caption, message or paragraph.</p>
    <h4>02 / NLP PRE-PROCESSING</h4><p class='small-muted'>The system reads the text and searches for language patterns and structured data.</p>
    <h4>03 / PATTERN RECOGNITION</h4><p class='small-muted'>Regular expressions identify formats such as email addresses, phone numbers and dates. Context rules flag possible age, name, location and school clues.</p>
    <h4>04 / RISK SCORING</h4><p class='small-muted'>Each finding receives a transparent point value. The total is capped at 100 and mapped to an exposure band.</p>
    <h4>05 / RECOMMENDATION</h4><p class='small-muted'>The app creates a masking preview so users can see one way to reduce exposure.</p>
    </div>
    """, unsafe_allow_html=True)
    st.warning("Important technical honesty: Version 1 is an AI-assisted NLP prototype using pattern recognition and rule-based scoring. It does not train a deep-learning model or verify whether a person can actually be identified. Context clues can produce false positives or miss information.")

elif page == "About the project":
    st.markdown("### ◈ Project profile")
    st.markdown("""
    **Project title:** TRACELESS — AI-Powered Digital Footprint & Privacy Exposure Analyser

    **Problem statement:** People may unintentionally reveal personal information in online text. They need a simple tool that highlights possible exposure before sharing.

    **Aim:** To demonstrate how Natural Language Processing and pattern recognition can help users notice personal information in text.

    **Objectives:**
    - Detect selected personal-information patterns.
    - Categorise possible exposure clues.
    - Generate a transparent exposure indicator.
    - Provide a masked-text preview.
    - Encourage privacy-aware online behaviour.

    **Technologies:** Python, Streamlit, regular expressions, pandas and Matplotlib.

    **Limitations:** The tool only detects patterns it has been programmed to recognise. It may miss indirect clues, misunderstand context or flag harmless text. Its score is an educational indicator, not a real-world threat probability.

    **Ethical design:** Use fictional examples in demonstrations. Do not enter passwords, government identity numbers, private medical details or another person's sensitive data.
    """)
    st.markdown("<div class='panel'><span class='kicker'>TRACELESS // BUILD 01</span><h2>Think before you share.</h2><p class='small-muted'>Your privacy is part of your identity.</p></div>", unsafe_allow_html=True)

st.markdown("---")
st.markdown("<center><span class='small-muted'>TRACELESS © 2035 CONCEPT INTERFACE · CLASS XII AI PROJECT PROTOTYPE</span></center>", unsafe_allow_html=True)
