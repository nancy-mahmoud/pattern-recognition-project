import streamlit as st
import pandas as pd
import numpy as np
import pickle
import warnings
from urllib.parse import urlparse
from feature_extractor import FeatureExtractor

warnings.filterwarnings('ignore')

# RULE-BASED TYPOSQUATTING / HOMOGLYPH PRE-CHECK
_HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '6': 'g', '7': 't', '8': 'b', '@': 'a',
}

_KNOWN_BRANDS = [
    'google', 'facebook', 'amazon', 'apple', 'microsoft',
    'github', 'stackoverflow', 'reddit', 'paypal', 'twitter',
    'instagram', 'linkedin', 'netflix', 'youtube', 'yahoo',
    'ebay', 'dropbox', 'adobe', 'office', 'outlook',
    'gmail', 'icloud', 'chase', 'wellsfargo', 'stripe',
    'coinbase', 'americanexpress', 'bankofamerica', 'steam',
    'twitch', 'discord', 'spotify', 'samsung', 'nvidia',
]

def _normalize(text):
    s = text.replace('vv', 'w').replace('rn', 'm')
    for fake, real in _HOMOGLYPH_MAP.items():
        s = s.replace(fake, real)
    return s

def check_typosquatting(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(':')[0].lstrip('www.')
        sld = domain.split('.')[0]
        normalized_sld = _normalize(sld)
        for brand in _KNOWN_BRANDS:
            if sld == brand:
                continue
            if normalized_sld == brand:
                return True, brand
            if brand in normalized_sld and brand not in sld:
                return True, brand
        return False, None
    except Exception:
        return False, None

_SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'banking', 
    'auth', 'confirm', 'support', 'service', 'recover', 'unlock', 'wallet'
]
_SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.cc', '.cn']

def check_suspicious_heuristics(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(':')[0].lstrip('www.')
        
        for tld in _SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return True, f"Suspicious Top-Level Domain ({tld})"
                
        matched_kws = [kw for kw in _SUSPICIOUS_KEYWORDS if kw in domain.replace('-', '')]
        if len(matched_kws) >= 2:
            return True, f"Multiple phishing keywords ({', '.join(matched_kws)})"
            
        return False, None
    except Exception:
        return False, None

# PAGE CONFIG
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# GLOBAL CSS — Dark premium cybersecurity theme
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

/* ── Base reset ── */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background: linear-gradient(135deg, #0a0e1a 0%, #0d1526 40%, #0a1020 100%);
    min-height: 100vh;
}

/* ── Hide default Streamlit chrome ── */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 2rem 3rem 3rem 3rem; max-width: 1100px; }

/* ── Hero header ── */
.hero {
    text-align: center;
    padding: 3rem 1rem 2rem 1rem;
}
.hero-badge {
    display: inline-block;
    background: linear-gradient(90deg, rgba(37,99,235,0.2), rgba(29,78,216,0.2));
    border: 1px solid rgba(37,99,235,0.45);
    color: #93c5fd;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    padding: 0.35rem 1rem;
    border-radius: 100px;
    margin-bottom: 1.2rem;
}
.hero-title {
    font-size: 3.2rem;
    font-weight: 800;
    background: linear-gradient(135deg, #dbeafe 0%, #93c5fd 50%, #3b82f6 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    line-height: 1.15;
    margin-bottom: 1rem;
}
.hero-sub {
    color: #64748b;
    font-size: 1.05rem;
    font-weight: 400;
    max-width: 540px;
    margin: 0 auto 2.5rem auto;
    line-height: 1.6;
}

/* ── Stats row ── */
.stats-row {
    display: flex;
    justify-content: center;
    gap: 2rem;
    margin-bottom: 2.5rem;
    flex-wrap: wrap;
}
.stat-pill {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 0.6rem 1.4rem;
    text-align: center;
}
.stat-pill .val {
    font-size: 1.4rem;
    font-weight: 700;
    color: #93c5fd;
}
.stat-pill .lbl {
    font-size: 0.72rem;
    color: #475569;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 600;
}

/* ── URL input card ── */
div[data-testid="stForm"] {
    background: rgba(255,255,255,0.04) !important;
    border: 1px solid rgba(37,99,235,0.25) !important;
    border-radius: 20px !important;
    padding: 2rem 2.5rem !important;
    margin-bottom: 2rem !important;
    backdrop-filter: blur(10px) !important;
    box-shadow: 0 0 40px rgba(37,99,235,0.1) !important;
}
.input-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: #64748b;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
}

/* Override Streamlit input */
.stTextInput > div > div > input {
    background: rgba(7, 15, 35, 0.85) !important;
    border: 1px solid rgba(37,99,235,0.35) !important;
    border-radius: 12px !important;
    color: #e2e8f0 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.95rem !important;
    padding: 0.85rem 1.2rem !important;
    transition: border-color 0.2s ease !important;
}
.stTextInput > div > div > input:focus {
    border-color: rgba(59,130,246,0.8) !important;
    box-shadow: 0 0 0 3px rgba(37,99,235,0.18) !important;
}
.stTextInput > div > div > input::placeholder {
    color: #334155 !important;
}

/* ── Button ── */
[data-testid="stFormSubmitButton"] > button, .stButton > button {
    background: #7db4fb !important;
    color: #0f172a !important;
    font-weight: 700 !important;
    font-size: 0.95rem !important;
    border: none !important;
    border-radius: 12px !important;
    padding: 0.75rem 2.5rem !important;
    transition: all 0.2s ease !important;
    letter-spacing: 0.02em !important;
    width: 100% !important;
}
.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 8px 25px rgba(37,99,235,0.45) !important;
}

/* ── Result cards ── */
.result-card {
    border-radius: 20px;
    padding: 2rem 2.5rem;
    margin: 1.5rem 0;
    position: relative;
    overflow: hidden;
}
.result-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
}
.result-phishing {
    background: linear-gradient(135deg, rgba(239,68,68,0.12), rgba(185,28,28,0.08));
    border: 1px solid rgba(239,68,68,0.3);
}
.result-phishing::before {
    background: linear-gradient(90deg, #ef4444, #dc2626);
}
.result-legitimate {
    background: linear-gradient(135deg, rgba(34,197,94,0.12), rgba(21,128,61,0.08));
    border: 1px solid rgba(34,197,94,0.3);
}
.result-legitimate::before {
    background: linear-gradient(90deg, #22c55e, #16a34a);
}

.result-icon {
    font-size: 3rem;
    margin-bottom: 0.5rem;
}
.result-verdict {
    font-size: 1.9rem;
    font-weight: 800;
    margin-bottom: 0.4rem;
}
.result-phishing .result-verdict { color: #fca5a5; }
.result-legitimate .result-verdict { color: #86efac; }
.result-desc {
    font-size: 0.95rem;
    color: #94a3b8;
    line-height: 1.6;
}
.confidence-badge {
    display: inline-block;
    padding: 0.3rem 0.9rem;
    border-radius: 100px;
    font-size: 0.8rem;
    font-weight: 700;
    margin-top: 1rem;
    letter-spacing: 0.05em;
}
.result-phishing .confidence-badge {
    background: rgba(239,68,68,0.2);
    color: #fca5a5;
    border: 1px solid rgba(239,68,68,0.3);
}
.result-legitimate .confidence-badge {
    background: rgba(34,197,94,0.2);
    color: #86efac;
    border: 1px solid rgba(34,197,94,0.3);
}

/* ── Gauge bar ── */
.gauge-wrap { margin: 1.5rem 0; }
.gauge-label-row {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.4rem;
}
.gauge-label { font-size: 0.78rem; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.1em; }
.gauge-val { font-size: 0.9rem; font-weight: 700; color: #e2e8f0; }
.gauge-track {
    height: 8px;
    background: rgba(255,255,255,0.06);
    border-radius: 100px;
    overflow: hidden;
}
.gauge-fill {
    height: 100%;
    border-radius: 100px;
    transition: width 0.6s ease;
}
.gauge-danger  { background: linear-gradient(90deg, #ef4444, #dc2626); }
.gauge-safe    { background: linear-gradient(90deg, #22c55e, #16a34a); }
.gauge-neutral { background: linear-gradient(90deg, #f59e0b, #d97706); }

/* ── Section heading ── */
.section-heading {
    font-size: 0.75rem;
    font-weight: 700;
    color: #475569;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin: 2rem 0 1rem 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}
.section-heading::after {
    content: '';
    flex: 1;
    height: 1px;
    background: rgba(255,255,255,0.06);
}

/* ── Feature grid ── */
.feat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1.5rem;
}
.feat-card {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 14px;
    padding: 1rem 1.2rem;
    transition: border-color 0.2s;
}
.feat-card:hover { border-color: rgba(37,99,235,0.4); }
.feat-name {
    font-size: 0.72rem;
    font-weight: 600;
    color: #475569;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 0.35rem;
}
.feat-value {
    font-size: 1.15rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
}
.feat-ok   { color: #86efac; }
.feat-warn { color: #fca5a5; }
.feat-neu  { color: #93c5fd; }

/* ── Typosquat warning ── */
.typo-card {
    background: linear-gradient(135deg, rgba(239,68,68,0.15), rgba(153,27,27,0.1));
    border: 1px solid rgba(239,68,68,0.4);
    border-radius: 20px;
    padding: 2rem 2.5rem;
    margin: 1.5rem 0;
    position: relative;
    overflow: hidden;
}
.typo-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, #ef4444, #f97316);
}
.typo-domain {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.1rem;
    color: #fca5a5;
    background: rgba(239,68,68,0.15);
    padding: 0.2rem 0.6rem;
    border-radius: 6px;
}

/* ── Spinner override ── */
.stSpinner > div { border-top-color: #3b82f6 !important; }

/* ── Warning / info banners ── */
.warn-banner {
    background: rgba(245,158,11,0.1);
    border: 1px solid rgba(245,158,11,0.3);
    border-radius: 12px;
    padding: 1rem 1.4rem;
    color: #fcd34d;
    font-size: 0.9rem;
    margin: 0.5rem 0;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: rgba(10,14,26,0.95) !important;
    border-right: 1px solid rgba(255,255,255,0.06) !important;
}
</style>
""", unsafe_allow_html=True)

# LOAD MODELS
@st.cache_resource
def load_models():
    try:
        model  = pickle.load(open("model.pkl",  "rb"))
        scaler = pickle.load(open("scaler.pkl", "rb"))
        pca    = pickle.load(open("pca.pkl",    "rb"))
        return model, scaler, pca, True, None
    except FileNotFoundError as e:
        return None, None, None, False, f"Missing file: {e}"
    except Exception as e:
        return None, None, None, False, f"Error loading models: {e}"

model, scaler, pca, success, error_msg = load_models()
if not success:
    st.error(f"❌ {error_msg}")
    st.stop()

# PREDICTION
def predict_phishing(features_dict):
    feature_names = [
        'URLSimilarityIndex', 'CharContinuationRate', 'URLCharProb',
        'SpacialCharRatioInURL', 'IsHTTPS', 'HasTitle', 'DomainTitleMatchScore',
        'URLTitleMatchScore', 'HasFavicon', 'IsResponsive', 'HasDescription',
        'HasSocialNet', 'HasSubmitButton', 'HasHiddenFields', 'HasCopyrightInfo'
    ]
    try:
        df = pd.DataFrame([[features_dict.get(f, 0) for f in feature_names]], columns=feature_names)
        scaled = scaler.transform(df)
        pca_out = pca.transform(scaled)
        pred = model.predict(pca_out)[0]
        prob = model.predict_proba(pca_out)[0]
        return pred, prob, None
    except Exception as e:
        return None, None, f"Prediction error: {e}"

# HELPERS
def gauge(label, pct, color_class):
    st.markdown(f"""
    <div class="gauge-wrap">
      <div class="gauge-label-row">
        <span class="gauge-label">{label}</span>
        <span class="gauge-val">{pct:.1f}%</span>
      </div>
      <div class="gauge-track">
        <div class="gauge-fill {color_class}" style="width:{pct}%"></div>
      </div>
    </div>
    """, unsafe_allow_html=True)

def feat_card(name, raw_val, good_when_high=True):
    if isinstance(raw_val, float):
        display = f"{raw_val:.2f}"
        is_good = raw_val >= 0.5 if good_when_high else raw_val < 0.5
    else:
        display = "✓ Yes" if raw_val else "✗ No"
        is_good = bool(raw_val) if good_when_high else not bool(raw_val)
    cls = "feat-ok" if is_good else "feat-warn"
    return f"""
    <div class="feat-card">
      <div class="feat-name">{name}</div>
      <div class="feat-value {cls}">{display}</div>
    </div>"""

# HERO SECTION
st.markdown("""
<div class="hero">
  <div class="hero-title">Phishing URL Detector</div>
  <div class="hero-sub">
    Instantly detect phishing URLs using machine learning and real-time
    website analysis. Paste any link below to get started.
  </div>
  <div class="stats-row">
    <div class="stat-pill"><div class="val">95%</div><div class="lbl">Accuracy</div></div>
    <div class="stat-pill"><div class="val">15</div><div class="lbl">Features</div></div>
    <div class="stat-pill"><div class="val">35+</div><div class="lbl">Brands Protected</div></div>
    <div class="stat-pill"><div class="val">&lt;10s</div><div class="lbl">Analysis Time</div></div>
  </div>
</div>
""", unsafe_allow_html=True)

# INPUT
with st.form("input_form", border=True):
    st.markdown('<div class="input-label">🔗 Enter URL to Analyze</div>', unsafe_allow_html=True)

    col_input, col_btn = st.columns([5, 1])
    with col_input:
        url_input = st.text_input(
            label="url",
            placeholder="https://example.com",
            label_visibility="collapsed"
        )
    with col_btn:
        analyze = st.form_submit_button("Analyze", use_container_width=True)

# ANALYSIS
if url_input and (analyze or url_input):

    if not url_input.startswith(('http://', 'https://')):
        st.markdown('<div class="warn-banner">⚠️ URL must start with <code>http://</code> or <code>https://</code></div>', unsafe_allow_html=True)
        st.stop()

    # ── Typosquatting pre-check ──
    is_typosquat, impersonated = check_typosquatting(url_input)
    if is_typosquat:
        parsed_show = urlparse(url_input).netloc
        st.markdown(f"""
        <div class="typo-card">
          <div class="result-verdict" style="color:#fca5a5;font-size:1.7rem;font-weight:800;">
            PHISHING DETECTED — Typosquatting
          </div>
          <div class="result-desc" style="margin-top:0.6rem;">
            The domain <span class="typo-domain">{parsed_show}</span> is impersonating
            <strong style="color:#fcd34d;">{impersonated}.com</strong> using lookalike
            characters (e.g. <code style="color:#fca5a5;">1</code> instead of
            <code style="color:#86efac;">l</code>).
          </div>
          <div class="confidence-badge" style="background:rgba(239,68,68,0.2);color:#fca5a5;border:1px solid rgba(239,68,68,0.3);display:inline-block;padding:0.3rem 0.9rem;border-radius:100px;font-size:0.8rem;font-weight:700;margin-top:1rem;">
            99.0% CONFIDENCE · Rule-Based Detection
          </div>
        </div>
        """, unsafe_allow_html=True)
        st.stop()

    # ── Suspicious Heuristics pre-check ──
    is_suspicious, reason = check_suspicious_heuristics(url_input)
    if is_suspicious:
        parsed_show = urlparse(url_input).netloc
        st.markdown(f"""
        <div class="typo-card">
          <div class="result-verdict" style="color:#fca5a5;font-size:1.7rem;font-weight:800;">
            PHISHING DETECTED — High Risk Pattern
          </div>
          <div class="result-desc" style="margin-top:0.6rem;">
            The domain <span class="typo-domain">{parsed_show}</span> exhibits a high-risk pattern commonly used in phishing attacks.
            <br><br><strong style="color:#fcd34d;">Reason:</strong> {reason}
          </div>
          <div class="confidence-badge" style="background:rgba(239,68,68,0.2);color:#fca5a5;border:1px solid rgba(239,68,68,0.3);display:inline-block;padding:0.3rem 0.9rem;border-radius:100px;font-size:0.8rem;font-weight:700;margin-top:1rem;">
            98.0% CONFIDENCE · Heuristic Detection
          </div>
        </div>
        """, unsafe_allow_html=True)
        st.stop()

    # ── ML analysis ──
    with st.spinner("🔍 Analyzing website…"):
        extractor = FeatureExtractor(url_input, timeout=15)
        features  = extractor.extract_all_features()
        pred, prob, err = predict_phishing(features)

    if err or pred is None:
        st.error(f"❌ {err or 'Unknown prediction error'}")
        st.stop()

    is_phishing = pred == 1
    phish_pct   = prob[1] * 100
    legit_pct   = prob[0] * 100
    confidence  = max(prob) * 100

    # ── Verdict card ──
    if is_phishing:
        st.markdown(f"""
        <div class="result-card result-phishing">
          <div class="result-icon">⚠️</div>
          <div class="result-verdict">PHISHING URL DETECTED</div>
          <div class="result-desc">
            This URL exhibits characteristics commonly associated with phishing attacks.
            Do <strong>not</strong> enter any credentials or personal information.
          </div>
          <span class="confidence-badge">{confidence:.1f}% Confidence</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="result-card result-legitimate">
          <div class="result-verdict">LEGITIMATE URL</div>
          <div class="result-desc">
            This URL appears to be safe based on ML analysis and structure checks.
            Always stay vigilant — no system is 100% perfect.
          </div>
          <span class="confidence-badge">{confidence:.1f}% Confidence</span>
        </div>
        """, unsafe_allow_html=True)

    # ── Tips ──
    st.markdown('<div class="section-heading">Safety Tips</div>', unsafe_allow_html=True)
    if is_phishing:
        st.markdown("""
        <div class="warn-banner">
        🚫 <strong>Do not visit this site.</strong> Do not enter passwords, payment details, or any personal information.<br>
        📧 If received via email, report it as phishing to your email provider.<br>
        🔒 Enable two-factor authentication on your important accounts.
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);border-radius:12px;padding:1rem 1.4rem;color:#86efac;font-size:0.9rem;margin:0.5rem 0;">
        ✅ URL appears safe — but always verify sensitive sites manually before entering credentials.<br>
        🔍 Check that the padlock icon is visible in your browser's address bar.
        </div>
        """, unsafe_allow_html=True)