# PhishGuard — URL Threat Detector 🛡️

PhishGuard is an AI-powered Phishing URL Detection System that analyzes websites in real-time to determine whether they are legitimate or potential phishing threats. It combines a robust rule-based typosquatting detection engine with a trained Machine Learning model (Random Forest Classifier) to provide accurate, confidence-based verdicts.

## Features

- **Real-Time Website Analysis**: Scrapes and analyzes the target URL and its HTML content on the fly.
- **Rule-Based Typosquatting Pre-check**: Instantly detects brand impersonation using homoglyph substitution (e.g., detecting `paypa1.com` instead of `paypal.com`) across 35+ top targeted brands.
- **Machine Learning Engine**: Uses a trained Random Forest Classifier on 15 distinct URL and content-based features.
- **Premium UI**: Features a modern, dark-themed, glassmorphism UI built with Streamlit, providing threat probabilities, confidence scores, and a detailed feature breakdown.

## Architecture & Detection Flow

1. **URL Validation**: Ensures the input is a valid HTTP/HTTPS URL.
2. **Typosquatting Pre-check**: Fast, rule-based check that spots obvious homoglyph attacks before any network requests are made.
3. **Website Download**: Fetches the HTML content of the target site using a custom user-agent.
4. **Feature Extraction**: Extracts 15 specific features from the URL structure and HTML body.
5. **Preprocessing**: Normalizes the features using a pre-fitted `StandardScaler` and reduces dimensionality via `PCA`.
6. **Prediction**: The Random Forest model processes the PCA components to predict the likelihood of the site being a phishing attempt.
7. **Results Display**: Renders a comprehensive report in the UI.

## The 15 Extracted Features

The model relies on the following features extracted by `feature_extractor.py`:

**URL-Based Features:**
- `URLSimilarityIndex`: How similar the domain is to known legitimate domains, penalizing suspicious structures and digits.
- `CharContinuationRate`: Measures consecutive identical characters (e.g., `aaaa`).
- `URLCharProb`: Probability based on the frequency of common characters.
- `SpacialCharRatioInURL`: Ratio of special, potentially suspicious characters.
- `IsHTTPS`: Binary check for HTTPS usage.

**Content-Based Features:**
- `HasTitle`: Binary check for the presence of a `<title>` tag.
- `DomainTitleMatchScore`: Measures if the domain name appears in the page title.
- `URLTitleMatchScore`: Measures if significant parts of the URL appear in the title.
- `HasFavicon`: Binary check for a favicon link.
- `IsResponsive`: Checks for a viewport meta tag.
- `HasDescription`: Checks for a meta description.
- `HasSocialNet`: Detects links to major social networks (Facebook, Twitter, etc.).
- `HasSubmitButton`: Checks for the presence of form submit buttons.
- `HasHiddenFields`: Checks for hidden input fields (common in credential harvesting).
- `HasCopyrightInfo`: Checks for copyright text or symbols.

## Prerequisites

- Python 3.8+
- `pip` package manager

## Installation

1. **Clone or Download the Repository**
2. **Set up a Virtual Environment (Recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```
3. **Install Dependencies:**
   Make sure you have the required packages installed. 
   ```bash
   pip install streamlit pandas numpy scikit-learn beautifulsoup4 requests validators
   ```

## Usage

1. **Run the Streamlit App:**
   ```bash
   streamlit run app.py
   ```
2. **Access the UI:**
   Open your browser and navigate to the URL provided in the terminal (usually `http://localhost:8501`).
3. **Analyze a URL:**
   Paste a complete URL (including `http://` or `https://`) into the input box and click **Analyze →**.

## Project Structure

- `app.py`: The main Streamlit application containing the UI layout, routing, and prediction logic.
- `feature_extractor.py`: Contains the `FeatureExtractor` class responsible for scraping the target website and computing the 15 features.
- `model.pkl`: The serialized Random Forest Classifier.
- `scaler.pkl`: The serialized `StandardScaler` used to normalize features during training.
- `pca.pkl`: The serialized PCA (Principal Component Analysis) transformer.

## Disclaimer

This system uses Machine Learning and heuristic rules, which are not 100% accurate. It may produce false positives or false negatives. Always verify suspicious links independently and never enter sensitive information on sites you do not fully trust.
