# FEATURE EXTRACTOR - Extracts 15 features from a website
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import validators
import re

class FeatureExtractor:
    """
    Extracts 15 features from a website for phishing detection.
    """
    
    def __init__(self, url, timeout=10):
        """
        Initialize the feature extractor.
        
        Args:
            url: The website URL to analyze
            timeout: Max time to wait for response (in seconds)
        """
        self.url = url
        self.timeout = timeout
        self.html = None
        self.soup = None
        self.features = {}
        
    def download_website(self):
        """
        Download the website HTML.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set a user-agent (pretend to be a browser)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            # Download the website
            response = requests.get(self.url, headers=headers, timeout=self.timeout, verify=False)
            
            # Check if request was successful
            if response.status_code == 200:
                self.html = response.text
                self.soup = BeautifulSoup(self.html, 'html.parser')
                return True
            else:
                print(f"[ERROR] Failed to download. Status code: {response.status_code}")
                return False
                
        except requests.exceptions.Timeout:
            print("[ERROR] Timeout: Website took too long to respond")
            return False
        except requests.exceptions.ConnectionError:
            print("[ERROR] Connection Error: Could not connect to website")
            return False
        except Exception as e:
            print(f"[ERROR] Error downloading website: {str(e)}")
            return False
    
    # FEATURE EXTRACTION METHODS (One for each feature)

    # Homoglyph character map: maps lookalike digits/symbols → real letters
    HOMOGLYPH_MAP = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
        '6': 'g', '7': 't', '8': 'b', '@': 'a',
    }

    # Well-known brand domains that attackers commonly impersonate
    KNOWN_BRANDS = [
        'google', 'facebook', 'amazon', 'apple', 'microsoft',
        'github', 'stackoverflow', 'reddit', 'paypal', 'twitter',
        'instagram', 'linkedin', 'netflix', 'youtube', 'yahoo',
        'ebay', 'dropbox', 'adobe', 'office', 'outlook',
        'gmail', 'icloud', 'chase', 'wellsfargo', 'stripe',
        'coinbase', 'americanexpress', 'bankofamerica', 'steam',
        'twitch', 'discord', 'spotify', 'samsung', 'nvidia',
    ]

    def _normalize_homoglyphs(self, text):
        """Replace lookalike characters with their real equivalents."""
        result = text
        # Multi-char substitution first
        result = result.replace('vv', 'w').replace('rn', 'm')
        # Single-char substitutions
        for fake, real in self.HOMOGLYPH_MAP.items():
            result = result.replace(fake, real)
        return result

    def extract_url_similarity_index(self):
        """
        Feature 1: URLSimilarityIndex
        Measures how similar the URL is to legitimate websites.
        High score  = legitimate-looking URL
        Near-zero   = typosquatting / homoglyph impersonation detected
        Low score   = suspicious structure
        """
        parsed = urlparse(self.url)
        domain = parsed.netloc.lower()
        # Strip port and leading www.
        clean_domain = domain.split(':')[0]
        clean_domain = clean_domain.lstrip('www.')

        # ── IP Masquerading (Pattern 6) ───────────────────────────────────
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', domain):
            self.features['URLSimilarityIndex'] = 0.0
            return

        # ── Redirect Attacks (Pattern 5) ──────────────────────────────────
        query = parsed.query.lower()
        if 'redirect=' in query or 'url=' in query or 'next=' in query:
            self.features['URLSimilarityIndex'] = 0.0
            return

        # ── Exact-match check ──────────────────────────────────────────────
        known_legitimate = [b + tld for b in self.KNOWN_BRANDS
                            for tld in ['.com', '.org', '.net', '.io', '.co']]
        for leg_domain in known_legitimate:
            if clean_domain == leg_domain or clean_domain.endswith('.' + leg_domain):
                self.features['URLSimilarityIndex'] = 1.0
                return

        # ── Typosquatting / Homoglyph detection (Pattern 1) ───────────────
        # Extract the second-level domain (SLD), e.g. "paypa1" from "paypa1.com"
        sld = clean_domain.split('.')[0]
        normalized_sld = self._normalize_homoglyphs(sld)

        for brand in self.KNOWN_BRANDS:
            if normalized_sld == brand and sld != brand:
                self.features['URLSimilarityIndex'] = 0.0
                return
            if brand in normalized_sld and brand not in sld:
                self.features['URLSimilarityIndex'] = 0.0
                return
            if normalized_sld != brand and brand in sld and clean_domain != brand + '.com':
                self.features['URLSimilarityIndex'] = 0.0
                return

        # ── Brand Embedding (Pattern 2) ───────────────────────────────────
        suspicious_keywords = ['secure', 'verify', 'account', 'update', 'login', 'banking', 'auth', 'confirm', 'wallet']
        if any(kw in clean_domain for kw in suspicious_keywords):
            # If domain contains a brand AND suspicious keywords
            if any(brand in clean_domain for brand in self.KNOWN_BRANDS):
                self.features['URLSimilarityIndex'] = 0.0
                return
            # Or if it's just pure phishing keywords and no recognized brand
            matched_kws = [kw for kw in suspicious_keywords if kw in clean_domain]
            if len(matched_kws) >= 2:
                self.features['URLSimilarityIndex'] = 0.0
                return

        # ── Score based on domain structure ───────────────────────────────
        domain_length = len(clean_domain)

        if domain_length < 15:
            score = 0.5          # Short but unknown — neutral, not blindly trusted
        elif domain_length < 30:
            score = 0.4
        else:
            score = 0.2          # Very long → suspicious

        # ── Excessive Subdomains & Registry Detection (Pattern 3) ─────────
        dot_count = clean_domain.count('.')
        if dot_count > 2:
            score -= 0.2 * (dot_count - 2)

        bad_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.cc', '.cn']
        if any(clean_domain.endswith(tld) for tld in bad_tlds):
            score -= 0.5

        # Penalize digits in the SLD (common in typosquatting)
        digit_count = sum(1 for c in sld if c.isdigit())
        if digit_count > 0:
            score -= 0.15 * digit_count

        score = max(0.0, min(1.0, score))
        self.features['URLSimilarityIndex'] = score
    
    def extract_char_continuation_rate(self):
        """
        Feature 2: CharContinuationRate
        Measures how many consecutive characters are the same.
        High = suspicious (e.g., "aaaa" in domain)
        Low = normal
        """
        parsed = urlparse(self.url)
        url_path = parsed.netloc + parsed.path
        
        max_continuation = 1
        current_continuation = 1
        
        # Find longest sequence of same character
        for i in range(1, len(url_path)):
            if url_path[i] == url_path[i-1]:
                current_continuation += 1
                max_continuation = max(max_continuation, current_continuation)
            else:
                current_continuation = 1
        
        # Score: longer continuation = higher rate (more suspicious)
        rate = min(max_continuation / 5, 1.0)  # Normalize by 5
        self.features['CharContinuationRate'] = rate
    
    def extract_url_char_prob(self):
        """
        Feature 3: URLCharProb
        Probability of characters used in URL.
        Uses common character frequencies.
        High = common characters (legitimate)
        Low = rare characters (suspicious)
        """
        url_chars = self.url.lower()
        
        # Frequency of characters in legitimate URLs
        common_chars = 'abcdefghijklmnopqrstuvwxyz0123456789.-_'
        
        # Count how many characters are "common"
        common_count = sum(1 for c in url_chars if c in common_chars)
        total_count = len(url_chars)
        
        # Score: higher = more common characters
        prob = common_count / total_count if total_count > 0 else 0.0
        self.features['URLCharProb'] = prob
    
    def extract_spacial_char_ratio(self):
        """
        Feature 4: SpacialCharRatioInURL
        Ratio of special characters in URL.
        Phishing URLs often have many special characters.
        High = suspicious
        """
        url_chars = self.url
        
        # Define special characters
        special_chars = '!@#$%^&*()_+=[]{}|;:,<>?/~`'
        
        # Count special characters
        special_count = sum(1 for c in url_chars if c in special_chars)
        total_count = len(url_chars)
        
        # Calculate ratio
        ratio = special_count / total_count if total_count > 0 else 0.0
        self.features['SpacialCharRatioInURL'] = ratio
    
    def extract_is_https(self):
        """
        Feature 5: IsHTTPS
        Binary feature: Does URL use HTTPS?
        1 = HTTPS (secure)
        0 = HTTP (insecure, suspicious for sensitive sites)
        """
        is_https = 1 if self.url.startswith('https') else 0
        self.features['IsHTTPS'] = is_https
    
    def extract_has_title(self):
        """
        Feature 6: HasTitle
        Binary feature: Does website have a title tag?
        1 = yes (legitimate)
        0 = no (suspicious)
        """
        if self.soup is None:
            self.features['HasTitle'] = 0
            return
        
        title = self.soup.find('title')
        has_title = 1 if title and title.string else 0
        self.features['HasTitle'] = has_title
    
    def extract_domain_title_match(self):
        """
        Feature 7: DomainTitleMatchScore
        Measures if domain name appears in page title.
        1.0 = exact match (legitimate)
        0.0 = no match (suspicious)
        """
        if self.soup is None:
            self.features['DomainTitleMatchScore'] = 0.0
            return
        
        # Get domain and title
        parsed = urlparse(self.url)
        domain = parsed.netloc.lower()
        domain_name = domain.replace('www.', '').split('.')[0]
        
        title = self.soup.find('title')
        if not title or not title.string:
            self.features['DomainTitleMatchScore'] = 0.0
            return
        
        title_text = title.string.lower()
        
        # Check if domain name is in title
        if domain_name in title_text:
            self.features['DomainTitleMatchScore'] = 1.0
        elif domain in title_text:
            self.features['DomainTitleMatchScore'] = 0.9
        else:
            self.features['DomainTitleMatchScore'] = 0.0
    
    def extract_url_title_match(self):
        """
        Feature 8: URLTitleMatchScore
        Measures if URL appears in page title.
        1.0 = match found (legitimate)
        0.0 = no match (suspicious)
        """
        if self.soup is None:
            self.features['URLTitleMatchScore'] = 0.0
            return
        
        title = self.soup.find('title')
        if not title or not title.string:
            self.features['URLTitleMatchScore'] = 0.0
            return
        
        title_text = title.string.lower()
        url_text = self.url.lower()
        
        # Check if significant part of URL is in title
        if any(part in title_text for part in url_text.split('/')):
            self.features['URLTitleMatchScore'] = 1.0
        else:
            self.features['URLTitleMatchScore'] = 0.0
    
    def extract_has_favicon(self):
        """
        Feature 9: HasFavicon
        Binary feature: Does website have a favicon?
        1 = yes (legitimate)
        0 = no (suspicious)
        """
        if self.soup is None:
            self.features['HasFavicon'] = 0
            return
        
        # Look for favicon links
        favicon = self.soup.find('link', rel='icon')
        has_favicon = 1 if favicon else 0
        self.features['HasFavicon'] = has_favicon
    
    def extract_is_responsive(self):
        """
        Feature 10: IsResponsive
        Binary feature: Is website mobile responsive?
        Checks for viewport meta tag.
        1 = yes (legitimate)
        0 = no (suspicious)
        """
        if self.soup is None:
            self.features['IsResponsive'] = 0
            return
        
        # Look for viewport meta tag
        viewport = self.soup.find('meta', attrs={'name': 'viewport'})
        is_responsive = 1 if viewport else 0
        self.features['IsResponsive'] = is_responsive
    
    def extract_has_description(self):
        """
        Feature 11: HasDescription
        Binary feature: Does page have meta description?
        1 = yes (legitimate)
        0 = no (suspicious)
        """
        if self.soup is None:
            self.features['HasDescription'] = 0
            return
        
        description = self.soup.find('meta', attrs={'name': 'description'})
        has_description = 1 if description else 0
        self.features['HasDescription'] = has_description
    
    def extract_has_social_net(self):
        """
        Feature 12: HasSocialNet
        Binary feature: Does page link to social networks?
        Checks for links to Facebook, Twitter, LinkedIn, etc.
        1 = yes (legitimate)
        0 = no (suspicious)
        """
        if self.soup is None:
            self.features['HasSocialNet'] = 0
            return
        
        # Social network domains
        social_domains = [
            'facebook.com', 'twitter.com', 'linkedin.com', 
            'instagram.com', 'youtube.com', 'tiktok.com'
        ]
        
        # Find all links
        links = self.soup.find_all('a', href=True)
        
        # Check if any link goes to social network
        has_social = 0
        for link in links:
            href = link['href'].lower()
            if any(social in href for social in social_domains):
                has_social = 1
                break
        
        self.features['HasSocialNet'] = has_social
    
    def extract_has_submit_button(self):
        """
        Feature 13: HasSubmitButton
        Binary feature: Does page have submit button?
        Phishing pages often have forms with submit buttons.
        1 = yes (could be legitimate or phishing)
        0 = no
        """
        if self.soup is None:
            self.features['HasSubmitButton'] = 0
            return
        
        # Look for submit buttons
        submit_buttons = self.soup.find_all('input', attrs={'type': 'submit'})
        submit_buttons += self.soup.find_all('button', attrs={'type': 'submit'})
        submit_buttons += self.soup.find_all('button')
        
        has_submit = 1 if submit_buttons else 0
        self.features['HasSubmitButton'] = has_submit
    
    def extract_has_hidden_fields(self):
        """
        Feature 14: HasHiddenFields
        Binary feature: Does page have hidden form fields?
        Phishing pages often use hidden fields.
        1 = yes (suspicious)
        0 = no (legitimate)
        """
        if self.soup is None:
            self.features['HasHiddenFields'] = 0
            return
        
        # Look for hidden input fields
        hidden_fields = self.soup.find_all('input', attrs={'type': 'hidden'})
        
        # Look for password fields (Data Harvesting - Pattern 4)
        password_fields = self.soup.find_all('input', attrs={'type': 'password'})
        
        has_hidden = 1 if (hidden_fields or password_fields) else 0
        self.features['HasHiddenFields'] = has_hidden
    
    def extract_has_copyright(self):
        """
        Feature 15: HasCopyrightInfo
        Binary feature: Does page have copyright information?
        Usually at bottom of page.
        1 = yes (legitimate)
        0 = no (suspicious)
        """
        if self.soup is None:
            self.features['HasCopyrightInfo'] = 0
            return
        
        # Look for copyright symbol or text
        copyright_text = str(self.soup).lower()
        
        # Check for various copyright indicators
        has_copyright = 0
        if '©' in copyright_text or 'copyright' in copyright_text or '&copy;' in copyright_text:
            has_copyright = 1
        
        self.features['HasCopyrightInfo'] = has_copyright
    
    # MAIN EXTRACTION METHOD - Calls all feature extraction methods
    def extract_all_features(self):
        """
        Extract all 15 features.
        
        Returns:
            Dictionary with all 15 features, or None if extraction failed
        """
        print("[INFO] Extracting URL-based features...")
        self.extract_url_similarity_index()
        self.extract_char_continuation_rate()
        self.extract_url_char_prob()
        self.extract_spacial_char_ratio()
        self.extract_is_https()
        
        # Step 1: Download website
        if not self.download_website():
            print("[WARN] Could not download website. Using default values for HTML features.")
            self.features.update({
                'HasTitle': 0,
                'DomainTitleMatchScore': 0.0,
                'URLTitleMatchScore': 0.0,
                'HasFavicon': 0,
                'IsResponsive': 0,
                'HasDescription': 0,
                'HasSocialNet': 0,
                'HasSubmitButton': 0,
                'HasHiddenFields': 0,
                'HasCopyrightInfo': 0,
            })
            return self.features
        
        # Step 2: Extract each feature
        print("[INFO] Extracting HTML features...")
        self.extract_has_title()
        self.extract_domain_title_match()
        self.extract_url_title_match()
        self.extract_has_favicon()
        self.extract_is_responsive()
        self.extract_has_description()
        self.extract_has_social_net()
        self.extract_has_submit_button()
        self.extract_has_hidden_fields()
        self.extract_has_copyright()
        
        print("[INFO] Features extracted successfully!")
        return self.features
    
    def get_features_dict(self):
        """Return the extracted features as a dictionary."""
        return self.features