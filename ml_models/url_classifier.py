import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import re
import urllib.parse
from typing import Dict, List, Tuple, Any
import logging
import math

logger = logging.getLogger(__name__)

class URLThreatClassifier:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3))
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
        
    def extract_features(self, url: str) -> Dict[str, Any]:
        """Extract comprehensive features from URL for ML analysis"""
        features = {}
        
        # Basic URL components
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        # Basic length features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(query)
        
        # Character analysis
        features['digit_ratio'] = sum(1 for c in domain if c.isdigit()) / len(domain) if domain else 0
        features['special_char_ratio'] = sum(1 for c in domain if c in '!@#$%^&*()_+-=[]{}|;:,.<>?') / len(domain) if domain else 0
        
        # Domain analysis
        features['dot_count'] = domain.count('.')
        features['hyphen_count'] = domain.count('-')
        features['underscore_count'] = domain.count('_')
        
        # TLD analysis
        features['has_suspicious_tld'] = any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf', '.gq'])
        
        # Entropy calculation
        if domain:
            char_freq = {}
            for char in domain:
                char_freq[char] = char_freq.get(char, 0) + 1
            entropy = 0
            for count in char_freq.values():
                p = count / len(domain)
                if p > 0:
                    entropy -= p * math.log2(p)
            features['entropy'] = entropy
        else:
            features['entropy'] = 0
        
        # Suspicious keyword detection
        suspicious_keywords = ['login', 'signin', 'account', 'bank', 'secure', 'update', 'verify', 'confirm']
        features['suspicious_keyword_count'] = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
        
        # IP address detection
        features['is_ip_address'] = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain))
        features['has_ip'] = bool(re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain))
        
        # Subdomain analysis
        features['subdomain_count'] = len(domain.split('.')) - 1 if domain else 0
        
        # Path analysis
        features['has_file_extension'] = bool(re.search(r'\.[a-zA-Z0-9]{2,4}$', path))
        features['path_depth'] = len([p for p in path.split('/') if p]) if path else 0
        
        # Query analysis
        features['query_param_count'] = len(query.split('&')) if query else 0
        
        # Protocol analysis
        features['is_https'] = parsed.scheme == 'https'
        
        # Brand impersonation score
        features['brand_impersonation_score'] = self._calculate_brand_impersonation_score(domain)
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_length = len(text)
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_brand_impersonation_score(self, domain: str) -> float:
        """Calculate brand impersonation score"""
        brand_names = ['google', 'gmail', 'youtube', 'facebook', 'instagram', 'whatsapp', 'amazon', 'paypal', 'microsoft', 'outlook', 'hotmail', 'apple', 'icloud', 'netflix', 'ebay', 'wells fargo', 'bank of america', 'chase', 'hsbc', 'citibank', 'usbank', 'barclays', 'lloyds', 'santander']
        
        max_score = 0.0
        for brand in brand_names:
            if brand in domain.lower():
                # Calculate similarity score
                similarity = 1.0 - (self._levenshtein_distance(brand, domain.lower()) / max(len(brand), len(domain)))
                max_score = max(max_score, similarity)
        
        return max_score
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]
    
    def _levenshtein_similarity(self, s1: str, s2: str) -> float:
        """Calculate similarity based on Levenshtein distance"""
        if len(s1) < len(s2):
            s1, s2 = s2, s1
        
        if len(s2) == 0:
            return 0.0
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        distance = previous_row[-1]
        max_len = max(len(s1), len(s2))
        return 1.0 - (distance / max_len) if max_len > 0 else 0.0
    
    def prepare_training_data(self, urls: List[str], labels: List[int]) -> pd.DataFrame:
        """Prepare training data with extracted features"""
        features_list = []
        for url in urls:
            features = self.extract_features(url)
            features_list.append(features)
        
        df = pd.DataFrame(features_list)
        df['label'] = labels
        return df
    
    def train(self, urls: List[str], labels: List[int]):
        """Train the classifier"""
        logger.info(f"Training URL classifier with {len(urls)} samples")
        
        # Prepare features
        df = self.prepare_training_data(urls, labels)
        
        # Split features and labels
        X = df.drop('label', axis=1)
        y = df['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train classifier
        self.classifier.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.classifier.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        logger.info(f"Training completed. Accuracy: {accuracy:.4f}")
        logger.info(f"Classification report:\n{classification_report(y_test, y_pred)}")
        
        self.is_trained = True
    
    def predict(self, url: str) -> Dict[str, float]:
        """Predict threat level for a URL"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        features = self.extract_features(url)
        
        # Create DataFrame with same structure as training data
        feature_df = pd.DataFrame([features])
        
        # Get prediction probabilities
        probabilities = self.classifier.predict_proba(feature_df)[0]
        
        # Get feature importance for this prediction
        feature_importance = self.classifier.feature_importances_
        feature_names = list(features.keys())
        
        # Create explanation
        explanation = {}
        for i, (name, importance) in enumerate(zip(feature_names, feature_importance)):
            if importance > 0.01:  # Only include significant features
                explanation[name] = {
                    'value': features[name],
                    'importance': float(importance)
                }
        
        return {
            'threat_probability': float(probabilities[1]),
            'safe_probability': float(probabilities[0]),
            'prediction': int(probabilities[1] > 0.5),
            'confidence': float(max(probabilities)),
            'explanation': explanation,
            'features': features
        }
    
    def save_model(self, filepath: str):
        """Save the trained model"""
        model_data = {
            'classifier': self.classifier,
            'vectorizer': self.vectorizer,
            'is_trained': self.is_trained
        }
        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load a trained model"""
        model_data = joblib.load(filepath)
        self.classifier = model_data['classifier']
        self.vectorizer = model_data['vectorizer']
        self.is_trained = model_data['is_trained']
        logger.info(f"Model loaded from {filepath}")


# Example usage and training data generation
def generate_training_data():
    """Generate synthetic training data for demonstration"""
    malicious_urls = [
        "http://192.168.1.1/login",
        "https://g00gle.com/verify",
        "http://secure-bank-update123.tk",
        "https://paypal-secure-verify.ga",
        "http://amazon-account-suspended.ml",
        "https://microsoft-security-alert.cf",
        "http://facebook-login-verify.tk",
        "https://netflix-payment-update.ga",
        "http://apple-id-verify.ml",
        "https://ebay-account-suspended.cf",
        "http://192.168.0.1/admin",
        "https://g00gle.com/login",
        "http://secure-login-verify.tk",
        "https://paypal-verify-secure.ga",
        "http://amazon-security-alert.ml",
        "https://microsoft-account-suspended.cf",
        "http://facebook-security-verify.tk",
        "https://netflix-account-update.ga",
        "http://apple-security-verify.ml",
        "https://ebay-security-alert.cf"
    ]
    
    safe_urls = [
        "https://google.com",
        "https://facebook.com",
        "https://amazon.com",
        "https://microsoft.com",
        "https://apple.com",
        "https://paypal.com",
        "https://netflix.com",
        "https://github.com",
        "https://stackoverflow.com",
        "https://wikipedia.org",
        "https://youtube.com",
        "https://twitter.com",
        "https://linkedin.com",
        "https://reddit.com",
        "https://instagram.com",
        "https://discord.com",
        "https://spotify.com",
        "https://twitch.tv",
        "https://zoom.us",
        "https://slack.com"
    ]
    
    urls = malicious_urls + safe_urls
    labels = [1] * len(malicious_urls) + [0] * len(safe_urls)
    
    return urls, labels


if __name__ == "__main__":
    # Example training
    urls, labels = generate_training_data()
    
    classifier = URLThreatClassifier()
    classifier.train(urls, labels)
    
    # Test predictions
    test_urls = [
        "https://google.com",  # Safe
        "https://g00gle.com/verify",  # Malicious
        "https://facebook.com",  # Safe
        "http://192.168.1.1/login"  # Malicious
    ]
    
    for url in test_urls:
        result = classifier.predict(url)
        print(f"URL: {url}")
        print(f"Threat probability: {result['threat_probability']:.4f}")
        print(f"Prediction: {'MALICIOUS' if result['prediction'] else 'SAFE'}")
        print(f"Confidence: {result['confidence']:.4f}")
        print("---") 