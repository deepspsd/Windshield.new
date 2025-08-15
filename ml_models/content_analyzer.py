import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import re
from typing import Dict, List, Any
import logging
from bs4 import BeautifulSoup
import requests

logger = logging.getLogger(__name__)

class ContentPhishingDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=2000, ngram_range=(1, 3))
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
        
    def extract_content_features(self, html_content: str) -> Dict[str, float]:
        """Extract features from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Get text content
        text_content = soup.get_text(separator=' ', strip=True).lower()
        
        # Get all links
        links = soup.find_all('a', href=True)
        link_texts = [link.get_text(strip=True).lower() for link in links]
        link_hrefs = [link.get('href', '').lower() for link in links]
        
        # Get all forms
        forms = soup.find_all('form')
        form_actions = [form.get('action', '').lower() for form in forms]
        
        # Get all images
        images = soup.find_all('img')
        image_alts = [img.get('alt', '').lower() for img in images]
        
        features = {}
        
        # Text-based features
        features['text_length'] = len(text_content)
        features['word_count'] = len(text_content.split())
        
        # Phishing indicators
        phishing_keywords = [
            'verify', 'suspend', 'suspended', 'limited', 'restriction', 'restricted',
            'confirm', 'update', 'unlock', 'locked', 'expire', 'expired', 'urgent',
            'immediately', 'immediate', 'alert', 'security', 'account', 'password',
            'login', 'signin', 'authentication', 'credential'
        ]
        
        features['phishing_keyword_count'] = sum(1 for keyword in phishing_keywords if keyword in text_content)
        features['phishing_keyword_ratio'] = features['phishing_keyword_count'] / max(features['word_count'], 1)
        
        # Brand impersonation
        popular_brands = [
            'paypal', 'amazon', 'microsoft', 'outlook', 'google', 'gmail', 'apple',
            'icloud', 'netflix', 'ebay', 'wells fargo', 'bank of america', 'chase',
            'hsbc', 'citibank', 'usbank', 'barclays', 'lloyds', 'santander'
        ]
        
        features['brand_mention_count'] = sum(1 for brand in popular_brands if brand in text_content)
        
        # Form analysis
        features['form_count'] = len(forms)
        features['password_input_count'] = len(soup.find_all('input', type='password'))
        features['email_input_count'] = len(soup.find_all('input', type='email'))
        features['text_input_count'] = len(soup.find_all('input', type='text'))
        
        # Link analysis
        features['link_count'] = len(links)
        features['external_link_count'] = sum(1 for href in link_hrefs if href.startswith('http'))
        features['suspicious_link_count'] = sum(1 for href in link_hrefs if any(susp in href for susp in ['bit.ly', 'tinyurl', 'goo.gl']))
        
        # Image analysis
        features['image_count'] = len(images)
        features['logo_image_count'] = sum(1 for alt in image_alts if any(brand in alt for brand in popular_brands))
        
        # Security indicators
        security_indicators = ['ssl', 'secure', 'https', 'certificate', 'encryption']
        features['security_indicator_count'] = sum(1 for indicator in security_indicators if indicator in text_content)
        
        # Urgency indicators
        urgency_patterns = [
            r'act\s+now', r'urgent', r'immediate', r'expires?\s+(today|soon)',
            r'limited\s+time', r'act\s+fast', r'don\'t\s+miss', r'last\s+chance'
        ]
        
        urgency_count = 0
        for pattern in urgency_patterns:
            urgency_count += len(re.findall(pattern, text_content))
        features['urgency_indicator_count'] = urgency_count
        
        # Grammar and spelling (simplified)
        features['exclamation_count'] = text_content.count('!')
        features['question_count'] = text_content.count('?')
        features['uppercase_ratio'] = sum(1 for c in text_content if c.isupper()) / max(len(text_content), 1)
        
        # Content structure
        features['paragraph_count'] = len(soup.find_all('p'))
        features['div_count'] = len(soup.find_all('div'))
        features['span_count'] = len(soup.find_all('span'))
        
        # JavaScript analysis
        scripts = soup.find_all('script')
        features['script_count'] = len(scripts)
        script_content = ' '.join([script.get_text() for script in scripts])
        features['javascript_length'] = len(script_content)
        
        # CSS analysis
        styles = soup.find_all('style')
        features['style_count'] = len(styles)
        
        return features
    
    def extract_text_features(self, text: str) -> Dict[str, float]:
        """Extract features from plain text"""
        text_lower = text.lower()
        
        features = {}
        
        # Basic text features
        features['text_length'] = len(text)
        features['word_count'] = len(text.split())
        features['sentence_count'] = len(re.split(r'[.!?]+', text))
        
        # Character features
        features['digit_count'] = sum(c.isdigit() for c in text)
        features['letter_count'] = sum(c.isalpha() for c in text)
        features['special_char_count'] = sum(not c.isalnum() and not c.isspace() for c in text)
        
        # Phishing indicators
        phishing_keywords = [
            'verify', 'suspend', 'suspended', 'limited', 'restriction', 'restricted',
            'confirm', 'update', 'unlock', 'locked', 'expire', 'expired', 'urgent',
            'immediately', 'immediate', 'alert', 'security', 'account', 'password',
            'login', 'signin', 'authentication', 'credential'
        ]
        
        features['phishing_keyword_count'] = sum(1 for keyword in phishing_keywords if keyword in text_lower)
        features['phishing_keyword_ratio'] = features['phishing_keyword_count'] / max(features['word_count'], 1)
        
        # Brand mentions
        popular_brands = [
            'paypal', 'amazon', 'microsoft', 'outlook', 'google', 'gmail', 'apple',
            'icloud', 'netflix', 'ebay', 'wells fargo', 'bank of america', 'chase',
            'hsbc', 'citibank', 'usbank', 'barclays', 'lloyds', 'santander'
        ]
        
        features['brand_mention_count'] = sum(1 for brand in popular_brands if brand in text_lower)
        
        # Urgency indicators
        urgency_patterns = [
            r'act\s+now', r'urgent', r'immediate', r'expires?\s+(today|soon)',
            r'limited\s+time', r'act\s+fast', r'don\'t\s+miss', r'last\s+chance'
        ]
        
        urgency_count = 0
        for pattern in urgency_patterns:
            urgency_count += len(re.findall(pattern, text_lower))
        features['urgency_indicator_count'] = urgency_count
        
        # Punctuation analysis
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['uppercase_ratio'] = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        
        return features
    
    def train(self, content_samples: List[str], labels: List[int], content_type: str = 'html'):
        """Train the classifier"""
        logger.info(f"Training content classifier with {len(content_samples)} samples")
        
        # Extract features based on content type
        if content_type == 'html':
            features_list = [self.extract_content_features(content) for content in content_samples]
        else:
            features_list = [self.extract_text_features(content) for content in content_samples]
        
        df = pd.DataFrame(features_list)
        df['label'] = labels
        
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
    
    def predict(self, content: str, content_type: str = 'html') -> Dict[str, float]:
        """Predict phishing probability for content"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        # Extract features based on content type
        if content_type == 'html':
            features = self.extract_content_features(content)
        else:
            features = self.extract_text_features(content)
        
        feature_vector = np.array(list(features.values())).reshape(1, -1)
        
        # Get prediction probabilities
        probabilities = self.classifier.predict_proba(feature_vector)[0]
        
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
            'phishing_probability': float(probabilities[1]),
            'legitimate_probability': float(probabilities[0]),
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


def generate_content_training_data():
    """Generate synthetic training data for content analysis"""
    phishing_html_samples = [
        """
        <html>
        <body>
            <h1>URGENT: Your PayPal Account Has Been Suspended!</h1>
            <p>Dear valued customer, your PayPal account has been SUSPENDED due to security concerns.</p>
            <p>Please <a href="http://paypal-verify-secure.tk">CLICK HERE</a> to verify your identity immediately.</p>
            <form action="http://malicious-site.com/steal">
                <input type="text" placeholder="Email" required>
                <input type="password" placeholder="Password" required>
                <button type="submit">VERIFY NOW</button>
            </form>
            <p>⚠️ ACT NOW - Limited time offer!</p>
        </body>
        </html>
        """,
        """
        <html>
        <body>
            <h1>Microsoft Security Alert</h1>
            <p>Your Microsoft account has been compromised. Immediate action required.</p>
            <p>Please confirm your identity to unlock your account.</p>
            <form action="http://fake-microsoft-verify.ga">
                <input type="email" placeholder="Email address" required>
                <input type="password" placeholder="Password" required>
                <input type="text" placeholder="Credit card number" required>
                <button type="submit">SECURE VERIFICATION</button>
            </form>
            <img src="microsoft-logo.png" alt="Microsoft Security">
        </body>
        </html>
        """,
        """
        <html>
        <body>
            <h1>URGENT: Amazon Account Suspended!</h1>
            <p>Your Amazon account has been SUSPENDED due to suspicious activity.</p>
            <p>Please verify your identity immediately to restore access.</p>
            <form action="http://amazon-verify-secure.tk">
                <input type="email" placeholder="Email" required>
                <input type="password" placeholder="Password" required>
                <input type="text" placeholder="Credit Card Number" required>
                <button type="submit">VERIFY NOW</button>
            </form>
            <p>⚠️ LIMITED TIME - Act now or lose access forever!</p>
        </body>
        </html>
        """,
        """
        <html>
        <body>
            <h1>Google Security Alert</h1>
            <p>Your Google account has been compromised. Immediate action required.</p>
            <p>Please confirm your identity to unlock your account.</p>
            <form action="http://google-verify-secure.ga">
                <input type="email" placeholder="Gmail address" required>
                <input type="password" placeholder="Password" required>
                <input type="text" placeholder="Phone number" required>
                <button type="submit">SECURE VERIFICATION</button>
            </form>
            <img src="google-logo.png" alt="Google Security">
        </body>
        </html>
        """
    ]
    
    legitimate_html_samples = [
        """
        <html>
        <body>
            <h1>Welcome to PayPal</h1>
            <p>Thank you for using PayPal. Your account is secure.</p>
            <p>For support, visit our <a href="https://help.paypal.com">help center</a>.</p>
        </body>
        </html>
        """,
        """
        <html>
        <body>
            <h1>Microsoft Account</h1>
            <p>Sign in to your Microsoft account to access your services.</p>
            <form action="https://login.microsoftonline.com">
                <input type="email" placeholder="Email" required>
                <input type="password" placeholder="Password" required>
                <button type="submit">Sign in</button>
            </form>
        </body>
        </html>
        """,
        """
        <html>
        <body>
            <h1>Welcome to Amazon</h1>
            <p>Sign in to your Amazon account to access your orders and settings.</p>
            <form action="https://www.amazon.com/ap/signin">
                <input type="email" placeholder="Email" required>
                <input type="password" placeholder="Password" required>
                <button type="submit">Sign in</button>
            </form>
            <p>New customer? <a href="https://www.amazon.com/register">Start here</a></p>
        </body>
        </html>
        """,
        """
        <html>
        <body>
            <h1>Google Account</h1>
            <p>Sign in to your Google account to access Gmail, Drive, and more.</p>
            <form action="https://accounts.google.com/signin">
                <input type="email" placeholder="Email or phone" required>
                <input type="password" placeholder="Password" required>
                <button type="submit">Next</button>
            </form>
            <p>Forgot email? <a href="https://accounts.google.com/signin/recovery">Get help</a></p>
        </body>
        </html>
        """
    ]
    
    content_samples = phishing_html_samples + legitimate_html_samples
    labels = [1] * len(phishing_html_samples) + [0] * len(legitimate_html_samples)
    
    return content_samples, labels


if __name__ == "__main__":
    # Example training
    content_samples, labels = generate_content_training_data()
    
    detector = ContentPhishingDetector()
    detector.train(content_samples, labels, content_type='html')
    
    # Test predictions
    test_content = [
        """
        <html>
        <body>
            <h1>URGENT: Account Suspended!</h1>
            <p>Your account has been suspended. Verify now!</p>
            <form action="http://fake-verify.com">
                <input type="password" placeholder="Password">
                <button>VERIFY</button>
            </form>
        </body>
        </html>
        """,
        """
        <html>
        <body>
            <h1>Welcome to Google</h1>
            <p>Sign in to your Google account.</p>
            <form action="https://accounts.google.com">
                <input type="email" placeholder="Email">
                <button>Sign in</button>
            </form>
        </body>
        </html>
        """
    ]
    
    for content in test_content:
        result = detector.predict(content, content_type='html')
        print(f"Phishing probability: {result['phishing_probability']:.4f}")
        print(f"Prediction: {'PHISHING' if result['prediction'] else 'LEGITIMATE'}")
        print(f"Confidence: {result['confidence']:.4f}")
        print("---") 
