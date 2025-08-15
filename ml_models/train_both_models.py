#!/usr/bin/env python3
"""
Train Both ML Models (URL Classifier and Content Analyzer)
This script trains both the URL threat classifier and content phishing detector
Enhanced with government domain dataset for better legitimate site recognition
"""

import sys
import os
import logging
import requests
import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Tuple, Dict, Any
import time
import random
import re

# Add the ml_models directory to the path
sys.path.append(str(Path(__file__).parent))

from url_classifier import URLThreatClassifier
from content_analyzer import ContentPhishingDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CombinedDataLoader:
    """Loads and processes data for both URL and content training"""
    
    def __init__(self):
        self.phishing_army_url = "https://phishing.army/download/phishing_army_blocklist_extended.txt"
        self.urlhaus_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
        self.openphish_url = "https://openphish.com/feed.txt"
        
        # Government domains dataset from the provided gist
        self.government_domains = [
            # .gov.in domains (major government websites)
            "aavin.tn.gov.in", "abnhpm.gov.in", "agnii.gov.in", "ap.gov.in", "aponline.gov.in",
            "appolice.gov.in", "attendance.gov.in", "cgg.gov.in", "eccs.gov.in", "edisha.gov.in",
            "enam.gov.in", "eoffice.gov.in", "gst.gov.in", "haryanatax.gov.in", "incometaxindiaefiling.gov.in",
            "indiapost.gov.in", "irdai.gov.in", "itschool.gov.in", "jscb.gov.in", "kvic.gov.in",
            "maharashtra.gov.in", "mbmc.gov.in", "mcd.gov.in", "mhada.gov.in", "mnre.gov.in",
            "nielit.gov.in", "nrsc.gov.in", "nsez.gov.in", "odishatax.gov.in", "odishatreasury.gov.in",
            "parivahan.gov.in", "phedharyana.gov.in", "punjab.gov.in", "rcil.gov.in", "shar.gov.in",
            "telangana.gov.in", "tnschools.gov.in", "trai.gov.in", "tspsc.gov.in", "112.gov.in",
            "11thnationalegovconf.gov.in", "12thplan.gov.in", "aaad.gov.in", "aaccc.gov.in",
            "aadhaar.hp.gov.in", "aadhaar.jharkhand.gov.in", "aadhaar.maharashtra.gov.in",
            "aadhaar.rajasthan.gov.in", "aagac.puducherry.gov.in", "aahar.jharkhand.gov.in",
            "aaib.gov.in", "aajeevika.gov.in", "aaplesarkar.mahaonline.gov.in", "aaplesarkar.maharashtra.gov.in",
            "aasc.assam.gov.in", "ab.dcmsme.gov.in", "abcd.kdisc.kerala.gov.in", "acabcmis.gov.in",
            "acb.mizoram.gov.in", "acb.rajasthan.gov.in", "acbap.gov.in", "accessibleindia.gov.in",
            "accountingonline.gov.in", "activesync.mahafireservice.gov.in", "actrec.gov.in",
            "acy.bsf.gov.in", "adgenez.gov.in", "adibasikalyan.gov.in", "adilabad.telangana.gov.in",
            "admin.nsd.gov.in", "ads.kerala.gov.in", "ads2.kerala.gov.in", "advgen.rajasthan.gov.in",
            "ae.uk.gov.in", "aeoindia.gov.in", "aera.gov.in", "aerc.assam.gov.in", "aerc.gov.in",
            "afk.gov.in", "aftjaipur.gov.in", "ag36g.cag.gov.in", "agartalacity.tripura.gov.in",
            "agarun.cag.gov.in", "agbihar.cag.gov.in", "aghp.cag.gov.in", "aghr.cag.gov.in",
            "agisac.gov.in", "agjh.cag.gov.in", "agjk.cag.gov.in", "agkar.cag.gov.in",
            "agker.cag.gov.in", "agmarknet.gov.in", "agmarkonline.dmi.gov.in", "agmc.gov.in",
            "agmegh.cag.gov.in", "agmpr.cag.gov.in", "agodisha.gov.in", "agprmp.gov.in",
            "agpunjab.gov.in", "agrafort.gov.in", "agraj.cag.gov.in", "agri-insurance.gov.in",
            "agri.arunachal.gov.in", "agri.gujarat.gov.in", "agri.puducherry.gov.in",
            "agri.telangana.gov.in", "agri.tripura.gov.in", "agricoop.gov.in", "agriculture.mizoram.gov.in",
            "agriculture.uk.gov.in", "agridept.cg.gov.in", "agriexchange.apeda.gov.in",
            "agriharyana.gov.in", "agrimanipur.gov.in", "agrimarketing.telangana.gov.in",
            "agripb.gov.in", "agskm.cag.gov.in", "agua.cag.gov.in", "agup.cag.gov.in",
            "agup.gov.in", "agwb.cag.gov.in", "ah.jharkhand.gov.in", "ahcichittagong.gov.in",
            "ahcikandy.gov.in", "ahcikhulna.gov.in", "ahcisylhet.gov.in", "ahd.cg.gov.in",
            "ahd.maharashtra.gov.in", "ahd.puducherry.gov.in", "ahd.tn.gov.in", "ahd.uk.gov.in",
            "ahddf.telangana.gov.in", "ahmedabad.cipet.gov.in", "ahmedabad.gujarat.gov.in",
            "ahmedabadcity.gov.in", "ahmedabadcustoms.gov.in", "ahmedabaddp.gujarat.gov.in",
            "ahrc.gov.in", "ahvety.mizoram.gov.in", "ahvs.andaman.gov.in", "aifa.assam.gov.in",
            "aiia.gov.in", "aiihph.gov.in", "aiipmr.gov.in", "aij.gov.in", "aim.gov.in",
            "airguwahati.gov.in", "airmenselection.gov.in", "airpanaji.gov.in", "airportspecialcargo.gov.in",
            "airsewa.gov.in", "aistic.gov.in", "aizawlddma.mizoram.gov.in", "aizawldrda.mizoram.gov.in",
            "ajmer.rajasthan.gov.in", "akola.gov.in", "akolapolice.gov.in", "akolazp.gov.in",
            "akshayaposhan.gov.in", "alberthalljaipur.gov.in", "alipurduar.gov.in", "allahabad.gov.in",
            "allahabadmc.gov.in", "alwar.rajasthan.gov.in",
            
            # Additional government domains from the dataset
            "gst.gov.in", "incometaxindiaefiling.gov.in", "indiapost.gov.in", "irdai.gov.in",
            "parivahan.gov.in", "trai.gov.in", "cgg.gov.in", "eccs.gov.in", "edisha.gov.in",
            "enam.gov.in", "eoffice.gov.in", "haryanatax.gov.in", "itschool.gov.in", "jscb.gov.in",
            "kvic.gov.in", "mbmc.gov.in", "mcd.gov.in", "mhada.gov.in", "mnre.gov.in",
            "nielit.gov.in", "nrsc.gov.in", "nsez.gov.in", "odishatax.gov.in", "odishatreasury.gov.in",
            "phedharyana.gov.in", "punjab.gov.in", "rcil.gov.in", "shar.gov.in", "telangana.gov.in",
            "tnschools.gov.in", "tspsc.gov.in", "112.gov.in", "11thnationalegovconf.gov.in",
            "12thplan.gov.in", "aaad.gov.in", "aaccc.gov.in", "aadhaar.hp.gov.in",
            "aadhaar.jharkhand.gov.in", "aadhaar.maharashtra.gov.in", "aadhaar.rajasthan.gov.in",
            "aagac.puducherry.gov.in", "aahar.jharkhand.gov.in", "aaib.gov.in", "aajeevika.gov.in",
            "aaplesarkar.mahaonline.gov.in", "aaplesarkar.maharashtra.gov.in", "aasc.assam.gov.in",
            "ab.dcmsme.gov.in", "abcd.kdisc.kerala.gov.in", "acabcmis.gov.in", "acb.mizoram.gov.in",
            "acb.rajasthan.gov.in", "acbap.gov.in", "accessibleindia.gov.in", "accountingonline.gov.in",
            "activesync.mahafireservice.gov.in", "actrec.gov.in", "acy.bsf.gov.in", "adgenez.gov.in",
            "adibasikalyan.gov.in", "adilabad.telangana.gov.in", "admin.nsd.gov.in", "ads.kerala.gov.in",
            "ads2.kerala.gov.in", "advgen.rajasthan.gov.in", "ae.uk.gov.in", "aeoindia.gov.in",
            "aera.gov.in", "aerc.assam.gov.in", "aerc.gov.in", "afk.gov.in", "aftjaipur.gov.in",
            "ag36g.cag.gov.in", "agartalacity.tripura.gov.in", "agarun.cag.gov.in", "agbihar.cag.gov.in",
            "aghp.cag.gov.in", "aghr.cag.gov.in", "agisac.gov.in", "agjh.cag.gov.in", "agjk.cag.gov.in",
            "agkar.cag.gov.in", "agker.cag.gov.in", "agmarknet.gov.in", "agmarkonline.dmi.gov.in",
            "agmc.gov.in", "agmegh.cag.gov.in", "agmpr.cag.gov.in", "agodisha.gov.in", "agprmp.gov.in",
            "agpunjab.gov.in", "agrafort.gov.in", "agraj.cag.gov.in", "agri-insurance.gov.in",
            "agri.arunachal.gov.in", "agri.gujarat.gov.in", "agri.puducherry.gov.in", "agri.telangana.gov.in",
            "agri.tripura.gov.in", "agricoop.gov.in", "agriculture.mizoram.gov.in", "agriculture.uk.gov.in",
            "agridept.cg.gov.in", "agriexchange.apeda.gov.in", "agriharyana.gov.in", "agrimanipur.gov.in",
            "agrimarketing.telangana.gov.in", "agripb.gov.in", "agskm.cag.gov.in", "agua.cag.gov.in",
            "agup.cag.gov.in", "agup.gov.in", "agwb.cag.gov.in", "ah.jharkhand.gov.in", "https://karnataka.gov.in/"
            "ahcichittagong.gov.in", "ahcikandy.gov.in", "ahcikhulna.gov.in", "ahcisylhet.gov.in",
            "ahd.cg.gov.in", "ahd.maharashtra.gov.in", "ahd.puducherry.gov.in", "ahd.tn.gov.in",
            "ahd.uk.gov.in", "ahddf.telangana.gov.in", "ahmedabad.cipet.gov.in", "ahmedabad.gujarat.gov.in",
            "ahmedabadcity.gov.in", "ahmedabadcustoms.gov.in", "ahmedabaddp.gujarat.gov.in",
            "ahrc.gov.in", "ahvety.mizoram.gov.in", "ahvs.andaman.gov.in", "aifa.assam.gov.in",
            "aiia.gov.in", "aiihph.gov.in", "aiipmr.gov.in", "aij.gov.in", "aim.gov.in",
            "aadhaar.uidai.gov.in","services.india.gov.in","services.gov.in","services.gov.in/aadhaar",
            "airguwahati.gov.in", "airmenselection.gov.in", "airpanaji.gov.in", "airportspecialcargo.gov.in",
            "airsewa.gov.in", "aistic.gov.in", "aizawlddma.mizoram.gov.in", "aizawldrda.mizoram.gov.in",
            "ajmer.rajasthan.gov.in", "akola.gov.in", "akolapolice.gov.in", "akolazp.gov.in",
            "akshayaposhan.gov.in", "alberthalljaipur.gov.in", "alipurduar.gov.in", "allahabad.gov.in",
            "allahabadmc.gov.in", "alwar.rajasthan.gov.in","www.karnataka.gov.in/", "sevasindhuservices.karnataka.gov.in/",
        ]
        
        # Other legitimate domains
        self.legitimate_urls = [
            "https://google.com", "https://facebook.com", "https://amazon.com",
            "https://microsoft.com", "https://apple.com", "https://paypal.com",
            "https://netflix.com", "https://github.com", "https://stackoverflow.com",
            "https://wikipedia.org", "https://youtube.com", "https://twitter.com",
            "https://linkedin.com", "https://reddit.com", "https://instagram.com",
            "https://discord.com", "https://spotify.com", "https://twitch.tv",
            "https://zoom.us", "https://slack.com", "https://dropbox.com",
            "https://airbnb.com", "https://uber.com", "https://lyft.com",
            "https://doordash.com", "https://grubhub.com", "https://ebay.com",
            "https://etsy.com", "https://shopify.com", "https://stripe.com",
            "https://square.com", "https://venmo.com", "https://cashapp.com",
            "https://coinbase.com", "https://binance.com", "https://kraken.com",
            "https://robinhood.com", "https://fidelity.com", "https://vanguard.com",
            "https://schwab.com", "https://etrade.com", "https://tdameritrade.com",
            "https://wellsfargo.com", "https://chase.com", "https://bankofamerica.com",
            "https://citibank.com", "https://usbank.com", "https://barclays.com",
            "https://lloydsbank.com", "https://santander.com", "https://hsbc.com"
        ]
    
    def download_phishing_data(self) -> Tuple[List[str], List[str]]:
        """Download phishing domains and URLs from multiple sources"""
        phishing_domains = []
        openphish_urls = []
        malicious_urls = []
        
        # Download from Phishing Army
        try:
            logger.info("Downloading Phishing Army data...")
            response = requests.get(self.phishing_army_url, timeout=30)
            response.raise_for_status()
            
            lines = response.text.split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('='):
                    phishing_domains.append(line)
            
            logger.info(f"Downloaded {len(phishing_domains)} domains from Phishing Army")
        except Exception as e:
            logger.warning(f"Failed to download Phishing Army data: {e}")
        
        # Download from URLhaus
        try:
            logger.info("Downloading URLhaus data...")
            response = requests.get(self.urlhaus_url, timeout=30)
            response.raise_for_status()
            
            lines = response.text.split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#') and ',' in line:
                    parts = line.split(',')
                    if len(parts) >= 2:
                        url = parts[2].strip('"')
                        if url.startswith('http'):
                            malicious_urls.append(url)

            logger.info(f"Downloaded {len(malicious_urls)} URLs from URLhaus")
        except Exception as e:
            logger.warning(f"Failed to download URLhaus data: {e}")
        
        return phishing_domains, malicious_urls, openphish_urls
    
    def create_url_training_dataset(self, phishing_domains: List[str], 
                                  malicious_urls: List[str]) -> Tuple[List[str], List[int]]:
        """Create training dataset for URL classifier with balanced data including government domains"""
        urls = []
        labels = []
        
        # Add government domains as legitimate URLs
        government_urls = []
        for domain in self.government_domains:
            government_urls.extend([
                f"https://{domain}",
                f"http://{domain}",
                f"https://{domain}/",
                f"https://{domain}/login",
                f"https://{domain}/signup",
                f"https://{domain}/account",
                f"https://{domain}/profile",
                f"https://{domain}/settings",
                f"https://{domain}/help",
                f"https://{domain}/support",
                f"https://{domain}/about",
                f"https://{domain}/contact",
                f"https://{domain}/services",
                f"https://{domain}/forms",
                f"https://{domain}/download",
                f"https://{domain}/apply",
                f"https://{domain}/status",
                f"https://{domain}/track",
                f"https://{domain}/verify",
                f"https://{domain}/certificate"
            ])
        
        # Add legitimate URLs (expand the list for better balance)
        legitimate_urls_expanded = []
        for url in self.legitimate_urls:
            legitimate_urls_expanded.extend([
                url,
                f"{url}/login",
                f"{url}/signup",
                f"{url}/account",
                f"{url}/profile",
                f"{url}/settings",
                f"{url}/help",
                f"{url}/support",
                f"{url}/about",
                f"{url}/contact"
            ])
        
        # Combine government and other legitimate URLs
        all_legitimate_urls = government_urls + legitimate_urls_expanded
        
        # Limit legitimate samples to avoid imbalance (prioritize government domains)
        government_limit = min(1000, len(government_urls))  # 1000 government samples
        other_legitimate_limit = 500  # 500 other legitimate samples
        
        # Add government URLs first (prioritized)
        for url in government_urls[:government_limit]:
            urls.append(url)
            labels.append(0)  # Safe
        
        # Add other legitimate URLs
        for url in legitimate_urls_expanded[:other_legitimate_limit]:
            urls.append(url)
            labels.append(0)  # Safe
        
        # Add phishing domains as URLs (limit to balance with safe samples)
        malicious_samples = []
        for domain in phishing_domains[:300]:  # Limit to 300 domains
            malicious_samples.extend([
                f"https://{domain}",
                f"http://{domain}",
                f"https://{domain}/login",
                f"https://{domain}/verify",
                f"https://{domain}/secure",
                f"https://{domain}/account",
                f"https://{domain}/bank",
                f"https://{domain}/paypal"
            ])
        
        # Add malicious URLs from URLhaus (limit to balance)
        for url in malicious_urls[:300]:  # Limit to 300 URLs
            malicious_samples.append(url)
        
        # Add synthetic malicious URLs
        synthetic_malicious = [
            "https://g00gle.com/verify",
            "http://192.168.1.1/login",
            "https://paypal-secure-verify.tk",
            "http://secure-bank-update123.tk",
            "https://microsoft-security-alert.cf",
            "https://fake-login.net/secure",
            "http://suspicious-domain.ml/verify",
            "https://phishing-site.ga/login",
            "http://malicious-url.click/secure",
            "https://fake-bank.info/update",
            "https://gov-in-secure.tk/verify",
            "http://government-verify.ml/login",
            "https://tax-refund-secure.cf/update",
            "http://aadhaar-verify.tk/secure",
            "https://gst-payment-secure.ga/verify"
        ]
        
        for url in synthetic_malicious:
            malicious_samples.append(url)
        
        # Add balanced malicious samples
        for url in malicious_samples[:1500]:  # Limit to 1500 malicious samples
            urls.append(url)
            labels.append(1)  # Malicious
        
        logger.info(f"URL dataset: {len([l for l in labels if l == 0])} safe (including {len([u for u in urls[:government_limit] if u in government_urls])} government), {len([l for l in labels if l == 1])} malicious")
        return urls, labels
    
    def create_content_training_dataset(self, phishing_domains: List[str], 
                                     malicious_urls: List[str]) -> Tuple[List[str], List[int]]:
        """Create training dataset for content analyzer using phishing URLs"""
        content_samples = []
        labels = []
        
        # Generate legitimate content samples including government websites
        legitimate_samples = [
            # Government website templates
            """
            <html>
            <head><title>Government of India - Official Portal</title></head>
            <body>
                <header>
                    <h1>Government of India</h1>
                    <nav>
                        <a href="/services">Services</a>
                        <a href="/departments">Departments</a>
                        <a href="/citizen-services">Citizen Services</a>
                    </nav>
                </header>
                <main>
                    <h2>Welcome to the Official Government Portal</h2>
                    <p>Access government services, forms, and information securely.</p>
                    <div class="services">
                        <h3>Popular Services</h3>
                        <ul>
                            <li><a href="/aadhaar">Aadhaar Services</a></li>
                            <li><a href="/gst">GST Services</a></li>
                            <li><a href="/income-tax">Income Tax</a></li>
                            <li><a href="/passport">Passport Services</a></li>
                        </ul>
                    </div>
                </main>
                <footer>
                    <p>&copy; 2024 Government of India. All rights reserved.</p>
                </footer>
            </body>
            </html>
            """,
            """
            <html>
            <head><title>GST Portal - Government of India</title></head>
            <body>
                <header>
                    <h1>GST Portal</h1>
                    <p>Goods and Services Tax - Government of India</p>
                </header>
                <main>
                    <h2>GST Services</h2>
                    <p>Access GST-related services and information.</p>
                    <form action="/login" method="post">
                        <input type="text" name="username" placeholder="GST Number">
                        <input type="password" name="password" placeholder="Password">
                        <button type="submit">Login</button>
                    </form>
                    <div class="services">
                        <h3>Available Services</h3>
                        <ul>
                            <li>GST Registration</li>
                            <li>GST Returns</li>
                            <li>GST Payments</li>
                            <li>GST Refunds</li>
                        </ul>
                    </div>
                </main>
            </body>
            </html>
            """,
            """
            <html>
            <head><title>Income Tax Department - Government of India</title></head>
            <body>
                <header>
                    <h1>Income Tax Department</h1>
                    <p>Government of India</p>
                </header>
                <main>
                    <h2>Income Tax Services</h2>
                    <p>File your income tax returns and access tax-related services.</p>
                    <form action="/login" method="post">
                        <input type="text" name="pan" placeholder="PAN Number">
                        <input type="password" name="password" placeholder="Password">
                        <button type="submit">Login</button>
                    </form>
                    <div class="services">
                        <h3>Tax Services</h3>
                        <ul>
                            <li>File ITR</li>
                            <li>View 26AS</li>
                            <li>Tax Calculator</li>
                            <li>Refund Status</li>
                        </ul>
                    </div>
                </main>
            </body>
            </html>
            """,
            """
            <html>
            <head><title>Aadhaar Services - UIDAI</title></head>
            <body>
                <header>
                    <h1>Aadhaar Services</h1>
                    <p>Unique Identification Authority of India</p>
                </header>
                <main>
                    <h2>Aadhaar Services Portal</h2>
                    <p>Access Aadhaar-related services and information.</p>
                    <div class="services">
                        <h3>Available Services</h3>
                        <ul>
                            <li>Aadhaar Enrollment</li>
                            <li>Aadhaar Update</li>
                            <li>Aadhaar Authentication</li>
                            <li>Download Aadhaar</li>
                        </ul>
                    </div>
                    <p>For official services, visit <a href="https://uidai.gov.in">uidai.gov.in</a></p>
                </main>
            </body>
            </html>
            """,
            # Regular legitimate website templates
            """
            <html>
            <head><title>Welcome to Google</title></head>
            <body>
                <h1>Welcome to Google</h1>
                <p>Search the world's information, including webpages, images, videos and more.</p>
                <form action="/search">
                    <input type="text" name="q" placeholder="Search Google">
                    <button type="submit">Search</button>
                </form>
            </body>
            </html>
            """,
            """
            <html>
            <head><title>Facebook - Log In or Sign Up</title></head>
            <body>
                <h1>Facebook</h1>
                <p>Connect with friends and the world around you on Facebook.</p>
                <form action="/login">
                    <input type="email" placeholder="Email or phone number">
                    <input type="password" placeholder="Password">
                    <button type="submit">Log In</button>
                </form>
            </body>
            </html>
            """,
            """
            <html>
            <head><title>Amazon.com: Online Shopping</title></head>
            <body>
                <h1>Amazon.com</h1>
                <p>Shop online for electronics, computers, clothing, shoes, toys, books, DVDs and more.</p>
                <div class="search">
                    <input type="text" placeholder="Search Amazon">
                    <button>Search</button>
                </div>
            </body>
            </html>
            """,
            """
            <html>
            <head><title>PayPal - Send and Request Money</title></head>
            <body>
                <h1>PayPal</h1>
                <p>Send and request money with friends and family. It's free to send money to friends and family.</p>
                <form action="/login">
                    <input type="email" placeholder="Email">
                    <input type="password" placeholder="Password">
                    <button type="submit">Log In</button>
                </form>
            </body>
            </html>
            """,
            """
            <html>
            <head><title>Microsoft - Cloud, Computers, Apps & Gaming</title></head>
            <body>
                <h1>Microsoft</h1>
                <p>Explore Microsoft products and services for your home or business. Shop Surface, Microsoft 365, Xbox, Windows, Azure and more.</p>
                <div class="search">
                    <input type="text" placeholder="Search Microsoft">
                    <button>Search</button>
                </div>
            </body>
            </html>
            """,
            """
            <html>
            <head><title>Bank of America - Banking, Credit Cards, Home Loans</title></head>
            <body>
                <h1>Bank of America</h1>
                <p>Bank of America provides banking, credit cards, home loans, auto loans and investment services.</p>
                <form action="/login">
                    <input type="text" placeholder="Online ID">
                    <input type="password" placeholder="Passcode">
                    <button type="submit">Sign In</button>
                </form>
            </body>
            </html>
            """
        ]
        
        # Add more legitimate samples with variations
        for i in range(30):  # Generate 30 more legitimate samples
            legitimate_samples.append(f"""
            <html>
            <head><title>Legitimate Website {i+1}</title></head>
            <body>
                <h1>Welcome to Our Service</h1>
                <p>This is a legitimate website providing useful services to our customers.</p>
                <nav>
                    <a href="/about">About</a>
                    <a href="/contact">Contact</a>
                    <a href="/services">Services</a>
                </nav>
                <div class="content">
                    <p>We are committed to providing excellent service and maintaining the highest standards of security.</p>
                </div>
            </body>
            </html>
            """)
        
        for sample in legitimate_samples:
            content_samples.append(sample)
            labels.append(0)  # Safe
        
        # Generate phishing content samples from phishing domains
        phishing_templates = [
            # Government phishing template
            """
            <html>
            <head><title>🔒 Government Security Alert</title></head>
            <body>
                <h1>🔒 Government Security Alert</h1>
                <p>Your government account has been compromised. Immediate verification required to prevent account suspension.</p>
                <div style="background: #ff0000; color: white; padding: 10px;">
                    <strong>IMMEDIATE ACTION REQUIRED</strong>
                </div>
                <form action="https://{domain}">
                    <input type="text" placeholder="Aadhaar Number">
                    <input type="text" placeholder="PAN Number">
                    <input type="password" placeholder="Password">
                    <input type="text" placeholder="Bank Account Number">
                    <input type="text" placeholder="IFSC Code">
                    <button type="submit">VERIFY ACCOUNT</button>
                </form>
                <p>🔐 Government Security Verified | SSL Secure</p>
            </body>
            </html>
            """,
            # GST phishing template
            """
            <html>
            <head><title>GST Portal - Security Update</title></head>
            <body>
                <h1>GST Portal Security Update</h1>
                <p>Your GST account requires immediate security verification. Failure to verify may result in permanent account suspension.</p>
                <div style="border: 2px solid red; padding: 15px;">
                    <h2>⚠️ CRITICAL SECURITY ALERT ⚠️</h2>
                    <p>Your GST account has been compromised. Verify your identity immediately.</p>
                </div>
                <form action="http://{domain}">
                    <input type="text" placeholder="GST Number">
                    <input type="password" placeholder="Password">
                    <input type="text" placeholder="Bank Account Number">
                    <input type="text" placeholder="IFSC Code">
                    <input type="text" placeholder="Mobile Number">
                    <button type="submit">VERIFY GST ACCOUNT</button>
                </form>
                <p>🔒 GST Security Verified | 256-bit SSL Encryption</p>
            </body>
            </html>
            """,
            # PayPal phishing template
            """
            <html>
            <head><title>🔒 PayPal Security Alert</title></head>
            <body>
                <h1>🔒 PayPal Security Alert</h1>
                <p>We detected unusual activity on your PayPal account. Your account has been temporarily limited for security reasons.</p>
                <div style="background: #ff0000; color: white; padding: 10px;">
                    <strong>IMMEDIATE ACTION REQUIRED</strong>
                </div>
                <form action="https://{domain}">
                    <input type="email" placeholder="PayPal Email">
                    <input type="password" placeholder="PayPal Password">
                    <input type="text" placeholder="Bank Account Number">
                    <input type="text" placeholder="Social Security Number">
                    <button type="submit">SECURE VERIFICATION</button>
                </form>
                <p>🔐 Norton Security Verified | SSL Secure</p>
            </body>
            </html>
            """,
            # Microsoft phishing template
            """
            <html>
            <head><title>Microsoft Account - Security Update</title></head>
            <body>
                <h1>Microsoft Account Security Update</h1>
                <p>Your Microsoft account requires immediate security verification. Failure to verify may result in permanent account suspension.</p>
                <div style="border: 2px solid red; padding: 15px;">
                    <h2>⚠️ CRITICAL SECURITY ALERT ⚠️</h2>
                    <p>Your account has been compromised. Verify your identity immediately.</p>
                </div>
                <form action="http://{domain}">
                    <input type="email" placeholder="Microsoft Email">
                    <input type="password" placeholder="Password">
                    <input type="text" placeholder="Phone Number">
                    <input type="text" placeholder="Date of Birth">
                    <input type="text" placeholder="Mother's Maiden Name">
                    <button type="submit">VERIFY ACCOUNT</button>
                </form>
                <p>🔒 McAfee Security Verified | 256-bit SSL Encryption</p>
            </body>
            </html>
            """,
            # Bank phishing template
            """
            <html>
            <head><title>Bank of America - Account Locked</title></head>
            <body>
                <h1>Bank of America - Account Security Alert</h1>
                <p>Your Bank of America account has been locked due to multiple failed login attempts. Unlock your account now.</p>
                <div style="background: #ff6600; color: white; padding: 10px;">
                    <strong>ACCOUNT LOCKED - IMMEDIATE ACTION REQUIRED</strong>
                </div>
                <form action="https://{domain}">
                    <input type="text" placeholder="Account Number">
                    <input type="password" placeholder="Online Banking Password">
                    <input type="text" placeholder="Debit Card Number">
                    <input type="text" placeholder="CVV">
                    <input type="text" placeholder="ATM PIN">
                    <button type="submit">UNLOCK ACCOUNT</button>
                </form>
                <p>🔐 Verisign Secured | 128-bit SSL</p>
            </body>
            </html>
            """,
            # Google phishing template
            """
            <html>
            <head><title>Google Account - Suspension Notice</title></head>
            <body>
                <h1>Google Account Suspension Notice</h1>
                <p>Your Google account has been suspended due to violation of our terms of service. Appeal this decision now.</p>
                <div style="border: 3px solid #ff0000; padding: 20px;">
                    <h2>🚨 ACCOUNT SUSPENDED 🚨</h2>
                    <p>Your account will be permanently deleted in 24 hours unless you verify your identity.</p>
                </div>
                <form action="http://{domain}">
                    <input type="email" placeholder="Gmail Address">
                    <input type="password" placeholder="Gmail Password">
                    <input type="text" placeholder="Recovery Phone">
                    <input type="text" placeholder="Recovery Email">
                    <button type="submit">APPEAL SUSPENSION</button>
                </form>
                <p>🔒 Google Security Verified | SSL Certificate Valid</p>
            </body>
            </html>
            """,
            # Generic phishing template
            """
            <html>
            <head><title>URGENT: Account Suspended!</title></head>
            <body>
                <h1>URGENT: Your Account Has Been Suspended!</h1>
                <p>Your account has been suspended due to suspicious activity. Verify your identity immediately to restore access.</p>
                <form action="http://{domain}">
                    <input type="text" placeholder="Full Name">
                    <input type="email" placeholder="Email Address">
                    <input type="password" placeholder="Password">
                    <input type="text" placeholder="Credit Card Number">
                    <input type="text" placeholder="CVV">
                    <button type="submit">VERIFY NOW</button>
                </form>
                <p style="color: red;">⚠️ URGENT: Action required within 24 hours!</p>
            </body>
            </html>
            """
        ]
        
        # Generate phishing content from phishing domains
        for domain in phishing_domains[:150]:  # Use first 150 domains
            for template in phishing_templates:
                content = template.format(domain=domain)
                content_samples.append(content)
                labels.append(1)  # Phishing
        
        # Generate phishing content from malicious URLs
        for url in malicious_urls[:75]:  # Use first 75 URLs
            domain = url.split('/')[2] if '://' in url else url.split('/')[0]
            for template in phishing_templates[:3]:  # Use first 3 templates
                content = template.format(domain=domain)
                content_samples.append(content)
                labels.append(1)  # Phishing
        
        logger.info(f"Content dataset: {len([l for l in labels if l == 0])} safe, {len([l for l in labels if l == 1])} phishing")
        return content_samples, labels

class CombinedModelTrainer:
    """Trains both URL classifier and content analyzer"""
    
    def __init__(self):
        self.url_classifier = URLThreatClassifier()
        self.content_detector = ContentPhishingDetector()
    
    def train_both_models(self, url_data: Tuple[List[str], List[int]], 
                         content_data: Tuple[List[str], List[int]]) -> Dict[str, Any]:
        """Train both URL classifier and content analyzer"""
        urls, url_labels = url_data
        content_samples, content_labels = content_data
        
        logger.info("Training URL classifier...")
        self.url_classifier.train(urls, url_labels)
        
        logger.info("Training content analyzer...")
        self.content_detector.train(content_samples, content_labels, content_type='html')
        
        # Save both models
        models_dir = Path("ml_models/saved_models")
        models_dir.mkdir(parents=True, exist_ok=True)
        
        self.url_classifier.save_model(str(models_dir / "url_classifier.joblib"))
        self.content_detector.save_model(str(models_dir / "content_detector.joblib"))
        
        logger.info("Both models trained and saved successfully!")
        
        return {
            'url_classifier_trained': self.url_classifier.is_trained,
            'content_detector_trained': self.content_detector.is_trained,
            'url_model_path': str(models_dir / "url_classifier.joblib"),
            'content_model_path': str(models_dir / "content_detector.joblib")
        }
    
    def evaluate_both_models(self, test_urls: List[str], test_url_labels: List[int],
                           test_content: List[str], test_content_labels: List[int]) -> Dict[str, Any]:
        """Evaluate both models"""
        logger.info("Evaluating both models...")
        
        # Evaluate URL classifier
        url_correct = 0
        url_total = len(test_urls)
        url_confidences = []
        
        for url, true_label in zip(test_urls, test_url_labels):
            prediction = self.url_classifier.predict(url)
            predicted_label = 1 if prediction['prediction'] else 0
            
            if predicted_label == true_label:
                url_correct += 1
            
            url_confidences.append(prediction['confidence'])
        
        url_accuracy = url_correct / url_total if url_total > 0 else 0
        url_avg_confidence = np.mean(url_confidences)
        
        # Evaluate content detector
        content_correct = 0
        content_total = len(test_content)
        content_confidences = []
        
        for content, true_label in zip(test_content, test_content_labels):
            prediction = self.content_detector.predict(content, content_type='html')
            predicted_label = 1 if prediction['prediction'] else 0
            
            if predicted_label == true_label:
                content_correct += 1
            
            content_confidences.append(prediction['confidence'])
        
        content_accuracy = content_correct / content_total if content_total > 0 else 0
        content_avg_confidence = np.mean(content_confidences)
        
        logger.info(f"URL Classifier - Accuracy: {url_accuracy:.4f} ({url_correct}/{url_total})")
        logger.info(f"URL Classifier - Avg Confidence: {url_avg_confidence:.4f}")
        logger.info(f"Content Detector - Accuracy: {content_accuracy:.4f} ({content_correct}/{content_total})")
        logger.info(f"Content Detector - Avg Confidence: {content_avg_confidence:.4f}")
        
        return {
            'url_classifier': {
                'accuracy': url_accuracy,
                'average_confidence': url_avg_confidence,
                'correct_predictions': url_correct,
                'total_predictions': url_total
            },
            'content_detector': {
                'accuracy': content_accuracy,
                'average_confidence': content_avg_confidence,
                'correct_predictions': content_correct,
                'total_predictions': content_total
            }
        }

def main():
    """Main training function for both models"""
    logger.info("Starting combined ML model training...")
    
    # Load data
    data_loader = CombinedDataLoader()
    phishing_domains, malicious_urls, openphish_urls = data_loader.download_phishing_data()
    
    # Create training datasets
    url_data = data_loader.create_url_training_dataset(phishing_domains, malicious_urls)
    content_data = data_loader.create_content_training_dataset(phishing_domains, malicious_urls)
    
    logger.info(f"URL training dataset: {len(url_data[0])} samples")
    logger.info(f"Content training dataset: {len(content_data[0])} samples")
    
    # Train both models
    trainer = CombinedModelTrainer()
    training_result = trainer.train_both_models(url_data, content_data)
    
    # Test both models
    test_urls = [
        "https://google.com",  # Safe
        "https://facebook.com",  # Safe
        "https://gst.gov.in",  # Safe government
        "https://incometaxindiaefiling.gov.in",  # Safe government
        "https://aadhaar.uidai.gov.in",  # Safe government
        "https://g00gle.com/verify",  # Malicious
        "https://paypal-secure-verify.tk",  # Malicious
        "http://192.168.1.1/login",  # Malicious
        "https://gov-in-secure.tk/verify",  # Malicious government impersonation
        "http://aadhaar-verify.tk/secure"  # Malicious government impersonation
    ]
    test_url_labels = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]
    
    test_content = [
        "<html><body><h1>Welcome to Google</h1></body></html>",  # Safe
        "<html><body><h1>Government of India - Official Portal</h1><p>Access government services securely.</p></body></html>",  # Safe government
        "<html><body><h1>GST Portal</h1><p>Goods and Services Tax - Government of India</p></body></html>",  # Safe government
        "<html><body><h1>URGENT: Account Suspended!</h1><form><input type='password'></form></body></html>",  # Phishing
        "<html><body><h1>🔒 Government Security Alert</h1><p>Your government account has been compromised!</p><form><input type='text' placeholder='Aadhaar Number'></form></body></html>"  # Government phishing
    ]
    test_content_labels = [0, 0, 0, 1, 1]
    
    evaluation = trainer.evaluate_both_models(test_urls, test_url_labels, test_content, test_content_labels)
    
    # Test individual predictions
    logger.info("\n=== Combined Model Test Results ===")
    
    logger.info("URL Classifier Tests:")
    for url in test_urls:
        result = trainer.url_classifier.predict(url)
        print(f"URL: {url}")
        print(f"  Threat probability: {result['threat_probability']:.4f}")
        print(f"  Prediction: {'MALICIOUS' if result['prediction'] else 'SAFE'}")
        print(f"  Confidence: {result['confidence']:.4f}")
        print()
    
    logger.info("Content Detector Tests:")
    for i, content in enumerate(test_content):
        result = trainer.content_detector.predict(content, content_type='html')
        print(f"Content {i+1}:")
        print(f"  Phishing probability: {result['phishing_probability']:.4f}")
        print(f"  Prediction: {'PHISHING' if result['prediction'] else 'SAFE'}")
        print(f"  Confidence: {result['confidence']:.4f}")
        print()
    
    logger.info("Combined training completed successfully!")
    logger.info(f"URL model saved as: {training_result['url_model_path']}")
    logger.info(f"Content model saved as: {training_result['content_model_path']}")

if __name__ == "__main__":
    main() 