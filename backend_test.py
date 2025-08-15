#!/usr/bin/env python3
"""
Comprehensive Backend Test Script for WebShield
Tests all major components: ML models, SSL analysis, VirusTotal, threat calculation
"""

import asyncio
import sys
import os
import time
from datetime import datetime

# Add the ml_models directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'ml_models'))

def test_ml_models():
    """Test ML model loading and prediction"""
    print("🔍 Testing ML Models...")
    
    try:
        from ml_integration import MLSecurityEngine
        
        # Test ML engine initialization
        engine = MLSecurityEngine(load_models=True)
        status = engine.get_model_status()
        
        print(f"  ✅ ML Engine Status: {status}")
        
        if not status['url_classifier_trained'] or not status['content_detector_trained']:
            print("  ❌ ML Models not loaded properly!")
            return False
        
        # Test URL analysis
        url_result = engine.analyze_url_ml('http://test.com')
        print(f"  ✅ URL Analysis: ML enabled={url_result['ml_enabled']}, Threat={url_result['threat_probability']:.3f}")
        
        # Test content analysis
        content_result = engine.analyze_content_ml('This is a test content')
        print(f"  ✅ Content Analysis: ML enabled={content_result['ml_enabled']}, Phishing={content_result['phishing_probability']:.3f}")
        
        # Test malicious URL
        malicious_url_result = engine.analyze_url_ml('http://192.168.1.1/login')
        print(f"  ✅ Malicious URL Test: Threat={malicious_url_result['threat_probability']:.3f}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ ML Models test failed: {e}")
        return False

def test_ssl_analysis():
    """Test SSL certificate analysis"""
    print("\n🔒 Testing SSL Analysis...")
    
    try:
        import ssl
        import socket
        import urllib.parse
        
        # Test SSL analysis function
        async def test_ssl():
            from backend.server import WebShieldDetector
            
            detector = WebShieldDetector()
            
            # Test HTTPS URL
            https_result = await detector.analyze_ssl_certificate('https://google.com')
            print(f"  ✅ HTTPS Test: Valid={https_result.get('valid', False)}")
            
            # Test HTTP URL
            http_result = await detector.analyze_ssl_certificate('http://example.com')
            print(f"  ✅ HTTP Test: Valid={http_result.get('valid', False)}")
            
            return True
        
        # Run the async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(test_ssl())
        loop.close()
        
        return result
        
    except Exception as e:
        print(f"  ❌ SSL Analysis test failed: {e}")
        return False

def test_virustotal_integration():
    """Test VirusTotal API integration"""
    print("\n🦠 Testing VirusTotal Integration...")
    
    try:
        # Check if API key is configured
        from dotenv import load_dotenv
        load_dotenv()
        
        vt_api_key = os.getenv('VT_API_KEY')
        if not vt_api_key or vt_api_key == 'your_virustotal_api_key_here':
            print("  ⚠️  VirusTotal API key not configured, skipping test")
            return True
        
        print(f"  ✅ VirusTotal API key found: {vt_api_key[:10]}...")
        
        # Test VirusTotal check function
        async def test_vt():
            from backend.server import WebShieldDetector
            
            detector = WebShieldDetector()
            
            # Test with a known safe URL
            vt_result = await detector.check_virustotal('https://google.com')
            print(f"  ✅ VirusTotal Test: Malicious count={vt_result.get('malicious_count', 0)}")
            
            return True
        
        # Run the async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(test_vt())
        loop.close()
        
        return result
        
    except Exception as e:
        print(f"  ❌ VirusTotal test failed: {e}")
        return False

def test_threat_calculation():
    """Test threat level calculation logic"""
    print("\n⚠️  Testing Threat Calculation...")
    
    try:
        # Test threat calculation logic
        def calculate_threat_level(threat_score, malicious_count, suspicious_count):
            if threat_score > 60 or malicious_count > 3:
                return 'high', True
            elif threat_score > 30 or suspicious_count > 2:
                return 'medium', True
            else:
                return 'low', False
        
        # Test cases
        test_cases = [
            (80, 5, 2, 'high', True),
            (45, 2, 3, 'medium', True),
            (20, 1, 1, 'low', False),
            (70, 4, 1, 'high', True),
            (25, 1, 2, 'low', False)
        ]
        
        all_passed = True
        for threat_score, malicious_count, suspicious_count, expected_level, expected_malicious in test_cases:
            level, malicious = calculate_threat_level(threat_score, malicious_count, suspicious_count)
            
            if level == expected_level and malicious == expected_malicious:
                print(f"  ✅ Test case: Score={threat_score}, Counts=({malicious_count},{suspicious_count}) -> {level}")
            else:
                print(f"  ❌ Test case failed: Score={threat_score}, Counts=({malicious_count},{suspicious_count}) -> Expected: {expected_level}, Got: {level}")
                all_passed = False
        
        return all_passed
        
    except Exception as e:
        print(f"  ❌ Threat calculation test failed: {e}")
        return False

def test_url_analysis():
    """Test URL pattern analysis"""
    print("\n🔗 Testing URL Analysis...")
    
    try:
        from backend.server import WebShieldDetector
        
        detector = WebShieldDetector()
        
        # Test suspicious URL patterns
        test_urls = [
            ('https://google.com', False),  # Safe
            ('http://192.168.1.1/login', True),  # IP address
            ('https://secure-bank-update.tk', True),  # Suspicious TLD
            ('https://g00gle.com/verify', True),  # Typosquatting
            ('https://facebook.com', False),  # Safe
            ('http://amazon-account-suspended.ml', True),  # Suspicious TLD + keywords
        ]
        
        all_passed = True
        for url, expected_suspicious in test_urls:
            result = detector.analyze_url_patterns(url)
            is_suspicious = result.get('is_suspicious', False)
            
            if is_suspicious == expected_suspicious:
                print(f"  ✅ {url}: Expected={expected_suspicious}, Got={is_suspicious}")
            else:
                print(f"  ❌ {url}: Expected={expected_suspicious}, Got={is_suspicious}")
                all_passed = False
        
        return all_passed
        
    except Exception as e:
        print(f"  ❌ URL analysis test failed: {e}")
        return False

def test_content_analysis():
    """Test content analysis functionality"""
    print("\n📄 Testing Content Analysis...")
    
    try:
        from backend.server import WebShieldDetector
        
        detector = WebShieldDetector()
        
        # Test content analysis
        async def test_content():
            # Test safe content
            safe_content = await detector.analyze_content('https://example.com')
            print(f"  ✅ Safe content analysis: Phishing score={safe_content.get('phishing_score', 0)}")
            
            return True
        
        # Run the async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(test_content())
        loop.close()
        
        return result
        
    except Exception as e:
        print(f"  ❌ Content analysis test failed: {e}")
        return False

def test_database_connection():
    """Test database connectivity"""
    print("\n🗄️  Testing Database Connection...")
    
    try:
        from backend.server import get_mysql_connection
        
        conn = get_mysql_connection()
        if conn and conn.is_connected():
            print("  ✅ Database connection successful")
            conn.close()
            return True
        else:
            print("  ❌ Database connection failed")
            return False
            
    except Exception as e:
        print(f"  ❌ Database test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Starting WebShield Backend Tests...")
    print("=" * 50)
    
    start_time = time.time()
    
    tests = [
        ("ML Models", test_ml_models),
        ("SSL Analysis", test_ssl_analysis),
        ("VirusTotal Integration", test_virustotal_integration),
        ("Threat Calculation", test_threat_calculation),
        ("URL Analysis", test_url_analysis),
        ("Content Analysis", test_content_analysis),
        ("Database Connection", test_database_connection),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"  ❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Backend is working correctly.")
    else:
        print("⚠️  Some tests failed. Please check the issues above.")
    
    elapsed_time = time.time() - start_time
    print(f"\n⏱️  Total test time: {elapsed_time:.2f} seconds")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

