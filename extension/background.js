// WebShield Extension Background Script

// Dynamic API endpoint detection
function getAPIBaseURL() {
  // In extension context, we need to use a different approach
  // Try to detect the environment based on available endpoints
  
  // Check if we're in a tunneled environment by testing the known tunnel URL
  const tunnelEndpoint = "https://pggjs0c8-8000.inc1.devtunnels.ms/api";
  
  // For now, return the most likely endpoint based on common patterns
  // The actual endpoint will be determined by the testEndpoints function
  
  // Default to localhost for development
  return "http://localhost:8000";
}

// Fallback endpoints for testing
const FALLBACK_ENDPOINTS = [
  "http://localhost:8000",                      // Local development (primary)
  "http://127.0.0.1:8000",                     // Alternative local
  "https://pggjs0c8-8000.inc1.devtunnels.ms"  // Remote tunnel (fallback)
];

let currentAPIBase = null; // Will be set after testing endpoints
let endpointTestInterval = null; // For periodic endpoint testing
let rateLimitMap = new Map(); // Rate limiting for API calls
const RATE_LIMIT_WINDOW = 60000; // 1 minute window
const MAX_REQUESTS_PER_WINDOW = 10; // Max requests per window
let isOfflineMode = false; // Track if we're in offline mode

// Enhanced endpoint testing with retry logic
async function testEndpoints() {
  console.log('WebShield: Testing API endpoints...');
  
  // Try dynamic endpoint first
  const dynamicEndpoint = getAPIBaseURL();
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    
    const response = await fetch(`${dynamicEndpoint}/api/health`, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'WebShield-Extension/1.0'
      }
    });
    
    clearTimeout(timeoutId);
    
    if (response.ok) {
      const data = await response.json();
      if (data.status === 'healthy' || data.message) {
        currentAPIBase = dynamicEndpoint;
        isOfflineMode = false;
        console.log(`WebShield: Using dynamic API endpoint: ${dynamicEndpoint}`);
        
        // Store the detected API base URL in storage for popup access
        chrome.storage.sync.set({ 
          detectedApiBase: dynamicEndpoint,
          webAppBase: dynamicEndpoint.replace('/api', '')
        });
        
        // Start periodic endpoint testing
        startPeriodicEndpointTesting();
        
        return dynamicEndpoint;
      }
    }
  } catch (error) {
            console.log(`WebShield: Dynamic endpoint ${dynamicEndpoint} failed:`, error.message);
  }
  
  // Try fallback endpoints
  for (const endpoint of FALLBACK_ENDPOINTS) {
    try {
      // Use AbortController for timeout instead of fetch timeout option
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      
      const response = await fetch(`${endpoint}/api/health`, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'User-Agent': 'WebShield-Extension/1.0'
        }
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        if (data.status === 'healthy' || data.message) {
          currentAPIBase = endpoint;
          isOfflineMode = false;
          console.log(`WebShield: Using fallback API endpoint: ${endpoint}`);
          
          // Store the detected API base URL in storage for popup access
          chrome.storage.sync.set({ 
            detectedApiBase: endpoint,
            webAppBase: endpoint.replace('/api', '')
          });
          
          // Start periodic endpoint testing
          startPeriodicEndpointTesting();
          
          return endpoint;
        }
      }
    } catch (error) {
      console.log(`WebShield: Endpoint ${endpoint} failed:`, error.message);
    }
  }
  
  console.log('WebShield: No working API endpoints found, switching to offline mode');
  currentAPIBase = null;
  isOfflineMode = true;
  return null;
}

// Start periodic endpoint testing
function startPeriodicEndpointTesting() {
  if (endpointTestInterval) {
    clearInterval(endpointTestInterval);
  }
  
  endpointTestInterval = setInterval(async () => {
    if (currentAPIBase && !isOfflineMode) {
      try {
        const response = await fetch(`${currentAPIBase}/health`, {
          method: 'GET',
          signal: AbortSignal.timeout(5000)
        });
        
        if (!response.ok) {
          console.log('WebShield: Current endpoint failed, retesting all endpoints...');
          await testEndpoints();
        }
      } catch (error) {
        console.log('WebShield: Endpoint health check failed, retesting...');
        await testEndpoints();
      }
    }
  }, 30000); // Check every 30 seconds
}

// Rate limiting function
function isRateLimited(url) {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;
  
  if (!rateLimitMap.has(url)) {
    rateLimitMap.set(url, []);
  }
  
  const requests = rateLimitMap.get(url);
  
  // Remove old requests outside the window
  const validRequests = requests.filter(timestamp => timestamp > windowStart);
  rateLimitMap.set(url, validRequests);
  
  if (validRequests.length >= MAX_REQUESTS_PER_WINDOW) {
    return true;
  }
  
  // Add current request
  validRequests.push(now);
  return false;
}

// Enhanced error handling with retry logic
async function makeAPIRequest(endpoint, options, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
      
      const response = await fetch(endpoint, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'WebShield-Extension/1.0',
          ...options.headers
        }
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        return await response.json();
      } else {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
    } catch (error) {
      console.log(`WebShield: API request attempt ${attempt} failed:`, error.message);
      
      if (attempt === maxRetries) {
        throw error;
      }
      
      // Wait before retry with exponential backoff
      await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
    }
  }
}

// Offline SSL certificate validation
function validateSSLOffline(url) {
  try {
    const urlObj = new URL(url);
    const protocol = urlObj.protocol;
    
    if (protocol === 'https:') {
      return {
        valid: true,
        issuer: 'Browser Validated',
        expires: null,
        error: null,
        details: {
          protocol: 'HTTPS',
          domain: urlObj.hostname,
          offline_validation: true
        }
      };
    } else {
      return {
        valid: false,
        issuer: null,
        expires: null,
        error: 'Non-HTTPS connection',
        details: {
          protocol: 'HTTP',
          domain: urlObj.hostname,
          offline_validation: true
        }
      };
    }
  } catch (error) {
    return {
      valid: false,
      issuer: null,
      expires: null,
      error: 'Invalid URL format',
      details: {
        offline_validation: true,
        error: error.message
      }
    };
  }
}

// Offline threat detection
function detectThreatsOffline(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    
    // Basic offline threat detection patterns
    const suspiciousPatterns = [
      'phishing', 'malware', 'virus', 'scam', 'fake',
      'suspicious', 'dangerous', 'malicious', 'fraud'
    ];
    
    const suspiciousKeywords = [
      'login', 'signin', 'account', 'password', 'credit',
      'bank', 'paypal', 'amazon', 'ebay', 'facebook'
    ];
    
    let threatScore = 0;
    let detectedThreats = [];
    
    // Check for suspicious patterns in URL
    for (const pattern of suspiciousPatterns) {
      if (hostname.includes(pattern)) {
        threatScore += 3;
        detectedThreats.push(`Suspicious keyword: ${pattern}`);
      }
    }
    
    // Check for typosquatting (basic)
    const commonDomains = ['google', 'facebook', 'amazon', 'paypal', 'ebay'];
    for (const domain of commonDomains) {
      if (hostname.includes(domain) && hostname !== domain) {
        const distance = levenshteinDistance(hostname, domain);
        if (distance <= 2) {
          threatScore += 2;
          detectedThreats.push(`Possible typosquatting: ${domain}`);
        }
      }
    }
    
    // Determine threat level
    let threatLevel = 'low';
    if (threatScore >= 5) {
      threatLevel = 'high';
    } else if (threatScore >= 2) {
      threatLevel = 'medium';
    }
    
    return {
      results: {
        threat_level: threatLevel,
        is_malicious: threatLevel === 'high',
        malicious_count: threatScore,
        suspicious_count: detectedThreats.length,
        total_engines: 1,
        detection_details: {
          offline_detection: true,
          detected_threats: detectedThreats,
          threat_score: threatScore
        }
      }
    };
  } catch (error) {
    return {
      results: {
        threat_level: 'unknown',
        is_malicious: false,
        malicious_count: 0,
        suspicious_count: 0,
        total_engines: 1,
        detection_details: {
          offline_detection: true,
          error: error.message
        }
      }
    };
  }
}

// Levenshtein distance for typosquatting detection
function levenshteinDistance(s1, s2) {
  const matrix = [];
  
  for (let i = 0; i <= s2.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= s1.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= s2.length; i++) {
    for (let j = 1; j <= s1.length; j++) {
      if (s2.charAt(i - 1) === s1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  
  return matrix[s2.length][s1.length];
}

// Initialize endpoint testing
testEndpoints();

// Enhanced message listener with better error handling
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  console.log('WebShield: Received message:', msg.type);
  
  // Rate limiting check
  if (isRateLimited(msg.url || 'general')) {
    console.log('WebShield: Rate limited for URL:', msg.url);
    sendResponse({ error: 'Rate limited. Please try again later.' });
    return true;
  }
  
  switch (msg.type) {
    case 'CHECK_URL':
      checkUrl(msg.url, sendResponse);
      return true;
      
    case 'REPORT_URL':
      reportUrl(msg.url, msg.reason, sendResponse);
      return true;
      
    case 'GET_HISTORY':
      getHistory(sendResponse);
      return true;
      
    case 'SYNC_SETTINGS':
      syncSettings(msg.settings, sendResponse);
      return true;
      
    case 'THREAT_ALERT':
      showThreatNotification(msg.url, msg.level);
      return true;
    case 'SHOW_SYSTEM_NOTIFICATION':
      // Explicit request from other contexts to show a system notification
      if (msg.url && msg.level) {
        showThreatNotification(msg.url, msg.level);
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false, error: 'Missing url or level' });
      }
      return true;
      
    case 'GET_TAB_ID':
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        sendResponse(tabs[0]?.id);
      });
      return true;
      
    case 'CLOSE_TAB':
      if (msg.tabId) {
        chrome.tabs.remove(msg.tabId);
      }
      return true;
      
    case 'CHECK_SSL_CERTIFICATE':
      checkSSLCertificate(msg.url, sendResponse);
      return true;
      
    case 'GET_SSL_DETAILS':
      getSSLDetails(msg.url, sendResponse);
      return true;
      
    case 'SHOW_THREAT_ALERT':
      // Enhanced fallback threat alert with better logging
      console.log('WebShield: Fallback threat alert:', msg.url, msg.level);
      showEnhancedThreatAlert(msg.url, msg.level);
      return true;
      
    case 'UPDATE_ICON':
      updateExtensionIcon(msg.status);
      sendResponse({ success: true });
      return true;
      

      
    case 'GET_EXTENSION_STATUS':
      getExtensionStatus(sendResponse);
      return true;
      
    case 'CLEAR_CACHE':
      clearCache(sendResponse);
      return true;
      
    default:
      console.log('WebShield: Unknown message type:', msg.type);
      sendResponse({ error: 'Unknown message type' });
      return true;
  }
});

// Enhanced SSL certificate validation with offline fallback
async function checkSSLCertificate(url, cb) {
  try {
    // Validate URL format
    if (!url || !url.startsWith('http')) {
      cb({ error: 'Invalid URL format' });
      return;
    }

    if (!currentAPIBase || isOfflineMode) {
      console.log('WebShield: Using offline SSL validation');
      const offlineResult = validateSSLOffline(url);
      cb(offlineResult);
      return;
    }
    
    console.log('WebShield: Checking SSL certificate for:', url);
    
    // Use the main scan endpoint which includes SSL analysis
    const requestBody = {
      url: url,
      user_email: null
    };
    
    const data = await makeAPIRequest(
      `${currentAPIBase}/api/scan`,
      {
        method: 'POST',
        body: JSON.stringify(requestBody)
      }
    );
    
    // Handle immediate results
    if (data.results && data.results.detection_details?.ssl_analysis) {
      const sslAnalysis = data.results.detection_details.ssl_analysis;
      console.log('WebShield: SSL analysis completed');
      
      const result = {
        valid: sslAnalysis.valid || false,
        issuer: sslAnalysis.issuer || null,
        expires: sslAnalysis.expires || null,
        error: sslAnalysis.error || null,
        details: sslAnalysis,
        scan_id: data.scan_id
      };
      
      cb(result);
      return;
    }
    
    // Handle processing status
    if (data.status === 'processing' && data.scan_id) {
      console.log('WebShield: SSL scan processing, polling for results...');
      await pollSSLResults(data.scan_id, cb);
      return;
    }
    
    // Handle errors
    if (data.status === 'error') {
      console.error('WebShield: SSL scan failed:', data.error);
      cb({ error: data.error || 'SSL analysis failed' });
      return;
    }
    
    // Fallback to offline validation
    console.log('WebShield: Falling back to offline SSL validation');
    const offlineResult = validateSSLOffline(url);
    cb(offlineResult);
    
  } catch (e) {
    console.error('WebShield: SSL check error:', e);
    console.log('WebShield: Falling back to offline SSL validation');
    const offlineResult = validateSSLOffline(url);
    cb(offlineResult);
  }
}

// Polling function for SSL results
async function pollSSLResults(scanId, cb, attempt = 1) {
  const maxAttempts = 5;
  const baseDelay = 1000;
  
  try {
    console.log(`WebShield: SSL polling attempt ${attempt}/${maxAttempts}`);
    
    const resultData = await makeAPIRequest(
      `${currentAPIBase}/api/scan/${scanId}`,
      { method: 'GET' }
    );
    
    if (resultData.results && resultData.results.detection_details?.ssl_analysis) {
      const sslAnalysis = resultData.results.detection_details.ssl_analysis;
      console.log('WebShield: SSL analysis completed via polling');
      
      const result = {
        valid: sslAnalysis.valid || false,
        issuer: sslAnalysis.issuer || null,
        expires: sslAnalysis.expires || null,
        error: sslAnalysis.error || null,
        details: sslAnalysis,
        scan_id: scanId
      };
      
      cb(result);
      return;
    }
    
    if (resultData.status === 'error') {
      cb({ error: resultData.error || 'SSL analysis failed' });
      return;
    }
    
    // Continue polling if still processing
    if (resultData.status === 'processing' && attempt < maxAttempts) {
      const delay = baseDelay * Math.pow(1.5, attempt - 1);
      setTimeout(() => {
        pollSSLResults(scanId, cb, attempt + 1);
      }, delay);
      return;
    }
    
    // Max attempts reached or unexpected status
    cb({ error: 'SSL analysis timeout' });
    
  } catch (error) {
    console.error('WebShield: SSL polling error:', error);
    
    if (attempt < maxAttempts) {
      const delay = baseDelay * Math.pow(1.5, attempt - 1);
      setTimeout(() => {
        pollSSLResults(scanId, cb, attempt + 1);
      }, delay);
    } else {
      cb({ error: 'SSL analysis failed' });
    }
  }
}

// Get detailed SSL certificate information
async function getSSLDetails(url, cb) {
  if (!currentAPIBase || isOfflineMode) {
    console.log('WebShield: Using offline SSL details');
    const offlineResult = validateSSLOffline(url);
    cb({
      ssl_valid: offlineResult.valid,
      ssl_analysis: offlineResult.details,
      threat_level: 'unknown',
      malicious_count: 0,
      suspicious_count: 0,
      total_engines: 1
    });
    return;
  }
  
  try {
    // Fix the request format to match the API expectations
    const requestBody = {
      url: url,
      user_email: null  // Add this field as expected by the API
    };
    
    const data = await makeAPIRequest(
      `${currentAPIBase}/api/scan`,
      {
        method: 'POST',
        body: JSON.stringify(requestBody)
      }
    );
    
    if (data.results) {
      cb({
        ssl_valid: data.results.ssl_valid,
        ssl_analysis: data.results.detection_details?.ssl_analysis || {},
        threat_level: data.results.threat_level,
        malicious_count: data.results.malicious_count,
        suspicious_count: data.results.suspicious_count,
        total_engines: data.results.total_engines
      });
    } else {
      cb({ error: 'SSL details not available' });
    }
  } catch (e) {
    console.error('SSL details error:', e);
    console.log('WebShield: Falling back to offline SSL details');
    const offlineResult = validateSSLOffline(url);
    cb({
      ssl_valid: offlineResult.valid,
      ssl_analysis: offlineResult.details,
      threat_level: 'unknown',
      malicious_count: 0,
      suspicious_count: 0,
      total_engines: 1
    });
  }
}

// Enhanced real-time URL check with improved polling and error handling
async function checkUrl(url, cb) {
  try {
    // Validate URL format
    if (!url || !url.startsWith('http')) {
      cb({ error: 'Invalid URL format' });
      return;
    }

    if (!currentAPIBase || isOfflineMode) {
      console.log('WebShield: Using offline threat detection');
      const offlineResult = detectThreatsOffline(url);
      handleThreatDetection(offlineResult, url);
      cb(offlineResult);
      return;
    }
    
    // Prepare request body
    const requestBody = {
      url: url,
      user_email: null
    };
    
    console.log('WebShield: Starting scan for URL:', url);
    
    // Initial scan request
    const data = await makeAPIRequest(
      `${currentAPIBase}/api/scan`,
      {
        method: 'POST',
        body: JSON.stringify(requestBody)
      }
    );
    
    // Handle immediate results
    if (data.results) {
      console.log('WebShield: Scan completed immediately');
      handleThreatDetection(data, url);
      cb(data);
      return;
    }
    
    // Handle processing status with improved polling
    if (data.status === 'processing' && data.scan_id) {
      console.log('WebShield: Scan processing, polling for results...');
      await pollScanResults(data.scan_id, url, cb);
      return;
    }
    
    // Handle other statuses
    if (data.status === 'error') {
      console.error('WebShield: Scan failed:', data.error || 'Unknown error');
      cb({ error: data.error || 'Scan failed' });
      return;
    }
    
    // Fallback for unexpected responses
    cb(data);
    
  } catch (e) {
    console.error('WebShield: URL check error:', e);
    console.log('WebShield: Falling back to offline threat detection');
    const offlineResult = detectThreatsOffline(url);
    handleThreatDetection(offlineResult, url);
    cb(offlineResult);
  }
}

// Improved polling function with exponential backoff
async function pollScanResults(scanId, url, cb, attempt = 1) {
  const maxAttempts = 10;
  const baseDelay = 1000; // 1 second
  const maxDelay = 8000;  // 8 seconds
  
  try {
    console.log(`WebShield: Polling attempt ${attempt}/${maxAttempts} for scan ${scanId}`);
    
    const resultData = await makeAPIRequest(
      `${currentAPIBase}/api/scan/${scanId}`,
      { method: 'GET' }
    );
    
    if (resultData.results) {
      console.log('WebShield: Scan completed successfully');
      handleThreatDetection(resultData, url);
      cb(resultData);
      return;
    }
    
    if (resultData.status === 'error') {
      console.error('WebShield: Scan failed during polling:', resultData.error);
      cb({ error: resultData.error || 'Scan failed' });
      return;
    }
    
    // Continue polling if still processing
    if (resultData.status === 'processing' && attempt < maxAttempts) {
      const delay = Math.min(baseDelay * Math.pow(1.5, attempt - 1), maxDelay);
      console.log(`WebShield: Scan still processing, retrying in ${delay}ms`);
      
      setTimeout(() => {
        pollScanResults(scanId, url, cb, attempt + 1);
      }, delay);
      return;
    }
    
    // Max attempts reached
    if (attempt >= maxAttempts) {
      console.warn('WebShield: Max polling attempts reached');
      cb({ error: 'Scan timeout - please try again' });
      return;
    }
    
    // Unexpected status
    cb({ error: 'Unexpected scan status' });
    
  } catch (error) {
    console.error('WebShield: Polling error:', error);
    
    if (attempt < maxAttempts) {
      const delay = Math.min(baseDelay * Math.pow(1.5, attempt - 1), maxDelay);
      setTimeout(() => {
        pollScanResults(scanId, url, cb, attempt + 1);
      }, delay);
    } else {
      cb({ error: 'Failed to get scan results' });
    }
  }
}

// Centralized threat detection handling
function handleThreatDetection(result, url) {
  if (!result.results) return;
  
  const { is_malicious, threat_level } = result.results;
  
  // Store scan ID for View Details functionality
  if (result.scan_id) {
    chrome.storage.local.set({ 
      lastScanId: result.scan_id,
      lastScanUrl: url,
      lastScanTime: Date.now()
    });
    console.log('WebShield: Stored scan ID:', result.scan_id);
  }
  
  // Check if threat detected
  if (is_malicious || threat_level === 'high' || threat_level === 'medium') {
    const level = threat_level || 'medium';
    
    // Show system notification
    showThreatNotification(url, level);
    
    // Broadcast to extension UIs
    chrome.runtime.sendMessage({ 
      type: 'THREAT_ALERT', 
      url, 
      level,
      scanId: result.scan_id,
      details: result.results
    });
    
    // Update extension icon
    updateExtensionIcon(level === 'high' ? 'danger' : 'warning');
    
    console.log(`WebShield: Threat detected - Level: ${level}, URL: ${url}`);
  } else {
    // Update icon for safe sites
    updateExtensionIcon('safe');
  }
}

// Report suspicious URL with enhanced error handling
async function reportUrl(url, reason, cb) {
  if (!currentAPIBase || isOfflineMode) {
    console.log('WebShield: Offline mode - cannot report URL');
    cb({ error: 'Cannot report URL in offline mode' });
    return;
  }
  
  try {
    const data = await makeAPIRequest(
      `${currentAPIBase}/api/report_blacklist`,
      {
        method: 'POST',
        body: JSON.stringify({ url, reason })
      }
    );
    cb(data);
  } catch (e) {
    console.error('Report URL error:', e);
    cb({ error: 'Network error' });
  }
}

// Get scan history with enhanced error handling
async function getHistory(cb) {
  try {
    if (!currentAPIBase || isOfflineMode) {
      console.log('WebShield: Offline mode - no history available');
      cb([]);
      return;
    }
    
    const data = await makeAPIRequest(
      `${currentAPIBase}/api/history?limit=20`,
      { method: 'GET' }
    );
    cb(data);
  } catch (e) {
    console.error('Get history error:', e);
    cb([]);
  }
}

// Sync settings with enhanced error handling
function syncSettings(settings, cb) {
  chrome.storage.sync.set({ settings }, () => {
    if (chrome.runtime.lastError) {
      console.error('WebShield: Settings sync error:', chrome.runtime.lastError);
      cb({ error: 'Failed to sync settings' });
    } else {
      cb({ success: true });
    }
  });
}

// Enhanced threat notification with better error handling
function showThreatNotification(url, level) {
  console.log(`WebShield: Threat detected - Level: ${level}, URL: ${url}`);
  
  // Create notification with better error handling
  try {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'WebShield Threat Detected',
      message: `Detected ${level} risk site: ${new URL(url).hostname}`,
      priority: 2
    }, (notificationId) => {
      if (chrome.runtime.lastError) {
        console.error('WebShield: Notification error:', chrome.runtime.lastError);
        // Fallback: show alert in popup or use a different method
        chrome.runtime.sendMessage({ 
          type: 'SHOW_THREAT_ALERT', 
          url: url, 
          level: level 
        });
      } else {
        console.log('WebShield: Notification created successfully:', notificationId);
      }
    });
  } catch (error) {
    console.error('WebShield: Notification creation failed:', error);
    // Fallback: show alert in popup
    chrome.runtime.sendMessage({ 
      type: 'SHOW_THREAT_ALERT', 
      url: url, 
      level: level 
    });
  }
  
  // Also update the extension icon to show danger state
  updateExtensionIcon('danger');
}

// Enhanced threat alert with more detailed information
function showEnhancedThreatAlert(url, level) {
  const hostname = new URL(url).hostname;
  const alertMessage = `⚠️ WebShield Security Alert ⚠️\n\n` +
    `Site: ${hostname}\n` +
    `Threat Level: ${level.toUpperCase()}\n` +
    `Time: ${new Date().toLocaleString()}\n\n` +
    `This site has been flagged as potentially dangerous. Proceed with caution.`;
  
  // Try to show in popup first, then fallback to console
  try {
    chrome.runtime.sendMessage({ 
      type: 'SHOW_ALERT', 
      message: alertMessage,
      level: level
    });
  } catch (error) {
    console.warn('WebShield Enhanced Alert:', alertMessage);
  }
}

// Update extension icon based on status with enhanced error handling
function updateExtensionIcon(status) {
  const iconMap = {
    'safe': 'icons/icon48.png',
    'warning': 'icons/icon48.png', // You can create warning icon
    'danger': 'icons/icon48.png',   // You can create danger icon

  };
  
  const iconPath = iconMap[status] || 'icons/icon48.png';
  
  // Check if chrome.action is available
  if (typeof chrome !== 'undefined' && chrome.action) {
    try {
      chrome.action.setIcon({
        path: iconPath
      }, () => {
        if (chrome.runtime.lastError) {
          console.error('WebShield: Icon update error:', chrome.runtime.lastError.message);
        } else {
          console.log(`WebShield: Icon updated to ${status} state`);
        }
      });
    } catch (error) {
      console.error('WebShield: Icon update failed:', error.message);
    }
  } else {
    console.log('WebShield: Chrome action API not available for icon update');
  }
}

// Context menu for quick scan/report with enhanced functionality
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'scan-url',
    title: 'Scan this URL with WebShield',
    contexts: ['link']
  });
  chrome.contextMenus.create({
    id: 'report-url',
    title: 'Report this site as suspicious',
    contexts: ['link']
  });
  chrome.contextMenus.create({
    id: 'check-ssl',
    title: 'Check SSL Certificate',
    contexts: ['link']
  });
  
  // Initialize API endpoints on extension install
  testEndpoints().then(() => {
    console.log('WebShield: Extension installed, API endpoints tested');
  });
});

// Initialize API endpoints when extension starts
chrome.runtime.onStartup.addListener(() => {
  testEndpoints().then(() => {
    console.log('WebShield: Extension started, API endpoints tested');
  });
});

// Also test endpoints when the background script loads
testEndpoints().then(() => {
  console.log('WebShield: Background script loaded, API endpoints tested');
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'scan-url') {
    chrome.runtime.sendMessage({ type: 'CHECK_URL', url: info.linkUrl });
  }
  if (info.menuItemId === 'report-url') {
    chrome.runtime.sendMessage({ type: 'REPORT_URL', url: info.linkUrl, reason: 'User reported from extension' });
  }
  if (info.menuItemId === 'check-ssl') {
    chrome.runtime.sendMessage({ type: 'CHECK_SSL_CERTIFICATE', url: info.linkUrl });
  }
});



// Get extension status
function getExtensionStatus(cb) {
  chrome.storage.sync.get({ extensionEnabled: true }, (settings) => {
    cb({
      enabled: settings.extensionEnabled,
      apiBase: currentAPIBase,
      endpoints: FALLBACK_ENDPOINTS, // Use fallback endpoints for status
      offlineMode: isOfflineMode
    });
  });
}

// Clear cache and reset state
function clearCache(cb) {
  rateLimitMap.clear();
  currentAPIBase = null;
  isOfflineMode = false;
  if (endpointTestInterval) {
    clearInterval(endpointTestInterval);
    endpointTestInterval = null;
  }
  
  // Retest endpoints
  testEndpoints().then(() => {
    cb({ success: true, message: 'Cache cleared and endpoints retested' });
  });
}

// Cleanup on extension unload
chrome.runtime.onSuspend.addListener(() => {
  if (endpointTestInterval) {
    clearInterval(endpointTestInterval);
  }
  rateLimitMap.clear();
  console.log('WebShield: Extension suspended, cleaned up resources');
});
