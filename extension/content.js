// WebShield Content Script
const WEBSHIELD_WHITELIST = [
  "pggjs0c8-8000.inc1.devtunnels.ms",
  // Add any other trusted domains here
];

// Enhanced security configuration
const SECURITY_CONFIG = {
  sslCheckEnabled: true,
  sslBlockInvalid: true,
  sslStrictness: 'moderate',
  threatDetectionEnabled: true,

  autoBlockHighThreat: false,
  showDetailedAlerts: true
};

// Rate limiting for content script
let lastCheckTime = 0;
const MIN_CHECK_INTERVAL = 5000; // 5 seconds between checks

// Safe DOM manipulation function
function safeAppendChild(parent, child) {
  try {
    if (parent && child && parent.appendChild) {
      return parent.appendChild(child);
    }
    return false;
  } catch (error) {
    console.error('WebShield: DOM append error:', error.message);
    return false;
  }
}

// Safe document.body check
function getSafeBody() {
  try {
    return document.body || document.documentElement;
  } catch (error) {
    console.error('WebShield: Cannot access document body:', error.message);
    return null;
  }
}

(function() {
  try {
    // Check if extension is enabled before running any logic
    chrome.storage.sync.get({ extensionEnabled: true }, (settings) => {
      if (!settings.extensionEnabled) {
        // Extension is disabled: update icon and do nothing else
        updateSafeBrowsingIcon('disabled');
        return;
      }
      const url = window.location.href;
      const hostname = new URL(url).hostname;
      // Skip processing for trusted domains
      if (WEBSHIELD_WHITELIST.includes(hostname)) {
        console.log('WebShield: Skipping trusted domain:', hostname);
        return;
      }
      // Initialize security analysis
      initializeSecurityAnalysis();
    });
  } catch (error) {
    console.error('WebShield: Content script initialization failed:', error.message);
  }
})();

// Enhanced initialization function
function initializeSecurityAnalysis() {
  try {
    const url = window.location.href;
    
    // Check if we should rate limit this check
    const now = Date.now();
    if (now - lastCheckTime < MIN_CHECK_INTERVAL) {
      console.log('WebShield: Rate limiting content check');
      return;
    }
    lastCheckTime = now;
    
    // Load settings and perform security analysis
    chrome.storage.sync.get(['ssl_check_enabled', 'ssl_block_invalid', 'ssl_strictness', 'threat_detection_enabled'], (settings) => {
      try {
        const config = {
          sslCheckEnabled: settings.ssl_check_enabled !== false,
          sslBlockInvalid: settings.ssl_block_invalid !== false,
          sslStrictness: settings.ssl_strictness || 'moderate',
          threatDetectionEnabled: settings.threat_detection_enabled !== false
        };
        
        if (!config.sslCheckEnabled && !config.threatDetectionEnabled) {
          console.log('WebShield: All security checks disabled');
          updateSafeBrowsingIcon('safe');
          return;
        }
        
        // Perform comprehensive security analysis
        performSecurityAnalysis(url, config);
      } catch (error) {
        console.error('WebShield: Settings processing failed:', error.message);
      }
    });
  } catch (error) {
    console.error('WebShield: Security analysis initialization failed:', error.message);
  }
}

// Enhanced security analysis function
async function performSecurityAnalysis(url, config) {
  try {
    console.log('WebShield: Starting security analysis for:', url);
    
    // Check for HTTPS first
    if (!url.startsWith('https://')) {
      handleNonHTTPS(url);
      return;
    }
    
    // Perform parallel security checks
    const checks = [];
    
    if (config.sslCheckEnabled) {
      checks.push(checkSSLSecurity(url));
    }
    
    if (config.threatDetectionEnabled) {
      checks.push(checkThreatLevel(url));
    }
    

    
    try {
      const results = await Promise.allSettled(checks);
      processSecurityResults(results, url);
    } catch (error) {
      console.error('WebShield: Security analysis failed:', error);
      updateSafeBrowsingIcon('warning');
    }
  } catch (error) {
    console.error('WebShield: Security analysis failed:', error);
    updateSafeBrowsingIcon('warning');
  }
}

// Enhanced SSL security check
async function checkSSLSecurity(url) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'CHECK_SSL_CERTIFICATE', url }, (sslResult) => {
      console.log('WebShield: SSL check result:', sslResult);
      resolve({ type: 'ssl', result: sslResult });
    });
  });
}

// Enhanced threat level check
async function checkThreatLevel(url) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'CHECK_URL', url }, (threatResult) => {
      console.log('WebShield: Threat check result:', threatResult);
      resolve({ type: 'threat', result: threatResult });
    });
  });
}



// Process all security results
function processSecurityResults(results, url) {
  let hasHighThreat = false;
  let hasMediumThreat = false;

  let sslValid = true;
  
  results.forEach((result) => {
    if (result.status === 'fulfilled') {
      const { type, result: data } = result.value;
      
      switch (type) {
        case 'ssl':
          if (data?.valid === false) {
            sslValid = false;
            showWarningOverlay('invalid-ssl', data);
            // Removed duplicate threat alert - handled by background.js
          } else if (data?.valid) {
            showSSLInfo(data);
          }
          break;
          
        case 'threat':
          if (data?.results) {
            const threatLevel = data.results.threat_level;
            const isMalicious = data.results.is_malicious;
            
            if (isMalicious || threatLevel === 'high') {
              hasHighThreat = true;
              // Removed duplicate threat alert - handled by background.js
            } else if (threatLevel === 'medium') {
              hasMediumThreat = true;
              // Removed duplicate threat alert - handled by background.js
            }
          }
          break;
          

      }
    }
  });
  
  // Update icon based on overall security status
 if (hasHighThreat || !sslValid) {
    updateSafeBrowsingIcon('danger');
  } else if (hasMediumThreat) {
    updateSafeBrowsingIcon('warning');
  } else {
    updateSafeBrowsingIcon('safe');
  }
}

// Enhanced non-HTTPS handling
function handleNonHTTPS(url) {
  console.log('WebShield: Non-HTTPS site detected:', url);
  
      if (document.body) {
        showWarningOverlay('no-https');
        // Removed duplicate threat alert - handled by background.js
      } else {
        window.addEventListener('DOMContentLoaded', () => {
          showWarningOverlay('no-https');
          // Removed duplicate threat alert - handled by background.js
        });
      }
  
          updateSafeBrowsingIcon('danger');
}

// Enhanced warning overlay with better styling
function showWarningOverlay(type, sslDetails = null) {
  // Remove existing overlay
  const existingOverlay = document.getElementById('webshield-overlay');
  if (existingOverlay) {
    existingOverlay.remove();
  }
  
  const overlay = document.createElement('div');
  overlay.id = 'webshield-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(220, 53, 69, 0.95);
    z-index: 999999;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: white;
    text-align: center;
    padding: 20px;
  `;
  
  let title, message, details;
  
  switch (type) {
    case 'no-https':
      title = '⚠️ SECURITY WARNING ⚠️';
      message = 'This site is not using HTTPS encryption. Your data may be vulnerable to interception.';
      details = 'Proceed with extreme caution or consider using a different site.';
      break;
      
    case 'invalid-ssl':
      title = '🔒 SSL CERTIFICATE ISSUE';
      message = 'This site has an invalid or expired SSL certificate.';
      details = sslDetails?.error || 'Certificate validation failed.';
      break;
    case 'block-site':
      title = '🚨 BLOCKED BY WEBSHIELD';
      message = 'This site has been blocked due to a high security risk!';
      details = 'Access to this site is restricted for your safety.';
      break;
    default:
      title = '⚠️ SECURITY ALERT';
      message = 'This site has been flagged as potentially dangerous.';
      details = 'Proceed with caution.';
  }
  
  overlay.innerHTML = `
    <div style="max-width: 600px; background: rgba(0,0,0,0.8); padding: 30px; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
      <h1 style="margin: 0 0 20px 0; font-size: 24px; color: #ff6b6b;">${title}</h1>
      <p style="margin: 0 0 15px 0; font-size: 16px; line-height: 1.5;">${message}</p>
      <p style="margin: 0 0 25px 0; font-size: 14px; color: #ffd93d;">${details}</p>
      <div style="display: flex; gap: 15px; justify-content: center;">
        <button id="webshield-proceed" style="
          background: #dc3545;
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 5px;
          cursor: pointer;
          font-size: 14px;
          font-weight: bold;
        ">Proceed Anyway</button>
        <button id="webshield-go-back" style="
          background: #28a745;
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 5px;
          cursor: pointer;
          font-size: 14px;
          font-weight: bold;
        ">Go Back</button>
      </div>
      <p style="margin: 20px 0 0 0; font-size: 12px; color: #adb5bd;">
        Powered by WebShield Security Extension
      </p>
    </div>
  `;
  
  document.body.appendChild(overlay);

  // Add event listeners
  document.getElementById('webshield-proceed').addEventListener('click', () => {
    overlay.remove();
  });
  
  document.getElementById('webshield-go-back').addEventListener('click', () => {
    window.history.back();
  });
}

// Enhanced SSL info display
function showSSLInfo(sslResult) {
  if (!SECURITY_CONFIG.showDetailedAlerts) return;
  
  const sslIndicator = document.createElement('div');
  sslIndicator.id = 'webshield-ssl-indicator';
  sslIndicator.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: #28a745;
    color: white;
    padding: 10px 15px;
    border-radius: 5px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 12px;
    z-index: 999998;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    cursor: pointer;
  `;
  
  sslIndicator.innerHTML = `
    <div style="display: flex; align-items: center; gap: 8px;">
      <span>��</span>
      <span>SSL Valid</span>
      <span style="font-size: 10px;">✓</span>
    </div>
  `;
  
  sslIndicator.addEventListener('click', () => {
    showSSLDetails(sslResult, false);
  });
  
  document.body.appendChild(sslIndicator);
  
  // Auto-remove after 5 seconds
  setTimeout(() => {
    if (sslIndicator.parentNode) {
      sslIndicator.remove();
    }
  }, 5000);
}

// Enhanced SSL details display
function showSSLDetails(sslResult, isWarning = false) {
  const detailsOverlay = document.createElement('div');
  detailsOverlay.id = 'webshield-ssl-details';
  detailsOverlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.8);
    z-index: 999999;
    display: flex;
    justify-content: center;
    align-items: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  `;
  
  const bgColor = isWarning ? '#ffc107' : '#28a745';
  const icon = isWarning ? '⚠️' : '🔒';
  
  detailsOverlay.innerHTML = `
    <div style="
      max-width: 500px;
      background: white;
      padding: 30px;
      border-radius: 10px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.3);
    ">
      <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px;">
        <span style="font-size: 24px;">${icon}</span>
        <h2 style="margin: 0; color: ${bgColor};">SSL Certificate Details</h2>
      </div>
      
      <div style="margin-bottom: 20px;">
        <p><strong>Status:</strong> <span style="color: ${isWarning ? '#ffc107' : '#28a745'};">${sslResult.valid ? 'Valid' : 'Invalid'}</span></p>
        ${sslResult.issuer ? `<p><strong>Issuer:</strong> ${sslResult.issuer}</p>` : ''}
        ${sslResult.expires ? `<p><strong>Expires:</strong> ${new Date(sslResult.expires).toLocaleDateString()}</p>` : ''}
        ${sslResult.error ? `<p><strong>Error:</strong> <span style="color: #dc3545;">${sslResult.error}</span></p>` : ''}
      </div>
      
      <button id="webshield-close-details" style="
        background: ${bgColor};
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 5px;
        cursor: pointer;
        font-size: 14px;
      ">Close</button>
    </div>
  `;
  
  document.body.appendChild(detailsOverlay);

  document.getElementById('webshield-close-details').addEventListener('click', () => {
    detailsOverlay.remove();
  });
}



// Enhanced icon update function
function updateSafeBrowsingIcon(status) {
  try {
    chrome.runtime.sendMessage({ type: 'UPDATE_ICON', status }, (response) => {
      if (chrome.runtime.lastError) {
        console.error('WebShield: Icon update failed:', chrome.runtime.lastError.message);
      } else {
        console.log('WebShield: Icon updated to:', status);
      }
    });
  } catch (error) {
    console.error('WebShield: Icon update error:', error.message);
  }
}

// Enhanced error handling for API calls
function handleAPIError(error, context) {
  console.error(`WebShield: ${context} error:`, error);
  
  // Show user-friendly error message
  const errorMessage = document.createElement('div');
  errorMessage.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: #dc3545;
    color: white;
    padding: 10px 15px;
    border-radius: 5px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 12px;
    z-index: 999998;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
  `;
  
  errorMessage.textContent = `WebShield: ${context} failed. Please try again.`;
  const body = getSafeBody();
  if (body) {
    safeAppendChild(body, errorMessage);
  }
  
  setTimeout(() => {
    if (errorMessage.parentNode) {
      errorMessage.remove();
    }
  }, 5000);
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('WebShield Content: Received message:', message.type);
  
  switch (message.type) {
    case 'SHOW_ALERT':
      showAlert(message.message, message.level);
      break;
      
    case 'UPDATE_SECURITY_STATUS':
      updateSecurityStatus(message.status);
      break;
      
    case 'CLEAR_OVERLAYS':
      clearAllOverlays();
      break;
    case 'BLOCK_SITE':
      showWarningOverlay('block-site');
      break;
  }
});

// Show alert message
function showAlert(message, level = 'info') {
  const alertDiv = document.createElement('div');
  alertDiv.style.cssText = `
    position: fixed;
    top: 20px;
    left: 50%;
    transform: translateX(-50%);
    background: ${level === 'danger' ? '#dc3545' : level === 'warning' ? '#ffc107' : '#28a745'};
    color: white;
    padding: 15px 20px;
    border-radius: 5px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    z-index: 999999;
    box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    max-width: 400px;
    text-align: center;
  `;
  
  alertDiv.textContent = message;
  const body = getSafeBody();
  if (body) {
    safeAppendChild(body, alertDiv);
  }
  
  setTimeout(() => {
    if (alertDiv.parentNode) {
      alertDiv.remove();
    }
  }, 5000);
}

// Update security status
function updateSecurityStatus(status) {
  try {
    updateSafeBrowsingIcon(status);
  } catch (error) {
    console.error('WebShield: Security status update failed:', error.message);
  }
}

// Clear all overlays
function clearAllOverlays() {
  const overlays = document.querySelectorAll('[id^="webshield-"]');
  overlays.forEach(overlay => overlay.remove());
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  clearAllOverlays();
}); 
