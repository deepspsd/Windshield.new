// WebShield Extension Options Script
document.addEventListener('DOMContentLoaded', () => {
  // Initialize options page
  initializeOptions();
  setupEventListeners();
  loadStatistics();
});

// Initialize options page
function initializeOptions() {
  console.log('WebShield: Initializing options page...');
  
  // Load current settings
  loadSettings();
  
  // Check extension status
  checkExtensionStatus();
  
  // Update status indicator
  updateStatusIndicator();
}

// Load current settings from storage
function loadSettings() {
  chrome.storage.sync.get({
    // Extension settings
    extensionEnabled: true,
    
    // SSL settings
    ssl_check_enabled: true,
    ssl_block_invalid: true,
    ssl_strictness: 'moderate',
    
    // Threat detection settings
    threat_detection_enabled: true,
    auto_block_high_threat: false,
    show_detailed_alerts: true,
    

    
    // Advanced settings
    enable_caching: true,
    enable_analytics: false,
    enable_notifications: true
  }, (settings) => {
    console.log('WebShield: Loaded settings:', settings);
    
    // Update UI with current settings
    updateSettingsUI(settings);
  });
}

// Update settings UI with current values
function updateSettingsUI(settings) {
  // Extension settings
  const extensionEnabled = document.getElementById('extension-enabled');
  if (extensionEnabled) extensionEnabled.checked = settings.extensionEnabled;
  
  // SSL settings
  const sslCheckEnabled = document.getElementById('ssl-check-enabled');
  if (sslCheckEnabled) sslCheckEnabled.checked = settings.ssl_check_enabled;
  
  const sslBlockInvalid = document.getElementById('ssl-block-invalid');
  if (sslBlockInvalid) sslBlockInvalid.checked = settings.ssl_block_invalid;
  
  const sslStrictness = document.getElementById('ssl-strictness');
  if (sslStrictness) sslStrictness.value = settings.ssl_strictness;
  
  // Threat detection settings
  const threatDetectionEnabled = document.getElementById('threat-detection-enabled');
  if (threatDetectionEnabled) threatDetectionEnabled.checked = settings.threat_detection_enabled;
  
  const autoBlockHighThreat = document.getElementById('auto-block-high-threat');
  if (autoBlockHighThreat) autoBlockHighThreat.checked = settings.auto_block_high_threat;
  
  const showDetailedAlerts = document.getElementById('show-detailed-alerts');
  if (showDetailedAlerts) showDetailedAlerts.checked = settings.show_detailed_alerts;
  

  
  // Advanced settings
  const enableCaching = document.getElementById('enable-caching');
  if (enableCaching) enableCaching.checked = settings.enable_caching;
  
  const enableAnalytics = document.getElementById('enable-analytics');
  if (enableAnalytics) enableAnalytics.checked = settings.enable_analytics;
  
  const enableNotifications = document.getElementById('enable-notifications');
  if (enableNotifications) enableNotifications.checked = settings.enable_notifications;
}

// Setup event listeners
function setupEventListeners() {
  // Save settings button
  const saveSettingsBtn = document.getElementById('save-settings');
  if (saveSettingsBtn) {
    saveSettingsBtn.addEventListener('click', saveSettings);
  }
  
  // Reset settings button
  const resetSettingsBtn = document.getElementById('reset-settings');
  if (resetSettingsBtn) {
    resetSettingsBtn.addEventListener('click', resetSettings);
  }
  
  // Clear data button
  const clearDataBtn = document.getElementById('clear-data');
  if (clearDataBtn) {
    clearDataBtn.addEventListener('click', clearAllData);
  }
  
  // Extension toggle
  const extensionEnabled = document.getElementById('extension-enabled');
  if (extensionEnabled) {
    extensionEnabled.addEventListener('change', (e) => {
      chrome.storage.sync.set({ extensionEnabled: e.target.checked });
      showNotification(`Extension ${e.target.checked ? 'enabled' : 'disabled'}`, 'success');
    });
  }
  
  // SSL settings
  const sslCheckEnabled = document.getElementById('ssl-check-enabled');
  if (sslCheckEnabled) {
    sslCheckEnabled.addEventListener('change', (e) => {
      chrome.storage.sync.set({ ssl_check_enabled: e.target.checked });
      showNotification(`SSL checking ${e.target.checked ? 'enabled' : 'disabled'}`, 'info');
    });
  }
  
  const sslBlockInvalid = document.getElementById('ssl-block-invalid');
  if (sslBlockInvalid) {
    sslBlockInvalid.addEventListener('change', (e) => {
      chrome.storage.sync.set({ ssl_block_invalid: e.target.checked });
      showNotification(`Invalid SSL blocking ${e.target.checked ? 'enabled' : 'disabled'}`, 'info');
    });
  }
  
  const sslStrictness = document.getElementById('ssl-strictness');
  if (sslStrictness) {
    sslStrictness.addEventListener('change', (e) => {
      chrome.storage.sync.set({ ssl_strictness: e.target.value });
      showNotification(`SSL strictness set to ${e.target.value}`, 'info');
    });
  }
  
  // Threat detection settings
  const threatDetectionEnabled = document.getElementById('threat-detection-enabled');
  if (threatDetectionEnabled) {
    threatDetectionEnabled.addEventListener('change', (e) => {
      chrome.storage.sync.set({ threat_detection_enabled: e.target.checked });
      showNotification(`Threat detection ${e.target.checked ? 'enabled' : 'disabled'}`, 'info');
    });
  }
  
  const autoBlockHighThreat = document.getElementById('auto-block-high-threat');
  if (autoBlockHighThreat) {
    autoBlockHighThreat.addEventListener('change', (e) => {
      chrome.storage.sync.set({ auto_block_high_threat: e.target.checked });
      showNotification(`Auto-block high threats ${e.target.checked ? 'enabled' : 'disabled'}`, 'info');
    });
  }
  
  const showDetailedAlerts = document.getElementById('show-detailed-alerts');
  if (showDetailedAlerts) {
    showDetailedAlerts.addEventListener('change', (e) => {
      chrome.storage.sync.set({ show_detailed_alerts: e.target.checked });
      showNotification(`Detailed alerts ${e.target.checked ? 'enabled' : 'disabled'}`, 'info');
    });
  }
  

  
  // Advanced settings
  const enableCaching = document.getElementById('enable-caching');
  if (enableCaching) {
    enableCaching.addEventListener('change', (e) => {
      chrome.storage.sync.set({ enable_caching: e.target.checked });
      showNotification(`Caching ${e.target.checked ? 'enabled' : 'disabled'}`, 'info');
    });
  }
  
  const enableAnalytics = document.getElementById('enable-analytics');
  if (enableAnalytics) {
    enableAnalytics.addEventListener('change', (e) => {
      chrome.storage.sync.set({ enable_analytics: e.target.checked });
      showNotification(`Analytics ${e.target.checked ? 'enabled' : 'disabled'}`, 'info');
    });
  }
  
  const enableNotifications = document.getElementById('enable-notifications');
  if (enableNotifications) {
    enableNotifications.addEventListener('change', (e) => {
      chrome.storage.sync.set({ enable_notifications: e.target.checked });
      showNotification(`Notifications ${e.target.checked ? 'enabled' : 'disabled'}`, 'info');
    });
  }
}

// Save all settings
function saveSettings() {
  const settings = {
    extensionEnabled: document.getElementById('extension-enabled')?.checked ?? true,
    ssl_check_enabled: document.getElementById('ssl-check-enabled')?.checked ?? true,
    ssl_block_invalid: document.getElementById('ssl-block-invalid')?.checked ?? true,
    ssl_strictness: document.getElementById('ssl-strictness')?.value ?? 'moderate',
    threat_detection_enabled: document.getElementById('threat-detection-enabled')?.checked ?? true,
    auto_block_high_threat: document.getElementById('auto-block-high-threat')?.checked ?? false,
    show_detailed_alerts: document.getElementById('show-detailed-alerts')?.checked ?? true,

    enable_caching: document.getElementById('enable-caching')?.checked ?? true,
    enable_analytics: document.getElementById('enable-analytics')?.checked ?? false,
    enable_notifications: document.getElementById('enable-notifications')?.checked ?? true
  };
  
  chrome.storage.sync.set(settings, () => {
    if (chrome.runtime.lastError) {
      showNotification('Failed to save settings', 'error');
      console.error('WebShield: Settings save error:', chrome.runtime.lastError);
    } else {
      showNotification('Settings saved successfully', 'success');
      console.log('WebShield: Settings saved:', settings);
    }
  });
}

// Reset settings to default
function resetSettings() {
  if (confirm('Are you sure you want to reset all settings to default values?')) {
    const defaultSettings = {
      extensionEnabled: true,
      ssl_check_enabled: true,
      ssl_block_invalid: true,
      ssl_strictness: 'moderate',
      threat_detection_enabled: true,
      auto_block_high_threat: false,
      show_detailed_alerts: true,

      enable_caching: true,
      enable_analytics: false,
      enable_notifications: true
    };
    
    chrome.storage.sync.set(defaultSettings, () => {
      if (chrome.runtime.lastError) {
        showNotification('Failed to reset settings', 'error');
      } else {
        updateSettingsUI(defaultSettings);
        showNotification('Settings reset to default', 'success');
      }
    });
  }
}

// Clear all data
function clearAllData() {
  if (confirm('Are you sure you want to clear all extension data? This action cannot be undone.')) {
    chrome.storage.sync.clear(() => {
      chrome.storage.local.clear(() => {
        showNotification('All data cleared successfully', 'success');
        
        // Reset UI to defaults
        const defaultSettings = {
          extensionEnabled: true,
          ssl_check_enabled: true,
          ssl_block_invalid: true,
          ssl_strictness: 'moderate',
          threat_detection_enabled: true,
          auto_block_high_threat: false,
          show_detailed_alerts: true,

          enable_caching: true,
          enable_analytics: false,
          enable_notifications: true
        };
        
        updateSettingsUI(defaultSettings);
        
        // Clear statistics
        updateStatistics({ scans_today: 0, threats_blocked: 0, sites_checked: 0 });
      });
    });
  }
}

// Check extension status
function checkExtensionStatus() {
  chrome.runtime.sendMessage({ type: 'GET_EXTENSION_STATUS' }, (response) => {
    if (response) {
      console.log('WebShield: Extension status:', response);
      updateStatusIndicator(response.enabled ? 'online' : 'offline');
    } else {
      updateStatusIndicator('warning');
    }
  });
}

// Update status indicator
function updateStatusIndicator(status) {
  const indicator = document.getElementById('status-indicator');
  if (indicator) {
    indicator.className = `status-indicator status-${status}`;
  }
}

// Load statistics
function loadStatistics() {
  // Get statistics from storage
  chrome.storage.local.get({
    scans_today: 0,
    threats_blocked: 0,
    sites_checked: 0,
    last_reset_date: new Date().toDateString()
  }, (stats) => {
    // Check if we need to reset daily stats
    const today = new Date().toDateString();
    if (stats.last_reset_date !== today) {
      stats.scans_today = 0;
      stats.last_reset_date = today;
      chrome.storage.local.set(stats);
    }
    
    updateStatistics(stats);
  });
}

// Update statistics display
function updateStatistics(stats) {
  const scansToday = document.getElementById('scans-today');
  if (scansToday) scansToday.textContent = stats.scans_today || 0;
  
  const threatsBlocked = document.getElementById('threats-blocked');
  if (threatsBlocked) threatsBlocked.textContent = stats.threats_blocked || 0;
  
  const sitesChecked = document.getElementById('sites-checked');
  if (sitesChecked) sitesChecked.textContent = stats.sites_checked || 0;
}

// Show notification
function showNotification(message, type = 'info') {
  const notification = document.getElementById('notification');
  
  if (notification) {
    notification.textContent = message;
    notification.className = `notification notification-${type}`;
    notification.classList.add('show');
    
    // Auto-hide after 3 seconds
    setTimeout(() => {
      notification.classList.remove('show');
    }, 3000);
  }
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('WebShield Options: Received message:', message.type);
  
  switch (message.type) {
    case 'UPDATE_STATISTICS':
      updateStatistics(message.data);
      break;
      
    case 'SHOW_NOTIFICATION':
      showNotification(message.message, message.type);
      break;
  }
});

// Periodic status check
setInterval(() => {
  checkExtensionStatus();
}, 30000); // Check every 30 seconds

// Initialize on page load
console.log('WebShield: Options page initialized'); 
