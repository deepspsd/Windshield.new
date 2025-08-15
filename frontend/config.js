// WebShield Frontend Configuration
// This file automatically detects the correct IP address for API calls

function getAPIBaseURL() {
    // Get the current hostname and port
    const protocol = window.location.protocol;
    const hostname = window.location.hostname;
    const port = window.location.port || (protocol === 'https:' ? '443' : '80');
    
    console.log('🔍 API URL Detection:');
    console.log('  Protocol:', protocol);
    console.log('  Hostname:', hostname);
    console.log('  Port:', port);
    console.log('  Full URL:', window.location.href);
    
    // Check if we're in a tunneled environment (Dev Tunnels, ngrok, etc.)
    const isTunneled = hostname.includes('devtunnels.ms') || 
                       hostname.includes('ngrok.io') || 
                       hostname.includes('tunnel') ||
                       hostname.includes('inc1.devtunnels.ms');
    
    if (isTunneled) {
        console.log('🚇 Detected tunneled environment');
        // For tunneled environments, use the same hostname but with /api path
        const tunnelApiUrl = `${protocol}//${hostname}/api`;
        console.log('🔧 Tunnel API URL:', tunnelApiUrl);
        return tunnelApiUrl;
    }
    
    // For local development
    if (hostname === 'localhost' || hostname === '0.0.0.0' || hostname === '127.0.0.1') {
        const localApiUrl = `${protocol}//${hostname}:8000/api`;
        console.log('🔧 Local API URL:', localApiUrl);
        return localApiUrl;
    }
    
    // For network access (mobile), use the current hostname (which will be the network IP)
    const networkApiUrl = `${protocol}//${hostname}:8000/api`;
    console.log('🔧 Network API URL:', networkApiUrl);
    return networkApiUrl;
}

// Export the API base URL
const API_BASE_URL = getAPIBaseURL();

// Log the API URL for debugging
console.log('WebShield API Base URL:', API_BASE_URL);
console.log('Current hostname:', window.location.hostname);
console.log('Current protocol:', window.location.protocol);

// Add a function to get the scan ID from the URL
function getScanId() {
    const params = new URLSearchParams(window.location.search);
    return params.get('scan_id');
}

// Add a function to check API health
async function checkAPIHealth() {
    try {
        const response = await fetch(`${API_BASE_URL}/health`);
        if (response.ok) {
            const health = await response.json();
            console.log('🔧 API Health Check:', health);
            return health;
        } else {
            console.warn('⚠️ API Health Check failed:', response.status);
            return { status: 'unhealthy', error: `HTTP ${response.status}` };
        }
    } catch (error) {
        console.error('❌ API Health Check error:', error);
        return { status: 'unhealthy', error: error.message };
    }
}

// Add a function to test scan ID generation
async function testScanIdGeneration() {
    try {
        const response = await fetch(`${API_BASE_URL}/test-scan-id`);
        if (response.ok) {
            const data = await response.json();
            console.log('🧪 Scan ID Generation Test:', data);
            return data;
        } else {
            console.warn('⚠️ Scan ID Generation Test failed:', response.status);
            return { error: `HTTP ${response.status}` };
        }
    } catch (error) {
        console.error('❌ Scan ID Generation Test error:', error);
        return { error: error.message };
    }
}

// Make it available globally
window.API_BASE_URL = API_BASE_URL;
window.getScanId = getScanId;
window.checkAPIHealth = checkAPIHealth;
window.testScanIdGeneration = testScanIdGeneration;

// Test scan ID generation on load
if (typeof window !== 'undefined') {
    setTimeout(() => {
        testScanIdGeneration();
    }, 1000);
}
