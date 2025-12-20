// API base URL
const API_BASE = '/api';

// Health check
async function checkHealth() {
    try {
        const response = await fetch(`${API_BASE}/health`);
        const data = await response.json();
        console.log('API Health:', data);
    } catch (error) {
        console.error('Health check failed:', error);
    }
}

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    console.log('App loaded');
    checkHealth();
});
