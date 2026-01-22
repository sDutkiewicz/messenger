// recovery.js - Recovery mode security checks for 2FA

/**
 * Check if user is in recovery mode
 * If user used recovery code, they MUST complete 2FA setup before accessing dashboard
 */
async function checkRecoveryMode() {
    try {
        const res = await fetch('/api/me', { credentials: 'same-origin' });
        if (!res.ok) {
            window.location.href = 'login.html';
            return;
        }
        
        const data = await res.json();
        if (data.in_2fa_recovery_mode) {
            // Force redirect to 2FA setup
            window.location.href = '2fa-setup-required.html';
            return;
        }
    } catch (e) {
        console.error('Recovery mode check failed:', e);
    }
}

/**
 * Check for forced 2FA setup via URL parameter
 * Handles redirect after recovery code is accepted
 */
function checkForcedSetup() {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('setup_2fa') === '1') {
        // Redirect to forced 2FA setup page
        window.location.href = '2fa-setup-required.html';
    }
}

// Run checks on page load
checkForcedSetup();
checkRecoveryMode();
