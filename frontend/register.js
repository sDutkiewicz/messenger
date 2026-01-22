

// Display message in the UI
function showMessage(elementId, text, color) {
    const el = document.getElementById(elementId);
    if (el) {
        el.textContent = text;
        el.style.color = color;
    }
}

// Initialize registration form on page load
document.addEventListener('DOMContentLoaded', function() {
    attachRegisterFormHandler();
    attachVerify2faFormHandler();
    attachDownloadCodesHandler();
    attachContinueButtonHandler();
});

// REGISTRATION FORM

// Handle registration form submission
function attachRegisterFormHandler() {
    document.getElementById('registerForm').onsubmit = async function(e) {
        e.preventDefault();
        const form = e.target;
        const data = {
            username: sanitizeInput(form.username.value),
            email: sanitizeInput(form.email.value),
            password: form.password.value
        };
        
        const res = await fetch('/api/register', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        
        const body = await res.json();
        
        // Check for validation errors BEFORE showing 2FA
        if (!res.ok) {
            showMessage('registerMsg', body.error || 'Błąd rejestracji', 'red');
            return;  // ← STOP HERE if validation failed
        }
        
        // If we get here, validation passed - show 2FA
        showMessage('registerMsg', 'Rejestracja udana! Dokończ konfigurację 2FA.', 'green');
        displayTwoFASetup(body);
    };
}

// Display QR code and TOTP secret
function displayTwoFASetup(body) {
    if (body.provisioning_qr || body.provisioning_uri || body.totp_secret) {
        const twofa = document.getElementById('twofaSetup');
        const qr = document.getElementById('provisionQr');
        const secret = document.getElementById('totpSecret');
        
        // Set QR code from response
        if (body.provisioning_qr) {
            qr.src = body.provisioning_qr;
        } else if (body.provisioning_qr_path) {
            qr.src = body.provisioning_qr_path;
        } else if (body.provisioning_uri) {
            // Fallback: generate QR via Google Charts
            qr.src = 'https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=' + encodeURIComponent(body.provisioning_uri);
        }
        
        secret.textContent = body.totp_secret || '';
        twofa.style.display = 'block';
    } else {
        // No 2FA needed (shouldn't happen)
        localStorage.setItem('loggedIn', '1');
        setTimeout(() => { window.location.href = 'dashboard.html'; }, 500);
    }
}

// 2FA VERIFICATION

// Handle 2FA code verification
function attachVerify2faFormHandler() {
    document.getElementById('verify2faForm').onsubmit = async function(e) {
        e.preventDefault();
        const code = sanitizeInput(e.target.code.value.trim());
        
        const res = await fetch('/api/verify-2fa', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({code})
        });
        
        if (res.ok) {
            const data = await res.json();
            showMessage('twofaMsg', '2FA skonfigurowane!', 'green');
            displayRecoveryCodes(data);
        } else {
            const err = await res.json();
            showMessage('twofaMsg', err.error || 'Błąd weryfikacji 2FA', 'red');
        }
    };
}

// Display recovery codes after successful 2FA verification
function displayRecoveryCodes(data) {
    if (data.recovery_codes && data.recovery_codes.length > 0) {
        // Store codes in session for download
        sessionStorage.setItem('recovery_codes', JSON.stringify(data.recovery_codes));
        
        // Display list of codes
        const listEl = document.getElementById('recoveryCodesList');
        listEl.innerHTML = data.recovery_codes
            .map((code, i) => `<div>${i + 1}. ${code}</div>`)
            .join('');
        
        // Hide 2FA setup, show recovery codes
        document.getElementById('twofaSetup').style.display = 'none';
        document.getElementById('recoveryCodesSection').style.display = 'block';
    } else {
        // No recovery codes? Redirect to login
        setTimeout(() => { window.location.href = 'login.html'; }, 1000);
    }
}

// RECOVERY CODES DOWNLOAD

// Handling recovery codes download as TXT file
function attachDownloadCodesHandler() {
    document.getElementById('downloadRecoveryCodes').onclick = function() {
        const codes = JSON.parse(sessionStorage.getItem('recovery_codes') || '[]');
        
        if (!codes.length) {
            alert('Brak kodów do pobrania!');
            return;
        }
        
        // TXT file content
        const text = 'KODY ODZYSKIWANIA - MESSENGER\n' +
                    '============================\n' +
                    'Jeśli stracisz dostęp do aplikacji 2FA, użyj jednego z tych kodów.\n' +
                    'Każdy kod można użyć tylko raz.\n\n' +
                    codes.map((code, i) => `${i + 1}. ${code}`).join('\n') +
                    '\n\nData: ' + new Date().toLocaleString('pl-PL');
        
        // Download file
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `2fa-recovery-codes-${Date.now()}.txt`;
        a.click();
        URL.revokeObjectURL(url);
        
        // Unlock "Continue" button after download
        sessionStorage.setItem('codes_downloaded', 'true');
        document.getElementById('continueAfterRecovery').disabled = false;
        document.getElementById('continueAfterRecovery').style.opacity = '1';
        document.getElementById('continueAfterRecovery').style.cursor = 'pointer';
        document.getElementById('downloadHint').style.display = 'none';
    };
}

// NAVIGATION

// Handle continue to login button
function attachContinueButtonHandler() {
    document.getElementById('continueAfterRecovery').onclick = function() {
        if (!sessionStorage.getItem('codes_downloaded')) {
            alert('Najpierw pobierz kody odzyskiwania!');
            return;
        }
        localStorage.setItem('loggedIn', '1');
        window.location.href = 'login.html';
    };
}
