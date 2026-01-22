// dashboard.js - Messenger Application (Dashboard)

// === IMPORTS ===
// crypto.js provides all cryptographic operations

// === FORCED 2FA SETUP CHECK ===
const urlParams = new URLSearchParams(window.location.search);
if (urlParams.get('setup_2fa') === '1') {
    // Redirect to forced 2FA setup page
    window.location.href = '2fa-setup-required.html';
}

// === CHECK IF IN RECOVERY MODE ===
// If user used recovery code, they MUST complete 2FA setup before accessing dashboard
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

checkRecoveryMode();

// === INITIALIZATION ===
if (!localStorage.getItem('loggedIn')) {
    window.location.href = 'login.html';
}

// === GLOBAL VARIABLES ===
let selectedUser = null;
let myId = null;
let privateKeyDecrypted = null;  // Decrypted private key cached in memory

// === USER INITIALIZATION ===

async function fetchMyId() {
    const res = await fetch('/api/me', { credentials: 'same-origin' });
    const data = await res.json();
    myId = data.id;
    const nameEl = document.getElementById('meName');
    if (data && data.username) nameEl.textContent = data.username; else nameEl.textContent = '—';
    
    // Load private key from sessionStorage (fetched during login)
    privateKeyDecrypted = sessionStorage.getItem('privateKeyDecrypted');
    if (!privateKeyDecrypted) {
        alert('Klucz prywatny nie jest dostępny. Proszę zalogować się ponownie.');
        window.location.href = 'login.html';
    }
}

// === UI HANDLING ===

document.getElementById('logoutBtn').onclick = async function() {
    await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
    localStorage.removeItem('loggedIn');
    window.location.href = 'login.html';
};

async function fetchUsers() {
    const res = await fetch('/api/users');
    const users = await res.json();
    const ul = document.getElementById('users');
    ul.innerHTML = '';
    users.forEach(u => {
        const li = document.createElement('li');
        li.textContent = u.username;
        li.dataset.id = u.id;
        li.onclick = () => selectUser(u);
        if (selectedUser && selectedUser.id === u.id) li.classList.add('selected');
        ul.appendChild(li);
    });
}

async function fetchMessages(userId) {
    const res = await fetch(`/api/messages/conversation/${userId}`);
    if (!res.ok) return;
    const data = await res.json();
    const messagesDiv = document.getElementById('messages');
    
    // Compare message count - if unchanged, skip re-render
    const currentCount = messagesDiv.querySelectorAll('.message-item').length;
    if (currentCount === data.messages.length && currentCount > 0) {
        // Check last message
        const lastItemText = messagesDiv.querySelector('.message-item:last-child span')?.textContent || '';
        const lastMessageInData = data.messages[data.messages.length - 1];
        // If last message hasn't changed, skip re-render
        if (lastItemText.includes(lastMessageInData.sender)) {
            return;
        }
    }
    
    // Smooth transition - fade out, clear, fade in
    messagesDiv.style.opacity = '0.5';
    messagesDiv.style.transition = 'opacity 0.1s ease-in-out';
    
    messagesDiv.innerHTML = '';
    
    for (const m of data.messages) {
        const wrapper = document.createElement('div');
        wrapper.className = 'message-item';
        const who = (m.sender_id === myId) ? 'You' : m.sender;
        
        let text = '';
        let isEncrypted = m.encrypted_content && m.session_key_encrypted;
        
        // If this is a message I sent - I can decrypt it now (I have the key)
        if (m.sender_id === myId) {
            if (isEncrypted) {
                const aesKeyB64 = await decryptAESKey(m.session_key_encrypted, privateKeyDecrypted);
                if (!aesKeyB64) {
                    text = `${who}: [Error decrypting sent message key]`;
                } else {
                    const plaintext = decryptAES(m.encrypted_content, aesKeyB64);
                    if (!plaintext) {
                        text = `${who}: [Error decrypting sent message]`;
                    } else {
                        text = `${who}: ${plaintext}`;
                    }
                }
            } else {
                text = `${who}: [Unencrypted message]`;
            }
            text += m.is_read ? ' [Read]' : ' [Sent]';
        } else {
            // If this is a received message - decrypt it
            if (isEncrypted) {
                const aesKeyB64 = await decryptAESKey(m.session_key_encrypted, privateKeyDecrypted);
                if (!aesKeyB64) {
                    text = `${who}: [Error decrypting key]`;
                } else {
                    const plaintext = decryptAES(m.encrypted_content, aesKeyB64);
                    if (!plaintext) {
                        text = `${who}: [Error decrypting message]`;
                    } else {
                        // Verify signature if available
                        let signatureValid = false;
                        if (m.signature) {
                            const senderPublicKey = await getSenderPublicKey(m.sender_id);
                            if (senderPublicKey) {
                                signatureValid = await verifySignature(plaintext, m.signature, senderPublicKey);
                            }
                        }
                        text = `${who}: ${plaintext}`;
                        if (signatureValid) {
                            text += ' [Verified]';
                        }
                        // Store data for verification in wrapper
                        wrapper.dataset.plaintext = plaintext;
                        wrapper.dataset.signature = m.signature || '';
                        wrapper.dataset.senderId = m.sender_id;
                    }
                }
            } else {
                text = `${who}: [Unencrypted message]`;
            }
        }
        
        const textNode = document.createElement('span');
        textNode.textContent = text;
        wrapper.appendChild(textNode);

        // Store AES key in wrapper dataset for attachment decryption
        // Get AES key if message is encrypted (attachments are encrypted with same key)
        if (isEncrypted) {
            const aesKeyB64 = await decryptAESKey(m.session_key_encrypted, privateKeyDecrypted);
            if (aesKeyB64) {
                wrapper.dataset.aesKey = aesKeyB64;
            }
        }

        if (m.attachments && m.attachments.length) {
            const attList = document.createElement('div');
            attList.style.marginTop = '6px';
            m.attachments.forEach(a => {
                const aBtn = document.createElement('button');
                aBtn.textContent = a.filename;
                aBtn.type = 'button';
                aBtn.style.display = 'inline-block';
                aBtn.style.marginRight = '8px';
                aBtn.style.padding = '4px 8px';
                aBtn.style.backgroundColor = '#007bff';
                aBtn.style.color = 'white';
                aBtn.style.border = 'none';
                aBtn.style.borderRadius = '3px';
                aBtn.style.cursor = 'pointer';
                aBtn.onclick = async (e) => {
                    e.preventDefault();
                    try {
                        const aesKey = wrapper.dataset.aesKey;
                        if (!aesKey) {
                            alert('Brak klucza deszyfrowania dla pliku');
                            return;
                        }
                        
                        // Fetch encrypted attachment data
                        const attRes = await fetch(`/api/attachments/${a.id}`);
                        if (!attRes.ok) {
                            alert('Błąd pobierania pliku');
                            return;
                        }
                        const attData = await attRes.json();
                        
                        // Decrypt file binary
                        const fileBuffer = decryptFileBinary(attData.encrypted_data, aesKey);
                        if (!fileBuffer) {
                            alert('Błąd deszyfrowania pliku');
                            return;
                        }
                        
                        // Create blob and download
                        const blob = new Blob([fileBuffer], { type: 'application/octet-stream' });
                        const url = URL.createObjectURL(blob);
                        const link = document.createElement('a');
                        link.href = url;
                        link.download = attData.filename;
                        document.body.appendChild(link);
                        link.click();
                        document.body.removeChild(link);
                        URL.revokeObjectURL(url);
                    } catch (error) {
                        alert('Błąd: ' + error.message);
                    }
                };
                attList.appendChild(aBtn);
            });
            wrapper.appendChild(attList);
        }

        if (m.sender_id === myId) {
            const delBtn = document.createElement('button');
            delBtn.textContent = 'Delete';
            delBtn.className = 'delete-btn';
            delBtn.onclick = async (e) => {
                e.stopPropagation();
                if (!confirm('Na pewno usunąć wiadomość?')) return;
                const res = await fetch(`/api/messages/${m.id}`, { method: 'DELETE' });
                if (res.status === 204) {
                    fetchMessages(selectedUser.id);
                } else {
                    const err = await res.json();
                    alert(err.error || 'Błąd usuwania wiadomości');
                }
            };
            wrapper.appendChild(delBtn);
        } else {
            // Verify button for received messages - next to text
            if (wrapper.dataset.plaintext && wrapper.dataset.signature) {
                const verifyBtn = document.createElement('button');
                verifyBtn.textContent = 'Verify';
                verifyBtn.style.display = 'inline-block';
                verifyBtn.style.padding = '2px 6px';
                verifyBtn.style.fontSize = '11px';
                verifyBtn.style.backgroundColor = '#007bff';
                verifyBtn.style.color = 'white';
                verifyBtn.style.border = 'none';
                verifyBtn.style.borderRadius = '3px';
                verifyBtn.style.cursor = 'pointer';
                verifyBtn.style.marginLeft = '4px';
                verifyBtn.style.verticalAlign = 'middle';
                
                verifyBtn.onclick = async (e) => {
                    e.stopPropagation();
                    const plaintext = wrapper.dataset.plaintext;
                    const signature = wrapper.dataset.signature;
                    const senderId = wrapper.dataset.senderId;
                    
                    if (!signature) {
                        alert('Wiadomość nie ma podpisu - nie można weryfikować autentyczności');
                        return;
                    }
                    
                    try {
                        const senderPublicKey = await getSenderPublicKey(parseInt(senderId));
                        if (!senderPublicKey) {
                            alert('Nie można pobrać klucza publicznego nadawcy');
                            return;
                        }
                        
                        const isValid = await verifySignature(plaintext, signature, senderPublicKey);
                        if (isValid) {
                            alert('Wiadomość jest autentyczna!\n\nPodpis zweryfikowany poprawnie. Wiadomość pochodzi od ' + m.sender);
                        } else {
                            alert('Wiadomość NIE jest autentyczna!\n\nPodpis jest nieprawidłowy. Wiadomość mogła zostać zmieniona!');
                        }
                    } catch (error) {
                        alert('Błąd weryfikacji: ' + error.message);
                    }
                };
                
                textNode.appendChild(verifyBtn);
            }
        }

        messagesDiv.appendChild(wrapper);
    }
    
    // Fade in after loading
    messagesDiv.style.opacity = '1';
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// === POLLING AND EVENTS ===

let pollIntervalId = null;
let usersIntervalId = null;

function startUsersPolling(){
    if (usersIntervalId) return;
    usersIntervalId = setInterval(fetchUsers, 10000);
}

function stopUsersPolling(){
    if (!usersIntervalId) return;
    clearInterval(usersIntervalId);
    usersIntervalId = null;
}

function startConversationPolling(userId){
    if (pollIntervalId) clearInterval(pollIntervalId);
    pollIntervalId = setInterval(()=>{
        if (selectedUser) fetchMessages(selectedUser.id);
    }, 2000);
}

function stopConversationPolling(){
    if (pollIntervalId) clearInterval(pollIntervalId);
    pollIntervalId = null;
}

function selectUser(user) {
    selectedUser = user;
    document.getElementById('convTitle').textContent = 'Conversation with: ' + user.username;
    document.getElementById('sendForm').style.display = 'flex';
    document.querySelectorAll('#users li').forEach(li => li.classList.remove('selected'));
    const node = Array.from(document.querySelectorAll('#users li')).find(n => n.dataset.id == user.id);
    if (node) node.classList.add('selected');
    fetchMessages(user.id);
    startConversationPolling(user.id);
}

function updateAttachmentsList() {
    const fileInput = document.getElementById('fileInput');
    const attachmentsList = document.getElementById('attachmentsList');
    attachmentsList.innerHTML = '';
    if (!fileInput.files.length) return;
    const listDiv = document.createElement('div');
    listDiv.style.marginTop = '8px';
    listDiv.style.padding = '8px';
    listDiv.style.backgroundColor = '#f0f0f0';
    listDiv.style.borderRadius = '4px';
    const title = document.createElement('strong');
    title.textContent = 'Attachments (' + fileInput.files.length + '):';
    listDiv.appendChild(title);
    const fileList = document.createElement('div');
    fileList.style.marginTop = '6px';
    Array.from(fileInput.files).forEach((file, index) => {
        const fileItemDiv = document.createElement('div');
        fileItemDiv.style.display = 'flex';
        fileItemDiv.style.justifyContent = 'space-between';
        fileItemDiv.style.alignItems = 'center';
        fileItemDiv.style.padding = '4px';
        fileItemDiv.style.borderBottom = '1px solid #ddd';
        const nameSpan = document.createElement('span');
        nameSpan.textContent = file.name + ' (' + (file.size / 1024).toFixed(1) + ' KB)';
        fileItemDiv.appendChild(nameSpan);
        const removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.textContent = '✕';
        removeBtn.style.padding = '2px 8px';
        removeBtn.style.backgroundColor = '#ff6b6b';
        removeBtn.style.color = 'white';
        removeBtn.style.border = 'none';
        removeBtn.style.borderRadius = '3px';
        removeBtn.style.cursor = 'pointer';
        removeBtn.onclick = (e) => {
            e.preventDefault();
            const dt = new DataTransfer();
            Array.from(fileInput.files).forEach((f, i) => {
                if (i !== index) dt.items.add(f);
            });
            fileInput.files = dt.files;
            updateAttachmentsList();
        };
        fileItemDiv.appendChild(removeBtn);
        fileList.appendChild(fileItemDiv);
    });
    listDiv.appendChild(fileList);
    attachmentsList.appendChild(listDiv);
}

document.getElementById('fileInput').onchange = updateAttachmentsList;

document.getElementById('sendForm').onsubmit = async function(e) {
    e.preventDefault();
    if (!selectedUser) return;
    if (!privateKeyDecrypted) {
        alert('Klucz prywatny nie jest załadowany!');
        return;
    }
    
    const msg = document.getElementById('msgInput').value;
    
    // Fetch recipient public key
    try {
        const keyRes = await fetch(`/api/users/${selectedUser.id}/public-key`, {
            credentials: 'same-origin'
        });
        const keyData = await keyRes.json();
        if (!keyRes.ok) {
            alert('Błąd: ' + (keyData.error || 'Klucz publiczny nie znaleziony'));
            return;
        }
        
        // Generate random AES key
        const aesKeyB64 = generateAESKey();
        
        // Encrypt message
        const encryptedContent = encryptAES(msg, aesKeyB64);
        if (!encryptedContent) {
            alert('Błąd szyfrowania wiadomości');
            return;
        }
        
        // Encrypt AES key with recipient public key
        const encryptedAESKey_recipient = await encryptAESKeyWithPublicKey(aesKeyB64, keyData.public_key);
        if (!encryptedAESKey_recipient) {
            alert('Błąd szyfrowania klucza dla odbiorcy');
            return;
        }
        
        // Also encrypt AES key with SENDER public key (so I can display my own message)
        // Fetch my public key
        const myKeyRes = await fetch(`/api/users/${myId}/public-key`, {
            credentials: 'same-origin'
        });
        const myKeyData = await myKeyRes.json();
        let encryptedAESKey_sender = null;
        if (myKeyRes.ok) {
            encryptedAESKey_sender = await encryptAESKeyWithPublicKey(aesKeyB64, myKeyData.public_key);
        }
        
        // Sign plaintext (original message) - not encrypted_content
        // This allows verification on receiving end where we have plaintext
        const signature = await signMessage(msg, privateKeyDecrypted);
        if (!signature) {
            alert('Błąd podpisywania wiadomości');
            return;
        }
        
        // Remember AES key for myself (to display own message)
        // Store in format: {r: "...", s: "...", k: "..."} where k is original key
        const sessionKeyData = {
            r: encryptedAESKey_recipient,  // for recipient
            s: encryptedAESKey_sender,      // for sender
            k: aesKeyB64                    // original key (for tests/debug)
        };
        
        // Send encrypted message
        const fileInput = document.getElementById('fileInput');
        const form = new FormData();
        form.append('recipient_id', selectedUser.id);
        form.append('encrypted_content', encryptedContent);
        form.append('session_key_encrypted', JSON.stringify(sessionKeyData));
        form.append('signature', signature);
        
        // Encrypt and add attachments
        if (fileInput && fileInput.files.length) {
            for (let i = 0; i < fileInput.files.length; i++) {
                const file = fileInput.files[i];
                try {
                    const arrayBuffer = await file.arrayBuffer();
                    const encryptedFileData = await encryptFileBinary(arrayBuffer, aesKeyB64);
                    if (!encryptedFileData) {
                        alert('Błąd szyfrowania pliku: ' + file.name);
                        return;
                    }
                    // Create blob from encrypted data string
                    const blob = new Blob([encryptedFileData], { type: 'application/octet-stream' });
                    form.append('attachments', blob, file.name);
                } catch (error) {
                    alert('Błąd przetwarzania pliku: ' + file.name + ' - ' + error.message);
                    return;
                }
            }
        }
        
        const response = await fetch('/api/messages/send', {
            method: 'POST',
            body: form,
            credentials: 'same-origin'
        });
        const data = await response.json();
        if (!response.ok) {
            alert('Błąd wysyłania: ' + (data.error || 'Nieznany błąd'));
            return;
        }
        document.getElementById('msgInput').value = '';
        if (fileInput) fileInput.value = '';
        document.getElementById('attachmentsList').innerHTML = '';
        fetchMessages(selectedUser.id);
    } catch (error) {
        alert('Błąd: ' + error.message);
    }
};

// === APPLICATION INITIALIZATION ===
(async ()=>{
    await fetchMyId();
    await fetchUsers();
    startUsersPolling();
})();
