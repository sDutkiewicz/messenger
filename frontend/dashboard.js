
// Check if user is logged in, if not redirect to login
if (!localStorage.getItem('loggedIn')) {
    window.location.href = 'login.html';
}

let selectedUser = null;          // Currently selected user to chat with
let myId = null;                  // Current logged-in user ID
let privateKeyDecrypted = null;   // User's decrypted private key (from login)

// STARTUP

// Load user info and initialize dashboard
async function initDashboard() {
    await loadMyInfo();
    await loadUserList();
    startPollingUsers();
}

// USER MANAGEMENT

// Fetch current user info (ID, username) and private key from session
async function loadMyInfo() {
    const res = await fetch('/api/me', { credentials: 'same-origin' });
    const data = await res.json();
    myId = data.id;
    
    // Display username in header
    const nameEl = document.getElementById('meName');
    nameEl.textContent = data.username || '—';
    
    // Load private key from sessionStorage (saved during login)
    privateKeyDecrypted = sessionStorage.getItem('privateKeyDecrypted');
    if (!privateKeyDecrypted) {
        alert('Klucz prywatny nie jest dostępny. Proszę zalogować się ponownie.');
        window.location.href = 'login.html';
    }
}

// Fetch and display all users in the left sidebar
async function loadUserList() {
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

// Select a user and load conversation
function selectUser(user) {
    selectedUser = user;
    document.getElementById('convTitle').textContent = 'Rozmowa z: ' + user.username;
    document.getElementById('messages').style.display = 'block';
    document.getElementById('sendForm').style.display = 'flex';
    
    // Highlight selected user
    document.querySelectorAll('#users li').forEach(li => li.classList.remove('selected'));
    const node = Array.from(document.querySelectorAll('#users li')).find(n => n.dataset.id == user.id);
    if (node) node.classList.add('selected');
    
    // Load messages from this conversation
    loadMessages(user.id);
    startPollingMessages(user.id);
}

// MESSAGE HANDLING 

// Fetch messages from conversation, decrypt, and display
async function loadMessages(userId) {
    const res = await fetch(`/api/messages/conversation/${userId}`);
    if (!res.ok) return;
    const data = await res.json();
    const messagesDiv = document.getElementById('messages');
    
    // Skip re-render if messages haven't changed
    const currentCount = messagesDiv.querySelectorAll('.message-item').length;
    if (currentCount === data.messages.length && currentCount > 0) {
        const lastItemText = messagesDiv.querySelector('.message-item:last-child span')?.textContent || '';
        const lastMsg = data.messages[data.messages.length - 1];
        if (lastItemText.includes(lastMsg.sender)) return;
    }
    
    messagesDiv.innerHTML = '';
    
    for (const m of data.messages) {
        const wrapper = document.createElement('div');
        wrapper.className = 'message-item';
        
        // Decrypt message content
        let text = await decryptMessage(m, myId, privateKeyDecrypted);
        
        const textNode = document.createElement('span');
        textNode.textContent = text;
        wrapper.appendChild(textNode);
        
        // Store encryption key for attachments
        if (m.encrypted_content && m.session_key_encrypted) {
            const aesKeyB64 = await decryptAESKey(m.session_key_encrypted, privateKeyDecrypted);
            if (aesKeyB64) wrapper.dataset.aesKey = aesKeyB64;
        }
        
        // Add attachment buttons if message has files
        if (m.attachments && m.attachments.length) {
            addAttachmentsUI(wrapper, m.attachments);
        }
        
        // Add delete button for own messages, verify button for received
        if (m.sender_id === myId) {
            addDeleteButton(wrapper, m.id);
        } else {
            addVerifyButton(wrapper, m, textNode);
        }
        
        messagesDiv.appendChild(wrapper);
    }
    
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// Decrypt message (handle both sent and received)
async function decryptMessage(m, myId, privateKeyDecrypted) {
    const who = (m.sender_id === myId) ? 'You' : m.sender;
    let isEncrypted = m.encrypted_content && m.session_key_encrypted;
    
    if (!isEncrypted) {
        return `${who}: [Unencrypted message]`;
    }
    
    const aesKeyB64 = await decryptAESKey(m.session_key_encrypted, privateKeyDecrypted);
    if (!aesKeyB64) {
        return `${who}: [Error decrypting key]`;
    }
    
    const plaintext = decryptAES(m.encrypted_content, aesKeyB64);
    if (!plaintext) {
        return `${who}: [Error decrypting message]`;
    }
    
    let text = `${who}: ${plaintext}`;
    
    // For sent messages: show read status
    if (m.sender_id === myId) {
        text += m.is_read ? ' [Read]' : ' [Sent]';
    }
    
    return text;
}

// Add download buttons for attachments
function addAttachmentsUI(wrapper, attachments) {
    const attList = document.createElement('div');
    attList.style.marginTop = '6px';
    
    attachments.forEach(a => {
        const btn = document.createElement('button');
        btn.textContent = a.filename;
        btn.type = 'button';
        btn.style.display = 'inline-block';
        btn.style.marginRight = '8px';
        btn.style.padding = '4px 8px';
        btn.style.backgroundColor = '#007bff';
        btn.style.color = 'white';
        btn.style.border = 'none';
        btn.style.borderRadius = '3px';
        btn.style.cursor = 'pointer';
        
        btn.onclick = async (e) => {
            e.preventDefault();
            await downloadAttachment(a, wrapper);
        };
        
        attList.appendChild(btn);
    });
    
    wrapper.appendChild(attList);
}

// Download and decrypt file
async function downloadAttachment(attachment, wrapper) {
    try {
        const aesKey = wrapper.dataset.aesKey;
        if (!aesKey) {
            alert('Brak klucza deszyfrowania dla pliku');
            return;
        }
        
        const res = await fetch(`/api/attachments/${attachment.id}`);
        if (!res.ok) {
            alert('Błąd pobierania pliku');
            return;
        }
        
        const data = await res.json();
        const fileBuffer = decryptFileBinary(data.encrypted_data, aesKey);
        
        if (!fileBuffer) {
            alert('Błąd deszyfrowania pliku');
            return;
        }
        
        // Save decrypted file
        const blob = new Blob([fileBuffer], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = data.filename || 'attachment';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    } catch (error) {
        alert('Błąd: ' + error.message);
    }
}

// Add delete button for own messages
function addDeleteButton(wrapper, messageId) {
    const btn = document.createElement('button');
    btn.textContent = 'Delete';
    btn.className = 'delete-btn';
    
    btn.onclick = async (e) => {
        e.stopPropagation();
        if (!confirm('Na pewno usunąć wiadomość?')) return;
        
        const res = await fetch(`/api/messages/${messageId}`, { method: 'DELETE' });
        if (res.status === 204) {
            loadMessages(selectedUser.id);
        } else {
            const err = await res.json();
            alert(err.error || 'Błąd usuwania wiadomości');
        }
    };
    
    wrapper.appendChild(btn);
}

// Add verify button for received messages (check signature)
function addVerifyButton(wrapper, m, textNode) {
    if (!wrapper.dataset.plaintext || !wrapper.dataset.signature) {
        return;
    }
    
    const btn = document.createElement('button');
    btn.textContent = 'Verify';
    btn.style.display = 'inline-block';
    btn.style.padding = '2px 6px';
    btn.style.fontSize = '11px';
    btn.style.backgroundColor = '#007bff';
    btn.style.color = 'white';
    btn.style.border = 'none';
    btn.style.borderRadius = '3px';
    btn.style.cursor = 'pointer';
    btn.style.marginLeft = '4px';
    
    btn.onclick = async (e) => {
        e.stopPropagation();
        await verifyMessageSignature(wrapper, m);
    };
    
    textNode.appendChild(btn);
}

// Verify message signature
async function verifyMessageSignature(wrapper, m) {
    const plaintext = wrapper.dataset.plaintext;
    const signature = wrapper.dataset.signature;
    
    if (!signature) {
        alert('Wiadomość nie ma podpisu - nie można weryfikować');
        return;
    }
    
    try {
        const senderPublicKey = await getSenderPublicKey(parseInt(wrapper.dataset.senderId));
        if (!senderPublicKey) {
            alert('Nie można pobrać klucza publicznego nadawcy');
            return;
        }
        
        const isValid = await verifySignature(plaintext, signature, senderPublicKey);
        if (isValid) {
            alert('✓ Wiadomość jest autentyczna!\n\nPodpis zweryfikowany poprawnie.');
        } else {
            alert('✗ Wiadomość NIE jest autentyczna!\n\nPodpis jest nieprawidłowy - mogła zostać zmieniona!');
        }
    } catch (error) {
        alert('Błąd weryfikacji: ' + error.message);
    }
}

// SENDING MESSAGES

// Show selected files before sending
function updateAttachmentsList() {
    const fileInput = document.getElementById('fileInput');
    const listContainer = document.getElementById('attachmentsList');
    listContainer.innerHTML = '';
    
    if (!fileInput.files.length) return;
    
    const div = document.createElement('div');
    div.style.marginTop = '8px';
    div.style.padding = '8px';
    div.style.backgroundColor = '#f0f0f0';
    div.style.borderRadius = '4px';
    
    const title = document.createElement('strong');
    title.textContent = 'Pliki (' + fileInput.files.length + '):';
    div.appendChild(title);
    
    Array.from(fileInput.files).forEach((file, index) => {
        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.justifyContent = 'space-between';
        row.style.alignItems = 'center';
        row.style.padding = '4px';
        row.style.borderBottom = '1px solid #ddd';
        
        const name = document.createElement('span');
        name.textContent = file.name + ' (' + (file.size / 1024).toFixed(1) + ' KB)';
        row.appendChild(name);
        
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
        
        row.appendChild(removeBtn);
        div.appendChild(row);
    });
    
    listContainer.appendChild(div);
}

// Send encrypted message with optional attachments
async function sendMessage(e) {
    e.preventDefault();
    
    if (!selectedUser || !privateKeyDecrypted) return;
    
    const msg = document.getElementById('msgInput').value;
    
    try {
        // Get recipient's public key
        const keyRes = await fetch(`/api/users/${selectedUser.id}/public-key`, {
            credentials: 'same-origin'
        });
        if (!keyRes.ok) {
            alert('Nie można pobrać klucza odbiorcy');
            return;
        }
        const keyData = await keyRes.json();
        
        // Generate random AES key for this message
        const aesKeyB64 = generateAESKey();
        
        // Encrypt message
        const encryptedContent = encryptAES(msg, aesKeyB64);
        if (!encryptedContent) {
            alert('Błąd szyfrowania wiadomości');
            return;
        }
        
        // Encrypt AES key for recipient
        const encryptedAESKey_recipient = await encryptAESKeyWithPublicKey(aesKeyB64, keyData.public_key);
        if (!encryptedAESKey_recipient) {
            alert('Błąd szyfrowania klucza');
            return;
        }
        
        // Also encrypt AES key for sender (so I can view my own message)
        const myKeyRes = await fetch(`/api/users/${myId}/public-key`, {
            credentials: 'same-origin'
        });
        let encryptedAESKey_sender = null;
        if (myKeyRes.ok) {
            const myKeyData = await myKeyRes.json();
            encryptedAESKey_sender = await encryptAESKeyWithPublicKey(aesKeyB64, myKeyData.public_key);
        }
        
        // Sign original plaintext message
        const signature = await signMessage(msg, privateKeyDecrypted);
        if (!signature) {
            alert('Błąd podpisywania wiadomości');
            return;
        }
        
        // Prepare form data
        const form = new FormData();
        form.append('recipient_id', selectedUser.id);
        form.append('encrypted_content', encryptedContent);
        form.append('session_key_encrypted', JSON.stringify({
            r: encryptedAESKey_recipient,  // for recipient
            s: encryptedAESKey_sender      // for sender
        }));
        form.append('signature', signature);
        
        // Collect encrypted attachments as base64
        const attachments = [];
        const fileInput = document.getElementById('fileInput');
        if (fileInput && fileInput.files.length) {
            for (let i = 0; i < fileInput.files.length; i++) {
                const file = fileInput.files[i];
                const arrayBuffer = await file.arrayBuffer();
                const encryptedFileDataB64 = await encryptFileBinary(arrayBuffer, aesKeyB64);
                
                if (!encryptedFileDataB64) {
                    alert('Błąd szyfrowania pliku: ' + file.name);
                    return;
                }
                
                attachments.push({
                    filename: file.name,
                    encrypted_data: encryptedFileDataB64
                });
            }
        }
        
        // Build complete message object
        const messageData = {
            recipient_id: selectedUser.id,
            encrypted_content: encryptedContent,
            session_key_encrypted: JSON.stringify({
                r: encryptedAESKey_recipient,
                s: encryptedAESKey_sender
            }),
            signature: signature,
            attachments: attachments
        };
        
        // Send message as JSON
        const res = await fetch('/api/messages/send', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(messageData),
            credentials: 'same-origin'
        });
        
        if (!res.ok) {
            const data = await res.json();
            alert('Błąd wysyłania: ' + (data.error || 'Nieznany błąd'));
            return;
        }
        
        // Clear form
        document.getElementById('msgInput').value = '';
        if (fileInput) fileInput.value = '';
        document.getElementById('attachmentsList').innerHTML = '';
        
        // Reload conversation
        loadMessages(selectedUser.id);
    } catch (error) {
        alert('Błąd: ' + error.message);
    }
}
// POLLING (Auto-refresh)

let pollIntervalId = null;
let usersIntervalId = null;

// Auto-refresh user list every 10 seconds
function startPollingUsers() {
    if (usersIntervalId) return;
    usersIntervalId = setInterval(loadUserList, 10000);
}

// Auto-refresh messages every 2 seconds
function startPollingMessages(userId) {
    if (pollIntervalId) clearInterval(pollIntervalId);
    pollIntervalId = setInterval(() => {
        if (selectedUser) loadMessages(selectedUser.id);
    }, 2000);
}

// EVENT LISTENERS 

// Logout button
document.getElementById('logoutBtn').onclick = async function() {
    await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
    localStorage.removeItem('loggedIn');
    window.location.href = 'login.html';
};

// File input changed
document.getElementById('fileInput').onchange = updateAttachmentsList;

// Send message form
document.getElementById('sendForm').onsubmit = sendMessage;

// INITIALIZATION 
initDashboard();