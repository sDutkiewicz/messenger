# Szyfrowanie Wiadomości w Aplikacji Messenger

## Model Hybrydowy Szyfrowania (WAŻNE)

To jest podejście zasugerowane przez prowadzącego i jest standardową praktyką w kryptografii.

### Architektura:

#### 1. **Klucz Prywatny Użytkownika**
- ✅ Przechowywany w bazie danych
- ✅ Sam zaszyfrowany (encryption at rest)
- ✅ Szyfrowany za pomocą klucza pochodzącego z hasła użytkownika
- ✅ Tylko autentyczny użytkownik może go odszyfrować ze swoim hasłem

**Logika:**
```
Hasło użytkownika → Key Derivation (PBKDF2/Argon2) → Klucz do odszyfrowania prywatnego klucza
```

#### 2. **Szyfrowanie Wiadomości (Symetryczne)**
- Algorytm: **AES-256** (lub Fernet - Authenticated Encryption)
- Używany do szyfrowania treści wiadomości
- Szybki i efektywny dla dużych danych
- Każda wiadomość powinna mieć swój IV (Initialization Vector)

**Logika:**
```
Wiadomość → AES-256 (klucz symetryczny) → Zaszyfrowana wiadomość
```

#### 3. **Wymiana Kluczy i Autentyczność (RSA)**
- Algorytm: **RSA-2048 lub RSA-4096**
- Używany do:
  - **Wymiany kluczy symetrycznych** (bezpieczne przesłanie AES key)
  - **Podpisów cyfrowych** (weryfikacja autora wiadomości)
  - **Weryfikacji autentyczności** (czy rzeczywiście od tego użytkownika?)

**Logika:**
```
Wiadomość → SHA-256 (hash) → RSA Private Key (podpis) → Wysłanie
Odbiorca: Weryfikuje podpis → RSA Public Key → Potwierdza autora
```

---

## Flow Wysyłania Wiadomości

1. **Użytkownik A wysyła wiadomość do Użytkownika B:**
   - Tworzy losowy klucz symetryczny (AES key)
   - Szyfruje wiadomość: `AES-256(treść, klucz)`
   - Podpisuje wiadomość: `RSA_Sign(SHA256(treść), privateKeyA)`
   - Szyfruje AES key: `RSA_Encrypt(aesKey, publicKeyB)`
   - Wysyła: `{encrypted_message, encrypted_aes_key, signature}`

2. **Użytkownik B odbiera wiadomość:**
   - Odszyfruje AES key: `RSA_Decrypt(encrypted_aes_key, privateKeyB)`
   - Odszyfruje wiadomość: `AES_Decrypt(encrypted_message, aesKey)`
   - Weryfikuje podpis: `RSA_Verify(signature, SHA256(treść), publicKeyA)`
   - Jeśli weryfikacja OK → wiadomość jest autentyczna i od User A

---

## Praktyczne Wdrażanie

### Biblioteki:
- **Python**: `cryptography`, `pycryptodome`
- **Szyfrowanie**: `Fernet` (Fernet) lub `AES` (PyCryptodome)
- **RSA**: `rsa` lub moduł z `cryptography`
- **Hash**: `hashlib.sha256()`

### Klucze w Bazie:
```python
# Tabela users:
- user_id
- username
- password_hash
- public_key (RSA, bez szyfrowania)
- encrypted_private_key (RSA, zaszyfrowany)
- encryption_key_salt (dla key derivation)

# Tabela messages:
- message_id
- sender_id
- receiver_id
- encrypted_message (AES-256)
- encrypted_aes_key (RSA)
- signature (RSA sign)
- timestamp
```

---

## Rzeczywiste Zastosowanie w Praktyce

| Aplikacja | Model |
|-----------|-------|
| **Signal** | E2E (RSA/Curve25519 + AES) |
| **WhatsApp** | Signal Protocol (RSA + AES) |
| **Telegram** | MTProto (RSA + AES) |
| **PGP/GPG** | RSA + Symetryczne |
| **TLS/HTTPS** | RSA Handshake + AES Stream |

---

## Wniosek

✅ **Twoje podejście jest prawidłowe i powszechnie używane w praktyce!**

Hybrydowe szyfrowanie (RSA + AES) jest standardem w nowoczesnych systemach komunikacji.
