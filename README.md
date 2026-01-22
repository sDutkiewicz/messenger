

# Messenger

Aplikacja do szyfrowanej wymiany wiadomości i plików z obsługą 2FA.

## Uruchomienie

### Docker (zalecane)

1. Wygeneruj certyfikaty SSL:
```bash
mkdir -p certs
cd certs
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=PL/ST=Poland/L=Poland/O=Messenger/OU=Dev/CN=localhost"
cd ..
```

2. Uruchom:
```bash
docker-compose up --build
```

3. Otwórz: https://localhost:3443

### Bezpośrednio (Python)

1. Zainstaluj zależności:
```bash
cd backend
pip install -r requirements.txt
```

2. Uruchom backend:
```bash
python app.py
```

3. Otwórz frontend w przeglądarce: http://localhost:8000

## Struktura projektu

```
messenger/
├── backend/                    # Flask API
|   ├──data/                      # Baza danych SQLite 
│   ├── app.py                 # Główna aplikacja
│   ├── auth.py                # Endpoints autentykacji
│   ├── messages.py            # Endpoints wiadomości
│   ├── db.py                  # Inicjalizacja bazy
│   ├── db_queries.py          # Query do bazy
│   ├── wsgi.py                # Entry point Gunicorn (przy docker)
│   ├── requirements.txt       # Python zależności
│   ├── Dockerfile             # Obraz Docker
│   └── helpers/               # Helpery
│       ├── crypto_helpers.py  # RSA, Fernet, Argon2
│       ├── totp_helpers.py    # 2FA/TOTP
│       ├── password_helpers.py
│       ├── sanitize.py
│       ├── qr_cleanup.py
│       └── rate_limiter.py
│
├── frontend/                   # HTML/JS/CSS
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── dashboard.js           # Logika aplikacji, wysyłanie wiadomości
│   ├── crypto.js              # AES (CryptoJS), RSA (szyfrowanie wiadomości)
│   ├── styles.css
│   └── Dockerfile
│
├── nginx/                      # Reverse proxy
│   ├── nginx.conf
│   └── Dockerfile
│
├── docker-compose.yml         # Konfiguracja kontenerów
├── README.md                  

```


