# Projekt indywidualny – Ochrona Informacji  
## Bezpieczna aplikacja do wymiany zaszyfrowanych wiadomości

**Autor:** Stanisław Dutkiewicz  
**Nr albumu:** 329076  

---

## 1. Cel projektu

Celem projektu jest zaprojektowanie bezpiecznej aplikacji webowej umożliwiającej
wymianę zaszyfrowanych wiadomości z załącznikami, z zachowaniem poufności,
integralności oraz autentyczności komunikacji.  
Projekt stanowi praktyczne wykorzystanie wiedzy i wniosków zdobytych podczas
laboratoriów przedmiotu *Ochrona Informacji*.

---

## 2. Zakres funkcjonalny

- rejestracja i logowanie użytkownika  
- bezpieczne przechowywanie haseł  
- dwuetapowa autentykacja (2FA – TOTP/HOTP)  
- wysyłanie i odbieranie zaszyfrowanych wiadomości  
- weryfikacja autentyczności wiadomości (podpis cyfrowy)  
- usuwanie i oznaczanie wiadomości jako przeczytanych  
- generowanie i obsługa certyfikatów SSL/TLS (samo podpisane dla dev, CA dla prod)  
- walidacja wszystkich danych wejściowych
- opóźnienia i limity prób (brute-force protection)
- ograniczone informowanie o błędach  

---

## 3. Wnioski z laboratoriów wykorzystane w projekcie

- **Szyfry klasyczne** są całkowicie nieodporne na analizę – nie są stosowane.
- **Bezpieczeństwo haseł** zależy od entropii, a nie tylko długości.
- **MD5 i pochodne** są niewystarczające – wymagane są nowoczesne algorytmy.
- **Hashowanie haseł** musi być odporne na ataki GPU i słownikowe (Argon2id).
- **SQL Injection i XSS** są realnymi zagrożeniami – wymagają jawnej ochrony.
- **Kryptografia asymetryczna** jest zbyt wolna dla dużych danych – stosowane jest
  szyfrowanie hybrydowe.
- **Aplikacje webowe** muszą działać za reverse proxy z HTTPS.

---

## 4. Stos technologiczny

### Backend
- **Python + Flask**
- **Gunicorn**
- **SQLite**

### Frontend
- **HTML** 
- **CS** 
- **Javascript**

### Infrastruktura
- **NGINX** – reverse proxy, HTTPS
- **Docker / Docker Compose**

---

## 5. Kryptografia i biblioteki

### Algorytmy
- **AES-256-GCM** – szyfrowanie treści wiadomości i załączników  
- **RSA** – szyfrowanie klucza sesyjnego oraz podpis cyfrowy  
- **SHA-256** – integralność danych  
- **Argon2id** – hashowanie haseł  
- **TOTP (RFC 6238)** – dwuetapowa autentykacja  

### Biblioteki i używane funkcje

#### cryptography
- `AESGCM.encrypt()` / `AESGCM.decrypt()` – szyfrowanie AES-GCM  
- `rsa.generate_private_key()` – generowanie kluczy RSA  
- `private_key.sign()` / `public_key.verify()` – podpis i weryfikacja  
- `hashes.SHA256()` – funkcja skrótu  

#### argon2-cffi
- `PasswordHasher.hash()` – hashowanie hasła  
- `PasswordHasher.verify()` – weryfikacja hasła  

#### pyotp
- `pyotp.TOTP.now()` – generowanie kodu 2FA  
- `pyotp.TOTP.verify()` – weryfikacja kodu  

#### sqlite3 (bez ORM)
- `cursor.execute("... WHERE x = ?", (param,))` – zapytania parametryzowane  
- brak dynamicznej konkatenacji SQL (ochrona przed SQL Injection)

#### nh3
- `nh3.clean()` – sanityzacja treści wiadomości (ochrona przed XSS)

#### Flask + Gunicorn + Werkzeug
- Flask – framework webowy (analogicznie z4, z5, z6, z7)
- Gunicorn – serwer WSGI (analogicznie z7)
- ProxyFix (Werkzeug) – obsługa nagłówków X-Forwarded-* (z7)

---

## 6. Architektura systemu

System składa się z czterech warstw:
1. **Przeglądarka użytkownika** – interfejs i część operacji kryptograficznych  
2. **NGINX** – HTTPS, przekierowania, nagłówki bezpieczeństwa  
3. **Flask + Gunicorn** – logika aplikacji  
4. **SQLite** – przechowywanie zaszyfrowanych danych  

Wrażliwe dane przechowywane są wyłącznie w formie zaszyfrowanej.

---

## 7. Mechanizmy bezpieczeństwa

### 7.1 Polityka haseł
- minimalna długość: **≥ 12 znaków**
- wymagany zestaw: małe i duże litery, cyfry, znaki specjalne
- cel: **≥ ~60 bitów entropii**
- przechowywanie: **Argon2id + losowa sól**

### 7.2 Logowanie i komunikaty
- brak ujawniania informacji:
  - `"Invalid email or password"`
  - `"Invalid code"`
  - `"If the account exists, email was sent"`

### 7.3 Ochrona przed brute-force
- limit prób logowania: **np. 5 / 15 min / IP**
- osobny limit dla 2FA
- czasowe opóźnienia po błędach

### 7.4 Ochrona przed SQL Injection
- wyłącznie zapytania parametryzowane (`sqlite3`)
- brak konkatenacji zapytań SQL

### 7.5 Ochrona przed XSS
- sanityzacja treści wiadomości przy użyciu **nh3**
- escapowanie danych wyjściowych

### 7.6 HTTPS
- wymuszenie HTTPS przez **NGINX**
- reverse proxy zamiast serwera developerskiego

---

## 8. Podsumowanie

Projekt realizuje wymagania przedmiotu oraz wykorzystuje technologie i mechanizmy
poznane na laboratoriach. Zastosowanie szyfrowania hybrydowego, Argon2id,
dwuetapowej autentykacji oraz jawnych mechanizmów ochrony przed atakami
zapewnia wysoki poziom bezpieczeństwa przetwarzanych informacji.
