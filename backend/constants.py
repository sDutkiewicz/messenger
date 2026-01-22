
# ========== PASSWORD VALIDATION ==========
MIN_PASSWORD_LENGTH = 12
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32

# ========== RATE LIMITING ==========
RATE_LIMIT_SHORT_ATTEMPTS = 5        # Failed attempts to trigger 5-min block
RATE_LIMIT_SHORT_DURATION_MIN = 5    # Duration of 5-min block
RATE_LIMIT_LONG_ATTEMPTS = 8         # Failed attempts to trigger 30-min block
RATE_LIMIT_LONG_DURATION_MIN = 30    # Duration of 30-min block
RATE_LIMIT_WINDOW_MIN = 30           # Sliding window for counting recent attempts

# ========== FILE UPLOADS ==========
MAX_FILE_SIZE_MB = 25
MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024

# ========== ERROR MESSAGES ==========
ERROR_INVALID_CREDENTIALS = 'Nieprawidłowe dane logowania.'
ERROR_USERNAME_EXISTS = 'Nazwa użytkownika już istnieje.'
ERROR_EMAIL_EXISTS = 'Email już istnieje.'
ERROR_INVALID_USERNAME = 'Nieprawidłowa nazwa użytkownika.'
ERROR_INVALID_EMAIL = 'Nieprawidłowy email.'
ERROR_WEAK_PASSWORD = 'Hasło musi mieć min. 12 znaków, dużą i małą literę oraz cyfrę.'
ERROR_TOO_MANY_ATTEMPTS_SHORT = 'Zbyt wiele nieudanych prób logowania. Spróbuj za 5 minut.'
ERROR_TOO_MANY_ATTEMPTS_LONG = 'Zbyt wiele nieudanych prób logowania. Konto zablokowane na 30 minut.'
ERROR_UNAUTHORIZED = 'Nieautoryzowany.'
ERROR_USER_NOT_FOUND = 'Użytkownik nie znaleziony.'
ERROR_REGISTRATION_FAILED = 'Rejestracja nie powiodła się.'
ERROR_2FA_FAILED = 'Weryfikacja 2FA nie powiodła się.'
ERROR_INVALID_RECOVERY_CODE = 'Nieprawidłowy kod odzyskiwania.'
ERROR_PASSWORD_MISMATCH = 'Hasła się nie zgadzają.'

# ========== SUCCESS MESSAGES ==========
MSG_LOGIN_REQUIRES_2FA = 'Wymagana weryfikacja 2FA.'
MSG_LOGIN_SUCCESS = 'Zalogowano pomyślnie.'
MSG_LOGOUT_SUCCESS = 'Wylogowano.'
MSG_REGISTRATION_PREPARED = 'Rejestracja przygotowana. Dokończ konfigurację 2FA.'
MSG_REGISTRATION_SUCCESS = 'Rejestracja zakończona pomyślnie.'
MSG_2FA_VERIFICATION_SUCCESS = 'Weryfikacja 2FA zakończona pomyślnie.'
MSG_PASSWORD_RESET_LINK_SENT = 'Jeśli email istnieje, otrzymasz instrukcje.'
MSG_PASSWORD_RESET_SUCCESS = 'Hasło zostało zmienione. Zaloguj się nowym hasłem.'
MSG_2FA_RECOVERY_SUCCESS = '2FA recovery kod zaakceptowany. Musisz teraz ustawić nowy 2FA.'
MSG_2FA_SETUP_SUCCESS = 'Nowy 2FA i recovery codes skonfigurowane'
