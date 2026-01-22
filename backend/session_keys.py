
# Session key constants to prevent typos and ensure consistency.

class SessionKeys:
    """Constants for all session keys used in authentication flow"""
    
    # Main authentication
    USER_ID = 'user_id'
    PRE_2FA_USER_ID = 'pre_2fa_user_id'
    PRE_2FA_PASSWORD = 'pre_2fa_password'
    
    # Registration flow
    REG_PENDING = 'reg_pending'
    
    # 2FA verification
    TWO_FA_VERIFIED = '2fa_verified'
    IN_2FA_RECOVERY_MODE = '2fa_recovery_mode'
    
    # Password reset flow
    PASSWORD_RESET_USER_ID = 'password_reset_user_id'
    PASSWORD_RESET_EMAIL = 'password_reset_email'
    CAN_RESET_PASSWORD = 'can_reset_password'
    
    # Forced 2FA setup (after recovery)
    FORCE_2FA_SECRET = '_force_2fa_secret'
    FORCE_2FA_QR_PATH = '_setup2fa_qr_path'
