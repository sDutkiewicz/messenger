import os
import glob
import time
from datetime import datetime, timedelta
from constants import RATE_LIMIT_SHORT_ATTEMPTS, RATE_LIMIT_SHORT_DURATION_MIN
from constants import RATE_LIMIT_LONG_ATTEMPTS, RATE_LIMIT_LONG_DURATION_MIN
from db_queries import LoginAttemptQueries


def cleanup_qr_file(qr_path):
    """Remove temporary QR code file"""
    try:
        if not qr_path or not qr_path.startswith('/static/qrs/'):
            return
        
        # Convert web path to filesystem path
        fs_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), qr_path.lstrip('/'))
        if os.path.exists(fs_path):
            os.remove(fs_path)
    except Exception:
        pass  # Silent fail for cleanup operations


def cleanup_qr_files_for_user(user_id):
    """Remove all QR files for user (wildcard cleanup)"""
    try:
        qr_dir = os.path.join(os.path.dirname(__file__), 'static', 'qrs')
        pattern = os.path.join(qr_dir, f"{user_id}_*.png")
        for filepath in glob.glob(pattern):
            try:
                os.remove(filepath)
            except Exception:
                pass
    except Exception:
        pass  # Silent fail for cleanup operations


def calculate_block_remaining_time(username, attempts_threshold, block_duration_min):
    """Calculate remaining block time. Returns (is_blocked, remaining_seconds)"""
    try:
        last_attempt = LoginAttemptQueries.get_last_failed_timestamp(username)
        if not last_attempt:
            return False, 0
        
        # Parse timestamp (handle both ISO format and regular datetime)
        timestamp_str = last_attempt['timestamp']
        if 'Z' in timestamp_str:
            timestamp_str = timestamp_str.replace('Z', '+00:00')
        
        try:
            last_attempt_time = datetime.fromisoformat(timestamp_str)
        except ValueError:
            # Fallback: try parsing without timezone
            last_attempt_time = datetime.fromisoformat(timestamp_str.split('+')[0])
        
        # Calculate unblock time
        block_duration = timedelta(minutes=block_duration_min)
        unblock_time = last_attempt_time + block_duration
        now = datetime.now()
        
        # Calculate remaining seconds
        remaining = int((unblock_time - now).total_seconds())
        
        if remaining > 0:
            return True, remaining
    except Exception:
        pass
    
    return False, 0


def get_block_status(username):
    """Check if user is blocked. Returns (is_blocked, remaining_seconds, block_type)"""
    from constants import RATE_LIMIT_WINDOW_MIN
    recent_failed = LoginAttemptQueries.get_recent_failed_count(username, RATE_LIMIT_WINDOW_MIN)
    
    # Check for long block (30 minutes after 8+ attempts)
    if recent_failed >= RATE_LIMIT_LONG_ATTEMPTS:
        is_blocked, remaining = calculate_block_remaining_time(
            username, 
            RATE_LIMIT_LONG_ATTEMPTS,
            RATE_LIMIT_LONG_DURATION_MIN
        )
        if is_blocked:
            return True, remaining, 'long'
    
    # Check for short block (5 minutes after 5+ attempts)
    if recent_failed >= RATE_LIMIT_SHORT_ATTEMPTS:
        is_blocked, remaining = calculate_block_remaining_time(
            username,
            RATE_LIMIT_SHORT_ATTEMPTS,
            RATE_LIMIT_SHORT_DURATION_MIN
        )
        if is_blocked:
            return True, remaining, 'short'
    
    return False, 0, None


def apply_failed_attempt_delay(failed_count):
    """Apply progressive backoff delay on failed attempts (0.5s-1.0s)"""
    if failed_count >= 3:
        time.sleep(1.0)    # 1 second after 3+ attempts
    else:
        time.sleep(0.5)    # 0.5 seconds before
