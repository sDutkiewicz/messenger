"""Rate limiting and login attempt tracking"""
import time
from datetime import datetime, timedelta
from flask import current_app, jsonify, make_response
from constants import RATE_LIMIT_SHORT_ATTEMPTS, RATE_LIMIT_SHORT_DURATION_MIN
from constants import RATE_LIMIT_LONG_ATTEMPTS, RATE_LIMIT_LONG_DURATION_MIN
from constants import ERROR_TOO_MANY_ATTEMPTS_LONG, ERROR_TOO_MANY_ATTEMPTS_SHORT
from db_queries import LoginAttemptQueries


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
        time.sleep(1.0)
    else:
        time.sleep(0.5)


def record_login_attempt(username, success):
    """Log login attempt to database"""
    try:
        LoginAttemptQueries.record(username, success)
    except Exception as e:
        current_app.logger.error('Failed to record login attempt: %s', str(e))


def reset_failed_attempts(username):
    """Reset failed login attempts after successful login"""
    try:
        LoginAttemptQueries.clear_failed_attempts(username)
    except Exception as e:
        current_app.logger.error('Failed to reset login attempts: %s', str(e))


def check_rate_limit(username):
    """Check if user has exceeded login attempt limit"""
    is_blocked, remaining_seconds, block_type = get_block_status(username)
    
    if is_blocked:
        error_msg = ERROR_TOO_MANY_ATTEMPTS_LONG if block_type == 'long' else ERROR_TOO_MANY_ATTEMPTS_SHORT
        retry_after = RATE_LIMIT_LONG_DURATION_MIN * 60 if block_type == 'long' else RATE_LIMIT_SHORT_DURATION_MIN * 60
        
        resp = make_response(jsonify({'error': error_msg}), 429)
        resp.headers['Retry-After'] = str(retry_after)
        return resp
    
    return None
