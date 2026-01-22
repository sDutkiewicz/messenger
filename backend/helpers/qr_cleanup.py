"""QR code file cleanup utilities"""
import os
import glob


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
        pass


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
        pass
