"""QR code file cleanup utilities"""
import os
import glob


def cleanup_qr_file(qr_path):
    """Remove temporary QR code file"""
    try:
        if not qr_path:
            return
        
        # Convert web path to filesystem path
        # qr_path is like: /static/qrs/reg_1234567890_abcdef.png
        if qr_path.startswith('/static/qrs/'):
            filename = qr_path.split('/')[-1]
            # Go up from helpers/ to backend/, then to static/qrs/
            qr_dir = os.path.join(os.path.dirname(__file__), '..', 'static', 'qrs')
            fs_path = os.path.join(qr_dir, filename)
            if os.path.exists(fs_path):
                os.remove(fs_path)
    except Exception:
        pass


def cleanup_qr_files_for_user(user_id):
    """Remove all QR files for user (wildcard cleanup)"""
    try:
        # Go up from helpers/ to backend/, then to static/qrs/
        qr_dir = os.path.join(os.path.dirname(__file__), '..', 'static', 'qrs')
        pattern = os.path.join(qr_dir, f"reg_*_*.png")
        for filepath in glob.glob(pattern):
            try:
                os.remove(filepath)
            except Exception:
                pass
    except Exception:
        pass
