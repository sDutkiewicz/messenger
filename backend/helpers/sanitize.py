try:
    import nh3
except Exception:
    nh3 = None


def clean_input(value):
    """Return a cleaned string using nh3 if available.

    Keeps None as-is. Falls back to a str(value) or the original value
    if conversion fails. Exceptions are swallowed to avoid breaking
    the main flow.
    """
    if value is None:
        return value
    try:
        s = str(value)
    except Exception:
        return value
    if nh3:
        try:
            return nh3.clean(s)
        except Exception:
            return s
    return s
