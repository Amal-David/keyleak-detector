"""
A minimal imghdr replacement for Python 3.13+ compatibility.
This module provides basic image type detection functionality.
"""

# List of test functions (required by mitmproxy)
tests = []


def what(file, h=None):
    """
    Detect the type of an image.
    
    Args:
        file: A file path or file-like object
        h: Optional header bytes
        
    Returns:
        A string describing the image type, or None if not recognized
    """
    if h is None:
        if isinstance(file, str):
            try:
                with open(file, 'rb') as f:
                    h = f.read(32)
            except:
                return None
        else:
            try:
                h = file.read(32)
                file.seek(0)
            except:
                return None
    
    # Basic image type detection based on magic bytes
    if h[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    elif h[:3] == b'\xff\xd8\xff':
        return 'jpeg'
    elif h[:6] in (b'GIF87a', b'GIF89a'):
        return 'gif'
    elif h[:2] in (b'MM', b'II'):
        return 'tiff'
    elif h[:2] == b'BM':
        return 'bmp'
    elif h[:4] == b'RIFF' and h[8:12] == b'WEBP':
        return 'webp'
    
    return None
