import sys
import os
from pathlib import Path

def patch_mitmproxy():
    """Patch mitmproxy to work with Python 3.13+ by replacing imghdr with a custom implementation."""
    # Create a custom imghdr module
    imghdr_path = os.path.join(os.path.dirname(__file__), 'imghdr.py')
    with open(imghdr_path, 'w') as f:
        f.write('''
"""A minimal imghdr replacement for Python 3.13+ compatibility."""

def what(file, h=None):
    """Minimal implementation that returns None for all files."""
    return None
''')
    
    # Add our custom imghdr to the path
    sys.path.insert(0, os.path.dirname(imghdr_path))
    
    # Now patch the mitmproxy content view
    from mitmproxy.contentviews import image
    
    # Replace the ViewImage class with a simple implementation
    class SimpleImageView:
        name = "image"
        
        def __call__(self, *args, **kwargs):
            return "Image (content view disabled in Python 3.13+)"
    
    # Replace the original view
    image.ViewImage = SimpleImageView

# Apply the patch when this module is imported
patch_mitmproxy()
