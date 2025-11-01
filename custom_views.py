from typing import Optional, Any

class CustomImageView:
    """A simple image view that doesn't require mitmproxy contentviews."""
    name = "Custom Image"
    
    def __call__(
        self,
        data: bytes,
        *,
        content_type: Optional[str] = None,
        **metadata: Any,
    ):
        if not data:
            return "No image data", []
            
        try:
            # Just show basic info about the image data
            return f"Image ({len(data)} bytes)", [
                ("text", f"Image data: {len(data)} bytes\n"),
                ("text", f"Preview (first 100 bytes): {str(data[:100])}")
            ]
        except Exception as e:
            return f"Image (error: {str(e)})", []

def load(l):
    return CustomImageView()
