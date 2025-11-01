from mitmproxy import contentviews
from mitmproxy.net.http import Headers
from mitmproxy.utils import strutils
from typing import Optional, List, Any
import base64

class CustomImageView(contentviews.View):
    name = "Custom Image"
    
    def __call__(
        self,
        data: bytes,
        *,
        content_type: Optional[str] = None,
        **metadata: Any,
    ) -> contentviews.TViewResult:
        if not data:
            return "No image data", []
            
        try:
            # Try to decode as base64 for display
            b64_data = base64.b64encode(data).decode("utf-8")
            return f"Image ({len(data)} bytes)", [
                ("text", f"Image data: {len(data)} bytes\n"),
                ("text", f"Preview (base64): {b64_data[:100]}...")
            ]
        except Exception as e:
            return f"Image (error: {str(e)})", []

def load(l):
    return CustomImageView()
