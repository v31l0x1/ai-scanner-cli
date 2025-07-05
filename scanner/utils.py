"""
Utility functions for the AI code scanner
"""

import logging
import os
import re
from typing import Optional

def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )

def validate_api_key(api_key: Optional[str]) -> bool:
    """Validate Gemini API key format"""
    if not api_key:
        return False
    
    # Basic validation - Gemini API keys typically start with 'AIza'
    if not api_key.startswith('AIza'):
        return False
    
    # Check minimum length
    if len(api_key) < 30:
        return False
    
    return True

def sanitize_path(path: str) -> str:
    """Sanitize file path for safe operations"""
    # Remove any dangerous characters
    path = re.sub(r'[<>:"|?*]', '', path)
    
    # Normalize path separators
    path = os.path.normpath(path)
    
    return path

def get_file_extension(filename: str) -> str:
    """Get file extension in lowercase"""
    return os.path.splitext(filename)[1].lower()

def is_binary_file(file_path: str) -> bool:
    """Check if file is binary"""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            if b'\0' in chunk:
                return True
        return False
    except:
        return True

def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

def truncate_string(text: str, max_length: int = 100) -> str:
    """Truncate string to maximum length"""
    if len(text) <= max_length:
        return text
    
    return text[:max_length - 3] + "..."
