"""
File scanning and discovery functionality
"""

import os
from pathlib import Path
from typing import List
import pathspec

from .config import ScanConfig

class FileScanner:
    """Handles file discovery and filtering"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.exclude_spec = pathspec.PathSpec.from_lines('gitwildmatch', config.exclude_patterns)
        self.include_spec = pathspec.PathSpec.from_lines('gitwildmatch', config.include_patterns)
    
    def get_files_to_scan(self) -> List[Path]:
        """Get list of files to scan based on configuration"""
        files = []
        
        if self.config.path.is_file():
            # Single file
            if self._should_include_file(self.config.path):
                files.append(self.config.path)
        else:
            # Directory
            files = self._scan_directory(self.config.path)
        
        # Limit number of files
        if len(files) > self.config.max_files:
            files = files[:self.config.max_files]
        
        return files
    
    def _scan_directory(self, directory: Path) -> List[Path]:
        """Recursively scan directory for files"""
        files = []
        
        try:
            if self.config.recursive:
                # Recursive scan
                for root, dirs, filenames in os.walk(directory):
                    root_path = Path(root)
                    
                    # Filter directories
                    dirs[:] = [d for d in dirs if not self._should_exclude_dir(root_path / d)]
                    
                    for filename in filenames:
                        file_path = root_path / filename
                        if self._should_include_file(file_path):
                            files.append(file_path)
            else:
                # Non-recursive scan
                for file_path in directory.iterdir():
                    if file_path.is_file() and self._should_include_file(file_path):
                        files.append(file_path)
        
        except PermissionError:
            # Skip directories we can't read
            pass
        
        return files
    
    def _should_include_file(self, file_path: Path) -> bool:
        """Check if file should be included in scan"""
        # Convert to relative path for pattern matching
        try:
            relative_path = file_path.relative_to(self.config.path.parent)
        except ValueError:
            relative_path = file_path
        
        relative_str = str(relative_path).replace('\\', '/')
        
        # Check exclude patterns
        if self.exclude_spec.match_file(relative_str):
            return False
        
        # Check include patterns
        if self.include_spec.match_file(relative_str):
            return True
        
        # Check file extension
        return self._is_source_code_file(file_path)
    
    def _should_exclude_dir(self, dir_path: Path) -> bool:
        """Check if directory should be excluded"""
        try:
            relative_path = dir_path.relative_to(self.config.path.parent)
        except ValueError:
            relative_path = dir_path
        
        relative_str = str(relative_path).replace('\\', '/')
        return self.exclude_spec.match_file(relative_str)
    
    def _is_source_code_file(self, file_path: Path) -> bool:
        """Check if file is a source code file"""
        source_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.h', '.hpp',
            '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala', '.sh',
            '.bash', '.ps1', '.sql', '.yaml', '.yml', '.json', '.xml', '.html',
            '.css', '.scss', '.less'
        }
        
        return file_path.suffix.lower() in source_extensions
