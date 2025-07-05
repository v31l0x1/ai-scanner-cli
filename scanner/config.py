"""
Configuration classes for the AI code scanner
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any
from enum import Enum

class ScanType(Enum):
    SECURITY = "security"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    ALL = "all"

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class OutputFormat(Enum):
    JSON = "json"
    TABLE = "table"
    MARKDOWN = "markdown"

@dataclass
class ScanConfig:
    """Configuration for code scanning"""
    path: Path
    api_key: str
    scan_type: str = "all"
    output_format: str = "table"
    output_file: Optional[str] = None
    exclude_patterns: List[str] = None
    include_patterns: List[str] = None
    min_severity: str = "medium"
    max_files: int = 50
    verbose: bool = False
    recursive: bool = True
    
    def __post_init__(self):
        if self.exclude_patterns is None:
            self.exclude_patterns = []
        if self.include_patterns is None:
            self.include_patterns = []
        
        # Default exclude patterns for common files that shouldn't be scanned
        default_excludes = [
            '*.git*',
            '*.pyc',
            '__pycache__',
            'node_modules',
            '*.log',
            '*.tmp',
            '*.temp',
            '.env',
            '.venv',
            'venv',
            'dist',
            'build',
            '*.min.js',
            '*.min.css'
        ]
        
        self.exclude_patterns.extend(default_excludes)
        
        # Default include patterns for source code files
        if not self.include_patterns:
            self.include_patterns = [
                '*.py',
                '*.js',
                '*.ts',
                '*.jsx',
                '*.tsx',
                '*.java',
                '*.c',
                '*.cpp',
                '*.h',
                '*.hpp',
                '*.cs',
                '*.php',
                '*.rb',
                '*.go',
                '*.rs',
                '*.swift',
                '*.kt',
                '*.scala',
                '*.sh',
                '*.bash',
                '*.ps1',
                '*.sql',
                '*.yaml',
                '*.yml',
                '*.json',
                '*.xml',
                '*.html',
                '*.css',
                '*.scss',
                '*.less'
            ]

@dataclass
class ScanIssue:
    """Represents a single scan issue"""
    file_path: str
    line_number: int
    severity: str
    issue_type: str
    title: str
    description: str
    recommendation: str
    confidence: float
    owasp_category: str = "Unknown"
    code_snippet: str = ""
    
@dataclass
class ScanResults:
    """Results of a code scan"""
    scan_config: ScanConfig
    files_scanned: int
    issues: List[ScanIssue]
    scan_duration: float
    timestamp: str
    summary: Dict[str, Any]
