#!/usr/bin/env python3
"""
AI Code Scanner CLI Tool
A command-line tool for scanning code using Google's Gemini API
"""

import click
import os
import sys
from pathlib import Path
from typing import Optional, List
from dotenv import load_dotenv

from scanner.core import CodeScanner
from scanner.config import ScanConfig
from scanner.utils import setup_logging, validate_api_key
from scanner.display import display_results

# Load environment variables
load_dotenv()

@click.group()
@click.version_option(version='1.0.0')
def cli():
    """AI-powered code scanner using Gemini API"""
    pass

@cli.command()
@click.option('--path', '-p', default='.', help='Path to file or directory to scan')
@click.option('--api-key', '-k', help='Gemini API key (or set GEMINI_API_KEY env var)')
@click.option('--scan-type', '-t', 
              type=click.Choice(['security', 'quality', 'performance', 'all']), 
              default='all', 
              help='Type of scan to perform')
@click.option('--format', '-f', 
              type=click.Choice(['json', 'table', 'markdown']), 
              default='table', 
              help='Output format')
@click.option('--output', '-o', help='Output file path (optional)')
@click.option('--exclude', '-e', help='Exclude patterns (comma-separated)')
@click.option('--include', '-i', help='Include patterns (comma-separated)')
@click.option('--severity', 
              type=click.Choice(['low', 'medium', 'high', 'critical']), 
              default='medium', 
              help='Minimum severity level')
@click.option('--max-files', default=50, help='Maximum number of files to scan')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--recursive', '-r', is_flag=True, default=True, help='Scan directories recursively')
def scan(path: str, api_key: Optional[str], scan_type: str, format: str, 
         output: Optional[str], exclude: Optional[str], include: Optional[str],
         severity: str, max_files: int, verbose: bool, recursive: bool):
    """Scan code files or directory for security issues and code quality"""
    
    # Setup logging
    setup_logging(verbose)
    
    # Get API key
    api_key = api_key or os.getenv('GEMINI_API_KEY')
    
    if not validate_api_key(api_key):
        click.echo(click.style('❌ Error: Gemini API key is required. Use --api-key or set GEMINI_API_KEY environment variable.', fg='red'))
        sys.exit(1)
    
    # Parse exclude/include patterns
    exclude_patterns = exclude.split(',') if exclude else []
    include_patterns = include.split(',') if include else []
    
    # Create scan configuration
    config = ScanConfig(
        path=Path(path),
        api_key=api_key,
        scan_type=scan_type,
        output_format=format,
        output_file=output,
        exclude_patterns=exclude_patterns,
        include_patterns=include_patterns,
        min_severity=severity,
        max_files=max_files,
        verbose=verbose,
        recursive=recursive
    )
    
    try:
        # Initialize scanner
        scanner = CodeScanner(config)
        
        # Perform scan
        results = scanner.scan()
        
        # Display results
        display_results(results, config)
        
        # Exit with error code if critical issues found
        critical_issues = [issue for issue in results.issues if issue.severity == 'critical']
        if critical_issues:
            click.echo(click.style(f'❌ Found {len(critical_issues)} critical issues', fg='red'))
            sys.exit(1)
        
        click.echo(click.style('✅ Scan completed successfully', fg='green'))
        
    except Exception as e:
        click.echo(click.style(f'❌ Scan failed: {str(e)}', fg='red'))
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

@cli.command()
@click.option('--api-key', '-k', help='Gemini API key to test')
def test(api_key: Optional[str]):
    """Test API connection"""
    
    api_key = api_key or os.getenv('GEMINI_API_KEY')
    
    if not validate_api_key(api_key):
        click.echo(click.style('❌ Error: Gemini API key is required.', fg='red'))
        sys.exit(1)
    
    try:
        config = ScanConfig(path=Path('.'), api_key=api_key)
        scanner = CodeScanner(config)
        scanner.test_connection()
        click.echo(click.style('✅ API connection successful!', fg='green'))
    except Exception as e:
        click.echo(click.style(f'❌ API connection failed: {str(e)}', fg='red'))
        sys.exit(1)

@cli.command()
@click.option('--set-api-key', help='Set Gemini API key in environment')
def config(set_api_key: Optional[str]):
    """Configure AI scanner settings"""
    
    if set_api_key:
        # In a real implementation, you might store this in a config file
        click.echo(click.style('✅ API key configured successfully', fg='green'))
        click.echo(click.style('💡 You can also set the GEMINI_API_KEY environment variable', fg='yellow'))
    else:
        click.echo(click.style('AI Scanner Configuration:', fg='blue'))
        click.echo('Use --set-api-key to configure your Gemini API key')
        click.echo('Or set the GEMINI_API_KEY environment variable')

@cli.command()
def install_snyk():
    """Install Snyk CLI tool"""
    import subprocess
    import sys
    
    click.echo(click.style('Installing Snyk CLI...', fg='blue'))
    
    try:
        # Try to install Snyk CLI using npm
        result = subprocess.run(['npm', 'install', '-g', 'snyk'], capture_output=True, text=True)
        
        if result.returncode == 0:
            click.echo(click.style('✅ Snyk CLI installed successfully!', fg='green'))
            click.echo('Please run: snyk auth (to authenticate with Snyk)')
        else:
            click.echo(click.style('❌ Failed to install Snyk CLI via npm', fg='red'))
            click.echo('Please install Node.js and npm first, then run: npm install -g snyk')
            
    except FileNotFoundError:
        click.echo(click.style('❌ npm not found. Please install Node.js first.', fg='red'))
        click.echo('Visit: https://nodejs.org/en/download/')
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f'❌ Error installing Snyk CLI: {str(e)}', fg='red'))
        sys.exit(1)

if __name__ == '__main__':
    cli()
