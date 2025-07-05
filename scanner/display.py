"""
Display and output formatting utilities
"""

import json
import csv
from pathlib import Path
from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from tabulate import tabulate

from .config import ScanResults, ScanConfig, ScanIssue

console = Console()

def display_results(results: ScanResults, config: ScanConfig):
    """Display scan results in the specified format"""
    
    if config.output_format == 'json':
        _display_json(results, config)
    elif config.output_format == 'markdown':
        _display_markdown(results, config)
    else:  # table format
        _display_table(results, config)

def _display_table(results: ScanResults, config: ScanConfig):
    """Display results in table format using Rich"""
    
    # Display summary
    _display_summary(results)
    
    if not results.issues:
        console.print(Panel("[green]🎉 No security vulnerabilities detected![/green]\n\n✅ Your code appears to be secure based on our analysis.", title="🛡️ Security Analysis Complete", border_style="green"))
        return
    
    # Create issues table
    table = Table(title="🔒 Security Analysis Results")
    table.add_column("File", style="cyan", no_wrap=True)
    table.add_column("Line", justify="right", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("OWASP Category", style="blue")
    table.add_column("Vulnerability", style="yellow")
    table.add_column("Recommendation", style="white")
    
    for issue in results.issues:
        # Color severity
        severity_color = _get_severity_color(issue.severity)
        severity_text = Text(issue.severity.upper(), style=severity_color)
        
        # Truncate long recommendations
        recommendation = issue.recommendation
        if len(recommendation) > 60:
            recommendation = recommendation[:57] + "..."
        
        # Format OWASP category
        owasp_display = issue.owasp_category if issue.owasp_category != "Unknown" else "N/A"
        if len(owasp_display) > 25:
            owasp_display = owasp_display[:22] + "..."
        
        table.add_row(
            Path(issue.file_path).name,
            str(issue.line_number),
            severity_text,
            owasp_display,
            issue.title,
            recommendation
        )
    
    console.print(table)
    
    # Display detailed issues with code snippets
    if config.verbose:
        console.print("\n" + "="*80)
        console.print("[bold]🔍 Detailed Vulnerability Analysis[/bold]")
        console.print("="*80)
        
        for i, issue in enumerate(results.issues, 1):
            _display_detailed_issue(issue, i)
    
    # Save to file if specified
    if config.output_file:
        _save_to_file(results, config)

def _display_detailed_issue(issue: ScanIssue, index: int):
    """Display detailed issue with code snippet"""
    
    severity_color = _get_severity_color(issue.severity)
    
    # Issue header with emoji
    severity_emoji = {
        'critical': '🚨',
        'high': '🔴',
        'medium': '🟡',
        'low': '🟢'
    }.get(issue.severity.lower(), '⚪')
    
    console.print(f"\n[bold cyan]{severity_emoji} Vulnerability #{index}[/bold cyan]")
    console.print(f"[bold]🎯 Issue:[/bold] {issue.title}")
    console.print(f"[bold]📁 File:[/bold] {Path(issue.file_path).name}")
    console.print(f"[bold]📍 Line:[/bold] {issue.line_number}")
    console.print(f"[bold]⚠️  Severity:[/bold] [{severity_color}]{issue.severity.upper()}[/{severity_color}]")
    console.print(f"[bold]🏷️  Type:[/bold] {issue.issue_type}")
    
    # Display OWASP category with proper formatting
    owasp_display = issue.owasp_category if issue.owasp_category and issue.owasp_category != "Unknown" else "Not Categorized"
    console.print(f"[bold]🛡️  OWASP Category:[/bold] {owasp_display}")
    console.print(f"[bold]🎯 Confidence:[/bold] {issue.confidence:.0%}")
    
    # Description
    console.print(f"\n[bold]📋 Technical Details:[/bold]")
    console.print(issue.description)
    
    # Code snippet
    if issue.code_snippet and issue.code_snippet.strip():
        console.print(f"\n[bold]💻 Vulnerable Code:[/bold]")
        console.print(Panel(issue.code_snippet, title=f"📁 {Path(issue.file_path).name} (Line {issue.line_number})", border_style="red"))
    
    # Remediation
    console.print(f"\n[bold]🔧 Recommended Fix:[/bold]")
    console.print(issue.recommendation)
    
    console.print("─" * 80)

def _display_json(results: ScanResults, config: ScanConfig):
    """Display results in JSON format"""
    
    # Convert results to JSON-serializable format
    data = {
        "analysis_metadata": {
            "target_path": str(results.scan_config.path),
            "scan_type": results.scan_config.scan_type,
            "minimum_severity": results.scan_config.min_severity,
            "files_analyzed": results.files_scanned,
            "analysis_duration_seconds": round(results.scan_duration, 2),
            "report_generated": results.timestamp
        },
        "summary": {
            "total_vulnerabilities": results.summary['total_issues'],
            "affected_files": results.summary['files_with_issues'],
            "severity_distribution": results.summary['by_severity'],
            "owasp_categories": results.summary.get('by_owasp', {})
        },
        "vulnerabilities": [
            {
                "file_name": Path(issue.file_path).name,
                "file_path": issue.file_path,
                "line_number": issue.line_number,
                "severity": issue.severity,
                "vulnerability_type": issue.issue_type,
                "vulnerability_title": issue.title,
                "technical_description": issue.description,
                "recommended_fix": issue.recommendation,
                "confidence_score": round(issue.confidence, 2),
                "owasp_category": issue.owasp_category if issue.owasp_category != "Unknown" else "Not Categorized",
                "code_snippet": issue.code_snippet
            }
            for issue in results.issues
        ]
    }
    
    json_str = json.dumps(data, indent=2)
    
    if config.output_file:
        with open(config.output_file, 'w') as f:
            f.write(json_str)
        console.print(f"[green]Results saved to {config.output_file}[/green]")
    else:
        console.print(json_str)

def _display_markdown(results: ScanResults, config: ScanConfig):
    """Display results in Markdown format"""
    
    md_content = f"""# 🔒 Security Analysis Report

## 📊 Executive Summary
- **Files Analyzed**: {results.files_scanned}
- **Vulnerabilities Identified**: {results.summary['total_issues']}
- **Affected Files**: {results.summary['files_with_issues']}
- **Analysis Duration**: {results.scan_duration:.1f} seconds
- **Report Generated**: {results.timestamp}

## ⚠️ Severity Distribution
"""
    
    # Sort severity by priority
    severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    for severity, count in sorted(results.summary['by_severity'].items(), 
                                 key=lambda x: severity_order.get(x[0], 0), reverse=True):
        severity_emoji = {'critical': '🚨', 'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(severity, '⚪')
        md_content += f"- {severity_emoji} **{severity.title()}**: {count}\n"
    
    # Add OWASP breakdown if available
    if 'by_owasp' in results.summary and results.summary['by_owasp']:
        owasp_items = [(k, v) for k, v in results.summary['by_owasp'].items() if k != "Unknown" and k != "N/A"]
        if owasp_items:
            md_content += "\n## 🛡️ OWASP Top 10 Categories\n"
            for owasp, count in sorted(owasp_items, key=lambda x: x[1], reverse=True):
                md_content += f"- **{owasp}**: {count} issue(s)\n"
    
    if results.issues:
        md_content += "\n## 🔍 Detailed Findings\n\n"
        
        for i, issue in enumerate(results.issues, 1):
            severity_emoji = {'critical': '🚨', 'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(issue.severity.lower(), '⚪')
            owasp_text = issue.owasp_category if issue.owasp_category and issue.owasp_category != "Unknown" else "Not Categorized"
            
            md_content += f"""### {severity_emoji} {i}. {issue.title}

**📍 Location**: `{Path(issue.file_path).name}` (Line {issue.line_number})  
**⚠️ Severity**: **{issue.severity.upper()}**  
**🏷️ Type**: {issue.issue_type}  
**🛡️ OWASP Category**: {owasp_text}  
**🎯 Confidence**: {issue.confidence:.0%}

**📋 Technical Details**:  
{issue.description}

**🔧 Recommended Fix**:  
{issue.recommendation}

"""
            if issue.code_snippet and issue.code_snippet.strip():
                md_content += f"""**💻 Vulnerable Code**:
```
{issue.code_snippet}
```

"""
            md_content += "---\n\n"
    else:
        md_content += "\n## 🎉 No Security Issues Found!\n\n✅ Your code appears to be secure based on our analysis.\n"
    
    if config.output_file:
        with open(config.output_file, 'w') as f:
            f.write(md_content)
        console.print(f"[green]Results saved to {config.output_file}[/green]")
    else:
        console.print(md_content)

def _display_summary(results: ScanResults):
    """Display scan summary"""
    
    # Calculate severity emoji and stats
    severity_emojis = {
        'critical': '🚨',
        'high': '🔴',
        'medium': '🟡',
        'low': '🟢'
    }
    
    summary_text = f"""🛡️ **Security Analysis Summary**
• Files Analyzed: {results.files_scanned}
• Vulnerabilities Found: {results.summary['total_issues']}
• Affected Files: {results.summary['files_with_issues']}
• Analysis Duration: {results.scan_duration:.1f}s
    """
    
    # Add severity breakdown with emojis
    if results.summary['by_severity']:
        summary_text += "\n\n⚠️  **Severity Breakdown**\n"
        for severity, count in sorted(results.summary['by_severity'].items(), 
                                     key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x[0], 0), 
                                     reverse=True):
            emoji = severity_emojis.get(severity, '⚪')
            summary_text += f"• {emoji} {severity.title()}: {count}\n"
    
    # Add OWASP breakdown if available
    if 'by_owasp' in results.summary and results.summary['by_owasp']:
        owasp_items = [(k, v) for k, v in results.summary['by_owasp'].items() if k != "Unknown" and k != "N/A"]
        if owasp_items:
            summary_text += "\n\n🛡️  **OWASP Top 10 Categories**\n"
            for owasp, count in sorted(owasp_items, key=lambda x: x[1], reverse=True)[:5]:  # Top 5
                # Shorten OWASP category names for display
                owasp_short = owasp.replace("A0", "A").replace(":2021", "").replace(" - ", ": ")
                if len(owasp_short) > 35:
                    owasp_short = owasp_short[:32] + "..."
                summary_text += f"• {owasp_short}: {count}\n"
    
    console.print(Panel(summary_text, title="🔒 AI Security Scanner Results", border_style="blue"))

def _get_severity_color(severity: str) -> str:
    """Get color for severity level"""
    colors = {
        'critical': 'red',
        'high': 'red',
        'medium': 'yellow',
        'low': 'green'
    }
    return colors.get(severity.lower(), 'white')

def _save_to_file(results: ScanResults, config: ScanConfig):
    """Save results to file"""
    try:
        if config.output_format == 'json':
            # Already handled in _display_json
            pass
        elif config.output_format == 'markdown':
            # Already handled in _display_markdown
            pass
        else:  # table format - save as CSV
            if config.output_file:
                headers = ['File', 'Line', 'Severity', 'Vulnerability_Type', 'OWASP_Category', 'Vulnerability_Title', 'Technical_Details', 'Recommended_Fix', 'Confidence_Score', 'Code_Snippet']
                rows = []
                
                for issue in results.issues:
                    rows.append([
                        Path(issue.file_path).name,
                        issue.line_number,
                        issue.severity.upper(),
                        issue.issue_type,
                        issue.owasp_category if issue.owasp_category != "Unknown" else "Not Categorized",
                        issue.title,
                        issue.description,
                        issue.recommendation,
                        f"{issue.confidence:.0%}",
                        issue.code_snippet.replace('\n', ' | ') if issue.code_snippet else 'N/A'
                    ])
                
                with open(config.output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)
                    writer.writerows(rows)
                
                console.print(f"[green]Results saved to {config.output_file}[/green]")
    
    except Exception as e:
        console.print(f"[red]Error saving to file: {str(e)}[/red]")
