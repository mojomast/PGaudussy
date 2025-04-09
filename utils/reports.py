#!/usr/bin/env python3
"""
PostgreSQL Database Permissions Audit Tool - Report Generation

This module provides functionality for generating HTML reports using Jinja2.
"""

import os
import json
import logging
import shutil
from datetime import datetime
from typing import Dict, List, Any, Optional

from jinja2 import Environment, FileSystemLoader
from rich.console import Console

logger = logging.getLogger("dbaudit_reports")

class ReportGenerator:
    """Class for generating HTML reports using Jinja2"""
    
    def __init__(self, console: Optional[Console] = None):
        """Initialize the report generator"""
        self.console = console or Console()
        self.template_dir = os.path.join(os.getcwd(), "templates")
        self.output_dir = os.path.join(os.getcwd(), "reports")
        self.static_dir = os.path.join(os.getcwd(), "static")
        
        # Ensure all required directories exist
        self._ensure_directories_exist()
            
        # Initialize Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=True
        )
    
    def _ensure_directories_exist(self):
        """Ensure all required directories exist"""
        # Ensure output directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
            
        # Ensure static directory in reports exists
        reports_static_dir = os.path.join(self.output_dir, "static", "js")
        if not os.path.exists(reports_static_dir):
            os.makedirs(reports_static_dir, exist_ok=True)
            
        # Ensure static/js directory exists
        static_js_dir = os.path.join(self.static_dir, "js")
        if not os.path.exists(static_js_dir):
            os.makedirs(static_js_dir, exist_ok=True)
    
    def load_audit_data(self, audit_file: str) -> Dict[str, Any]:
        """Load audit data from a file"""
        try:
            with open(audit_file, 'r') as f:
                data = json.load(f)
            return data
        except Exception as e:
            logger.error(f"Error loading audit data: {e}")
            self.console.print(f"[red]Error loading audit data: {e}[/red]")
            return {}
    
    def prepare_report_data(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for the report template"""
        # Count findings by risk level
        high_count = 0
        medium_count = 0
        low_count = 0
        info_count = 0
        
        findings = []
        recommendations = []
        
        # Process dangerous permissions as findings
        for permission in audit_data.get("dangerous_permissions", []):
            risk_level = permission.get("risk_level", "").lower()
            
            if risk_level == "high":
                high_count += 1
            elif risk_level == "medium":
                medium_count += 1
            elif risk_level == "low":
                low_count += 1
            elif risk_level == "info":
                info_count += 1
                
            # Create a finding from the permission
            finding = {
                "risk_level": risk_level,
                "finding_name": f"{permission.get('privilege', '')} on {permission.get('type', '')}",
                "object_name": permission.get('name', ''),
                "description": permission.get('recommendation', '')
            }
            findings.append(finding)
            
            # Add recommendation if not already in the list
            recommendation_text = permission.get('recommendation', '')
            if recommendation_text and not any(r.get("title") == recommendation_text for r in recommendations):
                recommendations.append({
                    "title": recommendation_text,
                    "description": f"Risk Level: {risk_level.upper()}",
                    "example_code": f"REVOKE {permission.get('privilege', '')} ON {permission.get('name', '')} FROM {permission.get('grantee', 'PUBLIC')};"
                })
        
        # Also check for findings in the original format if present
        for finding in audit_data.get("findings", []):
            risk_level = finding.get("risk_level", "").lower()
            
            if risk_level == "high":
                high_count += 1
            elif risk_level == "medium":
                medium_count += 1
            elif risk_level == "low":
                low_count += 1
            elif risk_level == "info":
                info_count += 1
                
            findings.append({
                "risk_level": risk_level,
                "finding_name": finding.get("name", ""),
                "object_name": finding.get("object", ""),
                "description": finding.get("description", "")
            })
        
        # Get database name and service name
        database_name = audit_data.get("database", "")
        
        # Get audit date from timestamp if available
        audit_date = audit_data.get("date", "")
        if not audit_date and "timestamp" in audit_data:
            try:
                from datetime import datetime
                timestamp = audit_data.get("timestamp", "")
                audit_date = timestamp.split("T")[0] + " " + timestamp.split("T")[1].split(".")[0]
            except:
                audit_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Determine overall risk level based on highest risk finding
        overall_risk_level = "low"
        if high_count > 0:
            overall_risk_level = "high"
        elif medium_count > 0:
            overall_risk_level = "medium"
        
        # Prepare template data
        report_data = {
            "database_name": database_name,
            "service_name": audit_data.get("service", ""),
            "audit_date": audit_date,
            "risk_level": overall_risk_level,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "info_count": info_count,
            "findings": findings,
            "recommendations": recommendations
        }
        
        return report_data
    
    def generate_html_report(self, audit_file: str) -> Optional[str]:
        """Generate an HTML report from audit data"""
        try:
            # Load audit data
            audit_data = self.load_audit_data(audit_file)
            if not audit_data:
                return None
                
            # Prepare data for template
            report_data = self.prepare_report_data(audit_data)
            
            # Get template
            template_name = "audit_report_template.html"
            template_path = os.path.join(self.template_dir, template_name)
            
            if not os.path.exists(template_path):
                self.console.print(f"[red]Template file not found: {template_path}[/red]")
                return None
            
            # Load template
            template = self.env.get_template(template_name)
            
            # Generate report filename
            db_name = report_data.get("database_name", "database")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"audit_report_{db_name}_{timestamp}.html"
            report_path = os.path.join(self.output_dir, report_filename)
            
            # Copy static files to report directory
            reports_static_js_dir = os.path.join(self.output_dir, "static", "js")
            chart_js_src = os.path.join(self.static_dir, "js", "chart.min.js")
            chart_js_dest = os.path.join(reports_static_js_dir, "chart.min.js")
            
            # Copy Chart.js if it exists
            if os.path.exists(chart_js_src):
                shutil.copy2(chart_js_src, chart_js_dest)
                self.console.print(f"[green]Copied Chart.js to report directory[/green]")
            else:
                self.console.print(f"[yellow]Warning: Chart.js not found at {chart_js_src}[/yellow]")
            
            # Render template with data and save to file
            with open(report_path, 'w', encoding='utf-8') as f:
                # Update the template to use the correct path to Chart.js
                rendered_html = template.render(**report_data)
                # Fix the path to Chart.js in the rendered HTML
                rendered_html = rendered_html.replace('../static/js/chart.min.js', 'static/js/chart.min.js')
                f.write(rendered_html)
                
            self.console.print(f"[green]Report generated successfully: {report_path}[/green]")
            return report_path
                
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            self.console.print(f"[red]Error generating report: {e}[/red]")
            return None
    
    def open_report(self, report_path: str) -> bool:
        """Open the generated report in the default browser"""
        try:
            import webbrowser
            return webbrowser.open(f"file://{os.path.abspath(report_path)}")
        except Exception as e:
            logger.error(f"Error opening report: {e}")
            self.console.print(f"[red]Error opening report: {e}[/red]")
            return False
