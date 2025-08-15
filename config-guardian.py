# configshield.py
import sys
import os # Added for path.splitext
import json # Added for JSON parsing
import click
import yaml
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from typing import Any, Dict, List, Optional, Tuple, Union
import re
from lxml import etree
import plistlib

# Import for Terraform HCL parsing
try:
    import hcl2
    HCL2_AVAILABLE = True
except ImportError:
    HCL2_AVAILABLE = False
    print("[WARNING] python-hcl2 not found. Terraform (.tf) scanning will be disabled.", file=sys.stderr)


# --- Updated SUPPORTED_FILES and Detection Logic ---

# Function to determine rule file based on path and content if needed
def get_rule_file_for_path(filepath: Path) -> Optional[str]:
    """Determine the appropriate rule file based on the file path and potentially content."""
    filename = filepath.name.lower()
    extension = filepath.suffix.lower()

    # Direct mappings based on name/extension
    direct_map = {
        "server.xml": "tomcat.yaml",
        "androidmanifest.xml": "android.yaml",
        "web.xml": "web.xml.yaml",
        "nginx.conf": "nginx.conf.yaml",
        "httpd.conf": "httpd.conf.yaml",
        "docker-compose.yml": "docker-compose.yaml",
        "info.plist": "info.plist.yaml",
        ".terraform.lock.hcl": None, # Ignore lock files
    }
    if filename in direct_map:
        return direct_map[filename]

    # Terraform
    if extension in ['.tf', '.tfvars']:
        if not HCL2_AVAILABLE:
            print(f"[WARNING] Skipping {filepath} - python-hcl2 not available.", file=sys.stderr)
            return None
        return "terraform.yaml"

    # YAML files - need content inspection for K8s, CloudFormation
    if extension in ['.yaml', '.yml']:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                # Read enough to identify the type
                content_preview = f.read(2048) # Read first 2KB
                f.seek(0) # Reset for full load if needed
                if '"AWSTemplateFormatVersion"' in content_preview or 'AWSTemplateFormatVersion:' in content_preview:
                    return "cloudformation.yaml"
                elif 'apiVersion:' in content_preview and 'kind:' in content_preview:
                     return "kubernetes.yaml"
                # Add more YAML type detections here if needed
                else:
                    # Generic YAML - could be docker-compose, nginx if named differently, etc.
                    # For now, if not a known specific type, we might skip or use a generic rule set.
                    # Let's assume if it's not caught above and not docker-compose.yml, it's not targeted yet.
                    # We could add a generic-yaml.yaml later if needed.
                    pass
        except Exception as e:
            click.secho(f"[!] Could not read {filepath} for type detection: {e}", fg='yellow')
        # Fallback if not detected by content
        return None # Or a generic YAML rule file if created

    # JSON files - need content inspection for CloudFormation, ARM
    if extension == '.json':
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                # Read enough to identify the type
                content_preview = f.read(2048)
                if '"AWSTemplateFormatVersion"' in content_preview:
                    return "cloudformation.yaml" # Using same rules for now, can split later
                elif '"$schema"' in content_preview and 'deploymentTemplate' in content_preview:
                    return "arm.yaml"
                # Add more JSON type detections here if needed
                else:
                    # Generic JSON
                    pass
        except Exception as e:
             click.secho(f"[!] Could not read {filepath} for type detection: {e}", fg='yellow')
        # Fallback if not detected by content
        return None # Or a generic JSON rule file if created

    # If no specific type matched
    return None


# --- Updated Parsing Logic ---

def load_hcl(filepath: Path) -> dict:
    """Load and parse a Terraform HCL file."""
    if not HCL2_AVAILABLE:
        raise ImportError("python-hcl2 is not installed.")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            dict_result = hcl2.load(f)
            # hcl2.load returns a dict, but structure can be complex.
            # e.g., {'resource': [{'aws_s3_bucket': {'my_bucket': {...}}}, ...]}
            return dict_result if dict_result else {}
    except Exception as e:
        click.secho(f"[!] Failed to parse HCL {filepath.name}: {e}", fg='red', err=True)
        raise


# --- Updated get_nested_value to be more robust ---

def get_nested_value(data: Union[Dict, List], key_path: str) -> List[Any]:
    """
    Traverse nested dict/list using dot notation with wildcard (*).
    Returns list of matching values.
    """
    if data is None:
        return []
    keys = key_path.split('.')
    results = [data]
    for k in keys:
        next_results = []
        for item in results:
            if isinstance(item, dict):
                if k == '*':
                    next_results.extend(item.values())
                elif k in item:
                    next_results.append(item[k])
            elif isinstance(item, list) and k == '*':
                next_results.extend(item)
            elif isinstance(item, list):
                # Try to interpret k as an index
                try:
                    idx = int(k)
                    if 0 <= idx < len(item):
                        next_results.append(item[idx])
                except ValueError:
                    # k is not an integer, maybe a key within list items (dicts)
                    # This is a simplification, assumes list items are dicts if key is not '*'
                    for list_item in item:
                        if isinstance(list_item, dict) and k in list_item:
                            next_results.append(list_item[k])
            # Add handling for other types if necessary
        results = next_results
    return results

# --- Updated evaluate_rule Logic ---

# (The main evaluate_rule function will be updated below to handle new types)

# --- Main CLI and Core Logic ---

@click.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.option('--format', 'output_format', type=click.Choice(['text', 'html']), default='text')
@click.option('--output', '-o', type=click.Path())
def scan(filepath: str, output_format: str, output: Optional[str]):
    """Scan configuration file for security misconfigurations."""
    filepath = Path(filepath)
    # filename = filepath.name # No longer used directly for rule mapping

    # --- Updated Rule File Detection ---
    rule_file = get_rule_file_for_path(filepath)
    if not rule_file:
        click.secho(f"[!] Unsupported or undetected file type for: {filepath.name}", fg='red', err=True)
        # click.secho(f"Supported: {', '.join(SUPPORTED_FILES.keys())}", dim=True) # No longer a simple list
        sys.exit(1)

    rules_path = Path(__file__).parent / "rules" / rule_file

    if not rules_path.exists():
        click.secho(f"[!] Rule file not found: {rules_path}", fg='red', err=True)
        sys.exit(1)

    # Load rules
    try:
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules_data = yaml.safe_load(f)
            if not rules_data or not isinstance(rules_data, dict) or "rules" not in rules_data:
                 click.secho(f"[!] Invalid rule file: {rules_path}", fg='red', err=True)
                 sys.exit(1)
    except Exception as e:
        click.secho(f"[!] Failed to load rules {rules_path.name}: {e}", fg='red', err=True)
        sys.exit(1)

    # --- Updated Parsing Logic ---
    config_data = None # For YAML, JSON, HCL, PList
    xml_doc = None    # For XML
    file_content = None # For text/plain regex checks
    file_type_category = None # To help evaluation logic

    try:
        # Determine parsing method by rule file type or extension/content
        if rule_file in ["tomcat.yaml", "android.yaml", "web.xml.yaml"]:
            file_type_category = "xml"
            with open(filepath, 'rb') as f:
                content_bytes = f.read()
            content_str = content_bytes.decode('utf-8')
            parser = etree.XMLParser(ns_clean=True, recover=True)
            xml_doc = etree.fromstring(content_str.encode(), parser)

        elif rule_file in ["nginx.conf.yaml", "httpd.conf.yaml"]:
             file_type_category = "text"
             with open(filepath, 'r', encoding='utf-8') as f:
                 file_content = f.read()

        elif rule_file == "docker-compose.yaml":
             file_type_category = "yaml"
             with open(filepath, 'r', encoding='utf-8') as f:
                 content_str = f.read()
                 config_data = yaml.safe_load(content_str) if content_str.strip() else {}

        elif rule_file == "info.plist.yaml":
             file_type_category = "plist"
             with open(filepath, 'rb') as f:
                 content_bytes = f.read()
                 config_data = plistlib.loads(content_bytes)

        elif rule_file == "terraform.yaml":
             file_type_category = "hcl"
             config_data = load_hcl(filepath) # This uses hcl2

        elif rule_file in ["kubernetes.yaml", "cloudformation.yaml"]:
             file_type_category = "yaml"
             with open(filepath, 'r', encoding='utf-8') as f:
                 content_str = f.read()
                 config_data = yaml.safe_load(content_str) if content_str.strip() else {}

        elif rule_file == "arm.yaml":
             file_type_category = "json"
             with open(filepath, 'r', encoding='utf-8') as f:
                 content_str = f.read()
                 config_data = json.loads(content_str) if content_str.strip() else {}

        # Add more elif blocks for other new types as needed

        else:
            # Fallback or error if rule_file not handled
            click.secho(f"[!] Internal error: No parser defined for rule file {rule_file}", fg='red', err=True)
            sys.exit(1)

    except Exception as e:
        click.secho(f"[!] Failed to parse {filepath.name}: {e}", fg='red', err=True)
        sys.exit(1)

    # --- Evaluate rules ---
    findings = []
    for rule in rules_data["rules"]:
        result = evaluate_rule(rule, xml_doc, config_data, file_content, filepath.name, file_type_category)
        if result:
            findings.append(result)

    # --- Generate output ---
    if output_format == "text":
        print_text_report(findings, filepath.name)
    elif output_format == "html":
        html = generate_html_report(findings, filepath.name)
        output = output or f"report_{filepath.name.replace('.', '_')}.html"
        try:
            with open(output, 'w', encoding='utf-8') as f:
                f.write(html)
            click.secho(f"[+] HTML report saved to: {Path(output).resolve()}", fg='green')
        except Exception as e:
            click.secho(f"[!] Failed to write report: {e}", fg='red', err=True)
            sys.exit(1)


def evaluate_rule(rule: dict, xml_doc, config_data, file_content: Optional[str], filename: str, file_type_category: str) -> Optional[dict]:
    rule_type = rule.get("type", "key") # Default to key for structured data
    severity = rule.get("severity", "Medium")

    try:
        # --- XML files (unchanged logic) ---
        if xml_doc is not None and file_type_category == "xml":
            xpath = rule.get("xpath")
            if not xpath:
                return None

            # Handle namespaces
            namespaces = {}
            if "AndroidManifest.xml" in filename:
                namespaces['android'] = 'http://schemas.android.com/apk/res/android'
            elif "web.xml" in filename:
                namespaces['ns'] = 'http://xmlns.jcp.org/xml/ns/javaee'

            try:
                matches = xml_doc.xpath(xpath, namespaces=namespaces)
            except Exception as e:
                click.secho(f"[!] XPath error: {e}", fg='yellow')
                return None

            if not matches:
                return None

            # Value check
            if 'value' in rule:
                for m in matches:
                    if str(m) == str(rule['value']):
                        return make_finding(rule, location=xpath)

            # Existence check
            if rule.get("condition") == "exists":
                return make_finding(rule, location=xpath)

        # --- Structured Data Files (YAML, JSON, HCL, PList) ---
        elif config_data is not None and file_type_category in ["yaml", "json", "hcl", "plist"]:
             # Use 'key' type for path-based lookups
             if rule_type == "key":
                key_path = rule.get("key")
                expected_value = rule.get("value")
                condition = rule.get("condition")

                if not key_path:
                    return None

                values = get_nested_value(config_data, key_path)
                if not values:
                    # If condition is 'not(exists)', this is a match
                    if condition == "not(exists)":
                         return make_finding(rule, location=f"key: {key_path} (not found)")
                    return None

                # If condition is 'not(exists)' and we found values, it's not a match
                if condition == "not(exists)":
                    return None

                # Value check
                if expected_value is not None:
                    for v in values:
                        # Handle different data types from YAML/JSON/HCL
                        if isinstance(v, str) and isinstance(expected_value, str):
                            if v.lower() == expected_value.lower():
                                return make_finding(rule, location=key_path)
                        elif v == expected_value: # Works for bools, numbers, etc.
                             return make_finding(rule, location=key_path)
                # Existence check (if value is not specified, just check if key/path exists)
                elif condition == "exists":
                     return make_finding(rule, location=key_path)

             # Potentially add other rule types specific to cloud configs later (e.g., 'check_attribute' for TF resources)

        # --- Text Files (Regex) ---
        elif file_content and file_type_category == "text":
            # This logic remains largely the same
            if rule_type == "regex":
                pattern = rule.get("regex")
                expected_value = rule.get("value")
                condition = rule.get("condition")

                if not pattern:
                    return None

                flags = re.MULTILINE | re.IGNORECASE
                matches = re.findall(pattern, file_content, flags)

                if matches:
                    if expected_value:
                        # This part might need refinement depending on exact rule structure
                        value_matches = re.findall(f"{pattern}.*({re.escape(expected_value)})", file_content, flags)
                        if value_matches:
                            return make_finding(rule, location=f"regex: {pattern}")
                    elif condition == "exists" or expected_value is None: # Default behavior for regex rules
                        return make_finding(rule, location=f"regex: {pattern}")
                    elif condition == "not(exists)":
                         # If we found matches but condition is not(exists), it's not a finding
                         pass

                # If no matches found and condition is 'not(exists)', it's a finding
                elif condition == "not(exists)":
                     return make_finding(rule, location=f"regex: {pattern} (not found)")


    except Exception as e:
        click.secho(f"[!] Rule eval error {rule.get('id', 'unknown')}: {e}", fg='yellow')
    return None


def make_finding(rule: dict, location: str = None) -> dict:
    return {
        "id": rule["id"],
        "name": rule["name"],
        "description": rule["description"],
        "severity": rule["severity"],
        "remediation": rule["remediation"],
        "reference": rule["reference"],
        "location": location or "Unknown"
    }


def print_text_report(findings: List[dict], filename: str):
    click.secho(f"\n🔐 ConfigShield Scan Report - {filename}\n", bold=True, fg='bright_blue')
    if not findings:
        click.secho("✅ No security issues found.", fg='green')
        return

    summary = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        summary[f['severity']] += 1

    for level in ["High", "Medium", "Low", "Info"]:
        if summary[level] > 0:
            color = {"High": "red", "Medium": "yellow", "Low": "blue", "Info": "white"}[level]
            click.secho(f"{level}: {summary[level]} finding(s)", fg=color)

    click.echo("")
    for f in findings:
        color = {"High": "red", "Medium": "yellow", "Low": "bright_black", "Info": "white"}[f['severity']]
        click.secho(f"🔴 [{f['id']}] {f['name']} ({f['severity']})", fg=color, bold=(f['severity'] == "High"))
        click.echo(f"   {f['description']}")
        click.echo(f"   📍 Location: {f['location']}")
        click.echo(f"   🛠️  Fix: {f['remediation']}")
        click.echo(f"   🔗 {f['reference']}\n")


def generate_html_report(findings: List[dict], filename: str) -> str:
    templates_dir = Path(__file__).parent / "templates"
    if not templates_dir.exists():
        click.secho(f"[!] Templates directory not found: {templates_dir}", fg='red', err=True)
        sys.exit(1)

    try:
        env = Environment(loader=FileSystemLoader(str(templates_dir), encoding='utf-8'))
        template = env.get_template("report.html.j2")
    except Exception as e:
        click.secho(f"[!] Template error: {e}", fg='red', err=True)
        sys.exit(1)

    summary = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f['severity'].lower()
        if sev in summary:
            summary[sev] += 1

    return template.render(findings=findings, filename=filename, summary=summary)


if __name__ == "__main__":
    scan()
