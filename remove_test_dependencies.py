#!/usr/bin/env python3
"""
Script to download an SBOM in SPDX format and remove test/dev dependencies.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from dotenv import load_dotenv
import requests

# Load environment variables from .env file
load_dotenv()

# Configuration
API_URL = 'https://api.endorlabs.com/v1'

def get_env_values():
    """Get necessary values from environment variables."""
    api_key = os.getenv("API_KEY")
    api_secret = os.getenv("API_SECRET")
    initial_namespace = os.getenv("ENDOR_NAMESPACE")
    
    if not api_key or not api_secret or not initial_namespace:
        print("ERROR: API_KEY, API_SECRET, and ENDOR_NAMESPACE environment variables must be set.")
        print("Please set them in a .env file or directly in your environment.")
        sys.exit(1)
    
    return {
        "api_key": api_key,
        "api_secret": api_secret,
        "initial_namespace": initial_namespace
    }

def get_token(api_key, api_secret):
    """Get API token using API key and secret."""
    url = f"{API_URL}/auth/api-key"
    payload = {
        "key": api_key,
        "secret": api_secret
    }
    headers = {
        "Content-Type": "application/json",
        "Request-Timeout": "60"
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=600)
        response.raise_for_status()
        token = response.json().get('token')
        return token
    except requests.exceptions.RequestException as e:
        print(f"Failed to get token: {e}")
        sys.exit(1)

def get_project_details(token, project_uuid, initial_namespace):
    """
    Fetch project details and extract name and namespace.
    """
    url = f"{API_URL}/namespaces/{initial_namespace}/projects"
    headers = {
        "Authorization": f"Bearer {token}",
        "Request-Timeout": "600"
    }
    
    params = {
        "list_parameters.filter": f"uuid=={project_uuid}",
        "list_parameters.mask": "meta.name,tenant_meta.namespace",
        "list_parameters.traverse": "true"
    }
    
    print(f"Fetching project details for project {project_uuid}...")
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=600)
        response.raise_for_status()
        
        data = response.json()
        objects = data.get('list', {}).get('objects', [])
        
        if objects and len(objects) > 0:
            project_data = objects[0]
            project_name = project_data.get('meta', {}).get('name')
            namespace = project_data.get('tenant_meta', {}).get('namespace')
            
            if project_name and namespace:
                print(f"Project name: {project_name}, Namespace: {namespace}")
                return project_name, namespace
        
        print("Project details not found in response")
        return None, None
        
    except requests.exceptions.RequestException as e:
        print(f"Failed to get project details: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
        return None, None

def get_package_versions(namespace, token, project_uuid, branch=None):
    """Get all package versions for a project."""
    url = f"{API_URL}/namespaces/{namespace}/package-versions"
    headers = {
        "Authorization": f"Bearer {token}",
        "Request-Timeout": "600"
    }
    
    # Build filter based on context type
    if branch and branch.lower() != "main":
        # Use branch context if specified and not main
        context_filter = f"context.id=={branch} and spec.project_uuid=={project_uuid}"
        print(f"Using branch context: {branch}")
    else:
        # Default to main context
        context_filter = f"context.type==CONTEXT_TYPE_MAIN and spec.project_uuid=={project_uuid}"
        print("Using main context")
    
    params = {
        "list_parameters.filter": context_filter,
        "list_parameters.mask": "uuid,meta.name"
    }
    
    package_versions = []
    next_page_id = None
    
    print(f"Fetching packageVersions for project {project_uuid}...")
    
    while True:
        if next_page_id:
            params['list_parameters.page_id'] = next_page_id

        try:
            response = requests.get(url, headers=headers, params=params, timeout=600)
            response.raise_for_status()
            
            response_data = response.json()
            items = response_data.get('list', {}).get('objects', [])
            
            for item in items:
                package_version = {
                    'uuid': item.get('uuid'),
                    'name': item.get('meta', {}).get('name', 'Unknown')
                }
                package_versions.append(package_version)
                print(f"Found packageVersion: {package_version['name']} (UUID: {package_version['uuid']})")

            next_page_id = response_data.get('list', {}).get('response', {}).get('next_page_id')
            if not next_page_id:
                break
                
        except requests.exceptions.RequestException as e:
            print(f"Failed to get packageVersions: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response: {e.response.text}")
            return []

    print(f"Total packageVersions found: {len(package_versions)}")
    return package_versions

def create_spdx_sbom_export(namespace, token, package_version_uuids, output_format="FORMAT_JSON"):
    """
    Create an SPDX SBOM export including multiple packageVersions.
    """
    url = f"{API_URL}/namespaces/{namespace}/sbom-export"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Request-Timeout": "600"
    }
    
    payload = {
        "tenant_meta": {
            "namespace": namespace
        },
        "meta": {
            "name": f"SPDX SBOM Export: {namespace}-sbom"
        },
        "spec": {
            "kind": "SBOM_KIND_SPDX",
            "format": output_format,
            "component_type": "COMPONENT_TYPE_APPLICATION",
            "export_parameters": {
                "package_version_uuids": package_version_uuids
            }
        }
    }
    
    try:
        print(f"Creating SPDX SBOM export for {len(package_version_uuids)} packageVersions...")
        response = requests.post(url, headers=headers, json=payload, timeout=600)
        response.raise_for_status()
        
        sbom_data = response.json()
        return sbom_data
        
    except requests.exceptions.RequestException as e:
        print(f"Failed to create SPDX SBOM export: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
        return None

def read_test_dependencies(filename):
    """Read test dependencies from a text file."""
    if not os.path.exists(filename):
        print(f"Warning: {filename} not found. No test dependencies will be removed.")
        return set()
    
    test_deps = set()
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    test_deps.add(line)
        print(f"Loaded {len(test_deps)} test dependencies from {filename}")
        return test_deps
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return set()

def is_test_dependency(package_name, package_version, test_dependencies):
    """Check if a package is a test dependency."""
    # Check exact name match first
    if package_name in test_dependencies:
        return True
    
    # Check name@version format if specified in test_dependencies
    name_version = f"{package_name}@{package_version}"
    if name_version in test_dependencies:
        return True
    
    return False

def remove_test_dependencies(spdx_sbom, test_dependencies):
    """
    Remove test dependencies and their relationships from the SPDX SBOM.
    
    Args:
        spdx_sbom: The SPDX SBOM data as a JSON object
        test_dependencies: Set of test dependency names to remove
    
    Returns:
        Cleaned SPDX SBOM as a JSON object
    """
    if not test_dependencies:
        print("No test dependencies to remove.")
        return spdx_sbom
    
    print(f"Removing {len(test_dependencies)} test dependencies from SBOM...")
    
    # Create a copy to avoid modifying the original
    cleaned_sbom = json.loads(json.dumps(spdx_sbom))
    
    # Track packages to remove
    packages_to_remove = set()
    
    # Identify packages that are test dependencies
    for package in cleaned_sbom.get("packages", []):
        package_name = package.get("name", "")
        package_version = package.get("versionInfo", "")
        if is_test_dependency(package_name, package_version, test_dependencies):
            packages_to_remove.add(package.get("SPDXID"))
            print(f"Marking for removal: {package_name}@{package_version} ({package.get('SPDXID')})")
    
    # Remove test dependency packages
    cleaned_sbom["packages"] = [
        package for package in cleaned_sbom.get("packages", [])
        if package.get("SPDXID") not in packages_to_remove
    ]
    
    print(f"Removed {len(packages_to_remove)} packages")
    
    # Clean up relationships
    if "relationships" in cleaned_sbom:
        # Remove relationships that involve removed packages
        cleaned_sbom["relationships"] = [
            rel for rel in cleaned_sbom.get("relationships", [])
            if (rel.get("spdxElementId") not in packages_to_remove and 
                rel.get("relatedSpdxElement") not in packages_to_remove)
        ]
        
        # Also remove relationships that reference non-existent packages
        existing_package_ids = {pkg.get("SPDXID") for pkg in cleaned_sbom.get("packages", [])}
        existing_package_ids.add("SPDXRef-DOCUMENT")  # Document always exists
        
        cleaned_sbom["relationships"] = [
            rel for rel in cleaned_sbom.get("relationships", [])
            if (rel.get("spdxElementId") in existing_package_ids and 
                rel.get("relatedSpdxElement") in existing_package_ids)
        ]
        
        print(f"Cleaned up relationships, remaining: {len(cleaned_sbom['relationships'])}")
    
    # Update document metadata
    current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cleaned_sbom["creationInfo"]["created"] = current_time
    cleaned_sbom["creationInfo"]["creators"].append("Tool: Test Dependency Removal Tool")
    
    return cleaned_sbom

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Download SPDX SBOM and remove test dependencies.')
    parser.add_argument('--project_uuid', type=str, required=True, help='The UUID of the project')
    parser.add_argument('--output', type=str, help='Output SPDX file name (defaults to {project_uuid}-cleaned-spdx.json)')
    parser.add_argument('--branch', type=str, help='Branch context to analyze (defaults to main context)')
    parser.add_argument('--test-deps-file', type=str, default='test_dependencies.txt', 
                       help='File containing test dependencies to remove (default: test_dependencies.txt)')
    
    args = parser.parse_args()
    
    # Set default filenames based on project_uuid and branch if not provided
    if not args.output:
        if args.branch and args.branch.lower() != "main":
            args.output = f"{args.project_uuid}-{args.branch}-cleaned-spdx.json"
        else:
            args.output = f"{args.project_uuid}-cleaned-spdx.json"
    
    # Get environment values
    env = get_env_values()
    
    # Get API token
    token = get_token(env["api_key"], env["api_secret"])
    if not token:
        print("Failed to get API token.")
        sys.exit(1)
    
    # Get project details using the initial namespace from .env
    project_name, namespace = get_project_details(token, args.project_uuid, env["initial_namespace"])
    
    if not namespace:
        print(f"ERROR: Could not determine namespace for project {args.project_uuid}.")
        sys.exit(1)
    
    print(f"Using namespace from project details: {namespace}")
    
    # First, get all packageVersions for the project
    package_versions = get_package_versions(namespace, token, args.project_uuid, args.branch)
    
    if not package_versions:
        print(f"No packageVersions found for project {args.project_uuid}.")
        sys.exit(1)
    
    # Extract just the UUIDs from the package_versions list
    package_version_uuids = [pv['uuid'] for pv in package_versions]
    
    # Generate an SPDX SBOM with all package versions
    spdx_response = create_spdx_sbom_export(namespace, token, package_version_uuids, "FORMAT_JSON")
    
    if not spdx_response:
        print("Failed to generate SPDX SBOM.")
        sys.exit(1)
    
    # Extract SPDX data
    spdx_data = None
    spdx_content = spdx_response.get('spec', {}).get('data')
    
    if spdx_content:
        try:
            spdx_data = json.loads(spdx_content)
        except json.JSONDecodeError:
            print("Error: Failed to parse SPDX data")
            sys.exit(1)
    else:
        print("Warning: No SPDX data found at spec.data path")
        # Try to use the response directly if it has packages
        if 'packages' in spdx_response:
            spdx_data = spdx_response
    
    if not spdx_data:
        print("Failed to process SPDX data.")
        sys.exit(1)
    
    # Read test dependencies
    test_dependencies = read_test_dependencies(args.test_deps_file)
    
    # Remove test dependencies
    cleaned_spdx = remove_test_dependencies(spdx_data, test_dependencies)
    
    # Save the original SPDX SBOM
    original_output = args.output.replace('-cleaned-', '-original-')
    with open(original_output, 'w') as f:
        json.dump(spdx_data, f, indent=2)
    
    # Save the cleaned SPDX SBOM
    with open(args.output, 'w') as f:
        json.dump(cleaned_spdx, f, indent=2)
    
    print(f"SBOM processing complete!")
    print(f"Original SBOM saved to: {original_output}")
    print(f"Cleaned SBOM saved to: {args.output}")
    print(f"Original packages: {len(spdx_data.get('packages', []))}")
    print(f"Cleaned packages: {len(cleaned_spdx.get('packages', []))}")
    print(f"Removed packages: {len(spdx_data.get('packages', [])) - len(cleaned_spdx.get('packages', []))}")

if __name__ == "__main__":
    main()
