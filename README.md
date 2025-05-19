# Endor Labs SBOM Generator

This repository contains scripts for interacting with the Endor Labs API to generate Software Bill of Materials (SBOM) files.

## Scripts

1. `fix_findings.py` - A script for querying and managing findings in Endor Labs.
2. `create_spdx_sbom.py` - A script for generating SBOM files in CycloneDX format.

## CycloneDX SBOM Generator Usage

The `create_spdx_sbom.py` script allows you to generate SBOM files in CycloneDX format for projects in your Endor Labs namespace.

### Prerequisites

- Python 3.6+
- Required Python packages: `requests`, `python-dotenv`
- Endor Labs API key and secret

### Installation

1. Install required packages:
   ```
   pip install requests python-dotenv
   ```

2. Create a `.env` file in the same directory as the script with your Endor Labs API credentials:
   ```
   API_KEY=your_api_key
   API_SECRET=your_api_secret
   ```

### Usage

```
python create_spdx_sbom.py --namespace YOUR_NAMESPACE --project_uuid YOUR_PROJECT_UUID [options]
```

#### Required Arguments

- `--namespace` - The Endor Labs namespace where your projects are located
- `--project_uuid` - The UUID of the project to generate an SBOM for

#### Optional Arguments

- `--output` - The output file name (defaults to `cyclonedx-sbom.json`)
- `--format` - The output format: `json` (default) or `xml`

#### Examples

Generate CycloneDX SBOM:
```
python create_spdx_sbom.py --namespace acme --project_uuid 123e4567-e89b-12d3-a456-426614174000
```

Generate CycloneDX SBOM with a custom output filename:
```
python create_spdx_sbom.py --namespace acme --project_uuid 123e4567-e89b-12d3-a456-426614174000 --output custom-sbom.json
```

Generate CycloneDX SBOM in XML format:
```
python create_spdx_sbom.py --namespace acme --project_uuid 123e4567-e89b-12d3-a456-426614174000 --format xml
```

## Related Information

- For more information about Endor Labs API, refer to the `openapiv2.swagger.json` file.
- Sample SBOM file: `sbom_export_dev.azure.com-itron_SoftwareProducts__git_DERA_test-itron-cyclonedx.json`