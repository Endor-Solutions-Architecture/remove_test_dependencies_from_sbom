# Endor Labs SBOM Generator

This repository contains a script for downloading SBOM files in SPDX format from the Endor Labs API and removing test/dev dependencies to produce cleaned SBOMs.

### Prerequisites

- Python 3.6+
- Required Python packages: `requests`, `python-dotenv`
- Endor Labs API key and secret

### Installation

1. Installation:
   ```
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\\Scripts\\activate`
   pip install -r requirements.txt
   ```

2. Create a `.env` file in the same directory as the script with your Endor Labs API credentials and fill these values or copy paste from env_template:
   ```
   API_KEY=<YOUR_KEY>
   API_SECRET=<YOUR_SECRET>
   ENDOR_NAMESPACE="<YOUR_TENANT_NAMESPACE>"
   ```

#### Examples

Download SPDX SBOM and remove test dependencies:
```
python remove_test_dependencies.py --project_uuid <your_project_uuid>
```

Remove test dependencies from a custom list:
```
python remove_test_dependencies.py --project_uuid <your_project_uuid> --test-deps-file my_test_deps.txt
```

### Test Dependencies File

The `remove_test_dependencies.py` script uses a text file (default: `test_dependencies.txt`) to specify which dependencies should be removed. The file should contain one dependency name per line. Lines starting with `#` are treated as comments and ignored.

Example `test_dependencies.txt`:
```
# Test and development dependencies
pytest
pytest-cov
coverage
black
flake8
```

The script will remove these packages and their relationships from the generated SBOM, producing a cleaned version without test dependencies.

**Note**: If no `test_dependencies.txt` file is found, the script will download the SBOM but return it unchanged (no dependencies will be removed).

**Output Files**: The script generates two files:
- `{project_uuid}-original-spdx.json` - The original SBOM downloaded from the API
- `{project_uuid}-cleaned-spdx.json` - The SBOM with test dependencies removed
