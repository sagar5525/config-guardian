# 🔐 config-guardian - Configuration Security Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.7%2B-blue)](https://www.python.org)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**config-guardian** is a comprehensive, open-source security scanner for configuration files. It detects misconfigurations and security vulnerabilities in critical files used by **web servers, mobile apps, containers, and cloud infrastructure**.

Think of it as a **static analysis tool for your `server.xml`, `AndroidManifest.xml`, `docker-compose.yml`, `nginx.conf`, and more** — helping you catch security issues before they go to production.

---

## 🚀 Features

✅ **Multi-Platform Support**: Scan configurations across 10+ technologies  
✅ **Comprehensive Rules**: Hardening rules based on OWASP, CIS, vendor best practices (Apache, Tomcat, AWS, Azure, etc.)  
✅ **Rich Output Formats**: Get results in **text** or detailed **HTML reports**  
✅ **Extensible Rule Engine**: Easily add new file types and custom rules  
✅ **MASVS-Aligned**: Android rules mapped to OWASP Mobile Application Security Verification Standard  
✅ **CI/CD Ready**: Perfect for integration into your DevSecOps pipeline  

---

## 📋 Supported Technologies

| Category | File Types | Example Rules |
|--------|-----------|---------------|
| **Web Servers** | `server.xml`, `nginx.conf`, `httpd.conf` | Debug mode, cleartext traffic, weak SSL, exposed management apps |
| **Mobile Apps** | `AndroidManifest.xml`, `Info.plist` | Debuggable, exported components, ATS disabled, backup enabled |
| **Containers** | `docker-compose.yml` | Privileged containers, host networking, secrets in env vars |
| **Cloud** | `*.tf`, `*.yaml` (K8s), `*.json` (CFN, ARM) | Public S3 buckets, unrestricted security groups, hardcoded secrets |
| **Java Apps** | `web.xml` | Directory listing, missing security constraints, session timeout |

---

## 📦 Installation

### Prerequisites
- Python 3.7 or higher
- `pip` package manager

### Install Dependencies
```bash
pip install -r requirements.txt
```

Note: For Terraform (.tf) scanning, install the HCL2 parser: 

```bash
pip install python-hcl2
```

## 🧪 Usage 

### Scan a Single File
```bash


# Text output
python config-guardian.py samples/AndroidManifest.xml --format text

# Generate HTML report
python config-guardian.py samples/docker-compose.yml --format html -o docker_report.html
```

### Scan Cloud Configurations
```bash

# Terraform
python config-guardian.py infra/main.tf --format html -o tf_report.html

# Kubernetes
python config-guardian.py k8s/deployment.yaml --format html -o k8s_report.html

# AWS CloudFormation
python config-guardian.py cloud/aws.yaml --format html -o cfn_report.html

# Azure ARM Template
python cconfig-guardian cloud/azure.json --format html -o arm_report.html
```

## Help
```bash

python config-guardian.py --help
```

## 🛠️ Rule Development

Adding new rules is easy! Just edit the corresponding .yaml file in the rules/ directory.

Example Rule (Docker)
```bash

rules:
  - id: "DOCKER-001"
    name: "Privileged Container"
    description: "Container runs in privileged mode, breaking isolation."
    type: "key"
    key: "services.*.privileged"
    value: "true"
    severity: "High"
    remediation: "Remove privileged: true unless absolutely necessary."
    reference: "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"
```
Rule Types: key (YAML/JSON), xpath (XML), regex (text files) 

#### ConfigShield fills the gap for non-IaC, non-code configuration files that are often overlooked in security pipelines.

## 🤝 Contributing

We welcome contributions! Please see our CONTRIBUTING.md for guidelines.

Fork the repository

Create your feature branch (git checkout -b feature/new-rule)

Commit your changes (git commit -am 'Add new rule for X')

Push to the branch (git push origin feature/new-rule)

Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📬 Contact
Have a question or found a bug? - Mail to srahalkar@proton.me
