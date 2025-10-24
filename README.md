# aws_python

Inventory check for AWS Cloud

## AWS Security Audit Toolkit

The repository provides a modular `aws_security_audit` package that scans
core AWS services for common security issues. Each service-specific audit
lives in its own module for easier maintenance and extension, while the
CLI ties the results together into a consolidated report.

```
aws_security_audit/
├── cli.py              # Command line entry point
├── core.py             # Finding aggregation and presentation helpers
├── diagram.py          # Optional Graphviz network diagram support
├── findings.py         # Dataclasses shared across auditors
├── services/           # Per-service audit implementations
│   ├── acm.py
│   ├── ec2.py
│   ├── ecs.py
│   ├── eks.py
│   ├── iam.py
│   ├── rds.py
│   ├── route53.py
│   ├── s3.py
│   ├── ssm.py
│   └── vpc.py
└── __main__.py         # Enables `python -m aws_security_audit`
```

### Features

- Reviews networking constructs for overly permissive security groups,
  internet-open network ACL rules, dormant VPC peering links, and unhealthy
  site-to-site VPN tunnels.
- Highlights EC2 instances without IAM roles and unencrypted EBS volumes.
- Audits S3 buckets for public access, missing encryption, and access
  block configuration.
- Evaluates IAM users for MFA enrollment and aged access keys.
- Detects RDS databases that are public or unencrypted.
- Checks Route53 hosted zones for DNSSEC coverage.
- Flags ACM certificates that are near expiration or unused.
- Reports on Systems Manager managed instances that are offline or
  non-compliant.
- Examines EKS and ECS clusters for observability and encryption gaps.
- Optionally generates a network topology diagram when the `graphviz`
  Python package is installed.

### Prerequisites

- Python 3.9+
- `boto3`
- AWS credentials with read access to the audited services
- Optional: `graphviz` (Python package and system binaries) to create
  topology diagrams

Install dependencies with:

```bash
pip install boto3 graphviz
```

### Usage

```bash
python -m aws_security_audit --profile myprofile --region us-east-1 \
  --json findings.json --diagram network
```

- `--services` allows limiting the scan to specific services (e.g.
  `--services s3 iam`).
- `--json` exports the findings to a JSON file for further processing.
- `--diagram` writes a `graphviz` diagram (the script appends the
  extension based on the renderer format).

The script prints a table summarizing all detected findings. Findings are
categorized by severity (HIGH, MEDIUM, LOW, WARNING, ERROR).
