# NET2008 PA2 - Fleet Compliance Auditor

Name: Justin Sideris
Student ID: 041197838

## Brief description 

A Python command-line tool that reads network devices from an XML file, checks them against a YAML compliance policy, and generates a JSON report.

## How to run
python pa2.py DEVICES.xml POLICY.yaml

## Requirements
- Python 3
- PyYAML 

## Output

audit.json contains device counts, interface counts, compliance violations, and compliant devices.