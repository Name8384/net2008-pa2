import xml.etree.ElementTree as ET
import yaml
import json
import sys

# Justin Sideris

# Student ID: 041197838


def read_inventory(xml_file):

    """Read an XML inventory file."""

    tree = ET.parse(xml_file)

    root = tree.getroot()

    return root

def read_policy(yaml_file):

    """Read a YAML compliance policy file."""

    with open(yaml_file, "r") as file:

        policy = yaml.safe_load(file)

    return policy

# checks to compare if both versions are equal and converts string to int adds a zeros to the shorter version and compares them. 
# Returns True if the current version meets or exceeds the minimum.

def compare_versions(current, minimum):

    """Compare two OS version numbers."""

    current = [int(part) for part in current.split(".")]

    minimum = [int(part) for part in minimum.split(".")]

    length = max(len(current), len(minimum))

    current = current + [0] * (length - len(current))

    minimum = minimum + [0] * (length - len(minimum))

    return current >= minimum

class PolicyError(Exception):
   
    """Custom exception for invalid policy settings."""


class Device:
    
    """Represent a network device from the XML inventory."""

    def __init__(self, element):
        
        """Extract device information from an XML element."""

        self.id = element.get("id")

        self.role = element.get("role")

        self.os = element.get("os")

        self.owner = element.find("owner")

        self.interfaces = element.findall("interface")

def valid_version(version):

    """Check whether a version contains only numeric components."""

    if not isinstance(version, str):

        return False

    parts = version.split(".")

    for part in parts:

        if not part.isdigit():

            return False

    return True

def main():

    """Main entry point for the compliance auditor."""

    if len(sys.argv) != 3:

        print("Usage: python pa2.py DEVICES.xml POLICY.yaml")

        sys.exit(2)
    
    #checks for if the file exists 

    try:
        read = read_inventory(sys.argv[1])

        site = read.get("site")

        devices = read.findall("device")

        policy = read_policy(sys.argv[2])

        if policy is None:
            
            policy = {}

        if not isinstance(policy, dict):

            print("Invalid policy file:", sys.argv[2])

            sys.exit(1)

        if "min_os" in policy:

            if not isinstance(policy["min_os"], dict):

                raise PolicyError("min_os must be a dictionary")

            for role, version in policy["min_os"].items():

                if not isinstance(role, str):

                    raise PolicyError("OS roles must be strings")

                if not valid_version(version):

                    raise PolicyError("Invalid OS version for role: " + role)

        if "require_owner" in policy and not isinstance(policy["require_owner"], bool):

            raise PolicyError("require_owner must be True or False")
       
        if "max_down_interfaces" in policy and (not isinstance(policy["max_down_interfaces"], int) or isinstance(policy["max_down_interfaces"], bool) or policy["max_down_interfaces"] < 0):
        
            raise PolicyError("max_down_interfaces must be a non-negative integer")

    except FileNotFoundError as error:

        print("File not found:", error.filename)

        sys.exit(1)

    except ET.ParseError:

        print("Invalid XML file:", sys.argv[1])

        sys.exit(1)

    except yaml.YAMLError:

        print("Invalid YAML file:", sys.argv[2])

        sys.exit(1)

    except PolicyError as error:

        print("Invalid policy file:", sys.argv[2], "-", error)

        sys.exit(1)
    

    device_count = 0

    skipped_devices = 0

    unknown_role = 0

    roles = {}

    device_ids = []

    violations = []

    interfaces_count = {
        "up": 0,
        "down": 0,
        "other": 0
    }

    audit_report = {}

    for element in devices:

        down_count = 0

        device = Device(element)

        device_id = device.id

        device_role = device.role

        device_os = device.os

        owner = device.owner

        # If device does not have an id add 1 , if there is no id count it as skipped and continue.

        if device_id is None:

            skipped_devices += 1
            
            continue

        device_ids.append(device_id)
       
        # Count how many devices have each role.
        
        if device_role in roles:

            roles[device_role] = roles[device_role] + 1

        else:

            roles[device_role] = 1

        device_count += 1

        # gets the interface data name example g0/0/1 and ststus if it's up or down and count how many are up down or are in a diffeent state

        interfaces = device.interfaces

        for interface in interfaces:

            interface_status = interface.get("status")

            if interface_status == "up":

                interfaces_count["up"] += 1

            elif interface_status == "down":

                interfaces_count["down"] += 1

                down_count += 1

            else:

                interfaces_count["other"] += 1

        max_down = policy.get("max_down_interfaces")

        if max_down is not None and down_count > max_down:

            violations.append({
                "device": device_id,
                "type": "too_many_down",
                "down": down_count
            })

        if "min_os" in policy:

            if device_role not in policy["min_os"]:

                unknown_role += 1

                violations.append({
                    "device": device_id,
                    "type": "unknown_role",
                    "role": device_role
                })
        
            else:
                
                minimum_os = policy["min_os"].get(device_role)

                if not valid_version(device_os):

                    print(device_id, "OS outdated")

                    violations.append({
                        "device": device_id,
                        "type": "os_outdated",
                        "found": device_os,
                        "required": minimum_os
                    })

                elif compare_versions(device_os, minimum_os):

                    print(device_id, "OS compliant")

                else:

                    print(device_id, "OS outdated")

                    violations.append({
                        "device": device_id,
                        "type": "os_outdated",
                        "found": device_os,
                        "required": minimum_os
                    })

        if policy.get("require_owner"):

            if owner is None or owner.text is None or owner.text.strip() == "":

                violations.append({
                    "device": device_id,
                    "type": "missing_owner"
                 })

    compliant = []

    for device_id in device_ids:

        has_violation = any(

            violation["device"] == device_id

            for violation in violations
        )
        
        if not has_violation:

            compliant.append(device_id)

    compliant.sort()

    print("\n Total devices:", device_count)

    print("\n Skipped devices:", skipped_devices)

    print("\n", roles)

    print("\n Interface counts:", interfaces_count)

    print("\n Policy:",policy)

    print("\n Unknown roles:", unknown_role)

    print("\n Violations:", violations)

    audit_report["site"] = site

    audit_report["total_devices"] = device_count

    audit_report["skipped_devices"] = skipped_devices

    audit_report["roles"] = roles

    audit_report["interfaces"] = interfaces_count

    audit_report["violations"] = violations   

    audit_report["compliant"] = compliant
    
    with open("audit.json", "w") as file:
    
        json.dump(audit_report, file, indent=4)

    
        
if __name__ == "__main__":
    main()