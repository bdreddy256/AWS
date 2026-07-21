#!/usr/bin/env python3
"""
Inspect your actual config structure to find where rules/SGPs are located.
"""

import xml.etree.ElementTree as ET
import sys
import glob

def find_rules_in_config(config_file):
    """Search for security rules in all possible locations."""
    try:
        tree = ET.parse(config_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing {config_file}: {e}")
        return
    
    print(f"\n{'='*80}")
    print(f"CONFIG: {config_file}")
    print(f"{'='*80}\n")
    
    # Search for all possible rule locations
    search_paths = [
        (".//security/rules/entry", "Generic security/rules"),
        (".//vsys/entry/security/rules/entry", "vsys → security/rules"),
        (".//devices/entry/vsys/entry/security/rules/entry", "devices/vsys → security/rules"),
        (".//shared/security/rules/entry", "shared/security/rules"),
        (".//pre-rulebase/security/rules/entry", "pre-rulebase/security/rules"),
        (".//post-rulebase/security/rules/entry", "post-rulebase/security/rules"),
    ]
    
    print("SEARCHING FOR SECURITY RULES:\n")
    found_rules = False
    for path, description in search_paths:
        rules = root.findall(path)
        if rules:
            found_rules = True
            print(f"✓ FOUND {len(rules)} rules at: {path}")
            print(f"  Description: {description}")
            for i, rule in enumerate(rules[:3]):
                rule_name = rule.get("name", "?")
                print(f"    - Rule {i+1}: {rule_name}")
            if len(rules) > 3:
                print(f"    ... and {len(rules)-3} more")
            print()
    
    if not found_rules:
        print("✗ NO SECURITY RULES FOUND in any standard location\n")
    
    # Search for SGPs
    sgp_paths = [
        (".//security-group-tagging/entry", "security-group-tagging"),
        (".//post-rulebase/security-group-tagging/entry", "post-rulebase/security-group-tagging"),
        (".//vsys/entry/post-rulebase/security-group-tagging/entry", "vsys → post-rulebase/security-group-tagging"),
        (".//shared/post-rulebase/security-group-tagging/entry", "shared → security-group-tagging"),
    ]
    
    print("SEARCHING FOR SECURITY GROUP PROFILES (SGP):\n")
    found_sgp = False
    for path, description in sgp_paths:
        sgps = root.findall(path)
        if sgps:
            found_sgp = True
            print(f"✓ FOUND {len(sgps)} SGPs at: {path}")
            print(f"  Description: {description}")
            for i, sgp in enumerate(sgps[:3]):
                sgp_name = sgp.get("name", "?")
                print(f"    - SGP {i+1}: {sgp_name}")
            if len(sgps) > 3:
                print(f"    ... and {len(sgps)-3} more")
            print()
    
    if not found_sgp:
        print("✗ NO SECURITY GROUP PROFILES FOUND\n")
    
    # Show which rules have SGPs attached
    if found_rules and found_sgp:
        print("RULES USING SGPs:\n")
        for path, _ in search_paths:
            rules = root.findall(path)
            if rules:
                for rule in rules[:5]:
                    rule_name = rule.get("name", "?")
                    sgp_members = rule.findall(".//group-tag/member")
                    if sgp_members:
                        sgps = [m.text for m in sgp_members]
                        print(f"  {rule_name:30} → SGP: {', '.join(sgps)}")
                break
    
    # Show config structure at root level
    print("\n" + "="*80)
    print("ROOT ELEMENTS IN CONFIG:")
    print("="*80 + "\n")
    for child in list(root)[:10]:
        tag = child.tag
        name = child.get("name", "")
        text = f" (name={name})" if name else ""
        count = len(list(child))
        print(f"  <{tag}>{text} - {count} children")
    
    if len(list(root)) > 10:
        print(f"  ... and {len(list(root))-10} more elements")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Inspect specific file
        find_rules_in_config(sys.argv[1])
    else:
        # Look for XML files in current directory or configs/
        xml_files = glob.glob("*.xml") + glob.glob("configs/*.xml")
        if not xml_files:
            print("Usage: python inspect_config_structure.py <config.xml>")
            print("\nOr place XML files in current directory or configs/ subdirectory")
            sys.exit(1)
        
        for xml_file in xml_files[:3]:  # Inspect first 3
            find_rules_in_config(xml_file)

