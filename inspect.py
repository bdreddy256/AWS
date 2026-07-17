import sys, xml.etree.ElementTree as ET

# Usage: python inspect.py yourconfig.xml
root = ET.parse(sys.argv[1]).getroot()

print("=== searching for password-complexity anywhere ===")
found = False
for el in root.iter():
    if el.tag in ("password-complexity", "minimum-length", "enabled"):
        # build path
        found = True
        print(f"  <{el.tag}> = {repr((el.text or '').strip())}")

if not found:
    print("  no password-complexity elements found at all")

print("\n=== full path to any 'minimum-length' ===")
def paths(node, trail=""):
    p = f"{trail}/{node.tag}"
    if node.tag == "minimum-length":
        print("  PATH:", p, "=", repr((node.text or '').strip()))
    for c in node:
        paths(c, p)
paths(root)

print("\n=== full path to any 'password-complexity' subtree ===")
def find_pc(node, trail=""):
    p = f"{trail}/{node.tag}"
    if node.tag == "password-complexity":
        print("  PATH:", p)
        print("  XML:", ET.tostring(node, encoding="unicode")[:400])
    for c in node:
        find_pc(c, p)
find_pc(root)
