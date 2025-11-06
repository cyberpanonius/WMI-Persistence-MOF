#!/usr/bin/env python3
"""
wmi_persistence_scan_safe.py
- Safely scans root\subscription for WMI persistence artifacts
- Handles uninitialized properties, decodes CreatorSID, resolves referenced consumers
- Writes results to wmi_persistence_results.json
"""
from pathlib import Path
from dissect.cim import CIM
import json
import sys
from typing import Any

# ---------- CONFIG ----------
index = Path("INDEX.BTR")
objects = Path("OBJECTS.DATA")
mappings = [
    Path(f"/home/dfir/tutorial-env/lib/python3.10/site-packages/MAPPING{i}.MAP")
    for i in range(1, 4)
]
output_json = Path("wmi_persistence_results.json")

# ---------- UTIL ----------

def safe_prop_value(prop) -> Any:
    """
    Safely return the property value for a dissect.cim property object.
    If the property is uninitialized or raises, return an indicative string.
    """
    try:
        # many property objects expose .value; some will raise if not initialized
        val = prop.value
    except Exception as e:
        return f"<UNINITIALIZED: {e}>"
    # handle arrays of bytes -> list shown earlier
    # leave complex types for caller to handle
    return val

def bytes_list_to_bytes(obj):
    """If obj is list of ints (as seen in CreatorSID), convert to bytes."""
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj)
    if isinstance(obj, list) and all(isinstance(x, int) for x in obj):
        return bytes(obj)
    return None

def sid_from_bytes(b: bytes) -> str:
    """
    Convert Windows SID binary to string form S-Revision-Authority-SubAuth1-...
    SID layout:
      1 byte revision
      1 byte subauthority count (n)
      6 bytes identifier authority (big-endian)
      n * 4 bytes subauthority (little-endian each)
    """
    if not b or len(b) < 8:
        return "<INVALID SID>"
    try:
        rev = b[0]
        subcount = b[1]
        ident_auth = int.from_bytes(b[2:8], byteorder='big')
        subs = []
        # remaining bytes should be 4 * subcount
        offset = 8
        for i in range(subcount):
            if offset + 4 <= len(b):
                sub = int.from_bytes(b[offset:offset+4], byteorder='little', signed=False)
                subs.append(str(sub))
            else:
                subs.append("<TRUNCATED>")
            offset += 4
        return "S-{}-{}".format(rev, "-".join([str(ident_auth)] + subs)) if subs else f"S-{rev}-{ident_auth}"
    except Exception as e:
        return f"<SID PARSE ERROR: {e}>"

def decode_creator_sid(prop_val):
    """Given a property value for CreatorSID, attempt to return a readable SID string."""
    b = bytes_list_to_bytes(prop_val)
    if b is None:
        return None
    return sid_from_bytes(b)

def instance_to_dict(inst, namespace_obj):
    """Convert an Instance to a serializable dict, safely reading properties."""
    out = {}
    for k, p in inst.properties.items():
        val = safe_prop_value(p)
        # If CreatorSID or similar binary-like, decode to SID if possible
        if k.lower() == "creatorsid":
            sid = decode_creator_sid(val)
            out[k] = {"raw": val, "sid": sid}
        else:
            # If value looks like a reference string
            # keep both raw and a resolved version (if possible)
            if isinstance(val, str) and ":" in val and "\\" in val:
                out[k] = {"raw": val}
                # try to resolve if it's a local root\subscription reference
                try:
                    # some references come in format "\\.\\root\\subscription:Class.Key=\"Name\""
                    resolved = None
                    try:
                        resolved = namespace_obj.query(val)
                    except Exception:
                        resolved = None
                    if resolved:
                        # if query found an instance, flatten its properties too
                        out[k]["resolved"] = instance_to_dict(resolved, namespace_obj)
                except Exception:
                    out[k]["resolve_error"] = "failed to resolve"
            else:
                # normal scalar or array
                out[k] = val
    return out

# ---------- MAIN ----------
def main():
    # validate inputs exist
    for p in [index, objects] + mappings:
        if not p.exists():
            print(f"ERROR: Path does not exist: {p}", file=sys.stderr)
            # continue rather than exit so user can see all missing
    try:
        repo = CIM(index.open("rb"), objects.open("rb"), [m.open("rb") for m in mappings])
    except Exception as e:
        print("Failed to open CIM repository:", e, file=sys.stderr)
        sys.exit(2)

    print("✅ Loaded CIM repository\n")
    print("Available namespaces:")
    for ns in repo.root.namespaces:
        print(" -", ns.name)
    print()

    # try subscription namespace
    try:
        subscription_ns = repo.root.namespace("subscription")
    except Exception as e:
        print("Could not open root\\subscription:", e, file=sys.stderr)
        sys.exit(3)

    results = {"bindings": [], "consumers": {}, "filters": []}

    # === bindings ===
    try:
        binding_class = subscription_ns.class_("__FilterToConsumerBinding")
        bindings = list(binding_class.instances)
        print(f"=== __FilterToConsumerBinding Instances ===\nFound {len(bindings)} binding(s).")
        for b in bindings:
            bdict = instance_to_dict(b, subscription_ns)
            results["bindings"].append(bdict)
            # print small summary
            consumer_ref = bdict.get("Consumer")
            print("\nBinding Instance:")
            for k, v in bdict.items():
                if k == "Consumer" and isinstance(v, dict):
                    print(f"  Consumer (raw): {v.get('raw')}")
                    if "resolved" in v:
                        # print summary of resolved consumer if present
                        res = v["resolved"]
                        name = res.get("Name") or res.get("InstanceID") or None
                        print(f"    -> Resolved consumer name-like: {name}")
                else:
                    # nice-print CreatorSID with resolved SID if available
                    if k.lower() == "creatorsid" and isinstance(v, dict):
                        print(f"  CreatorSID: {v.get('sid')} (raw: {v.get('raw')})")
                    else:
                        print(f"  {k}: {v}")
    except Exception as e:
        print("Error reading bindings:", e)

    # === consumers ===
    consumer_classes = [
        "CommandLineEventConsumer",
        "ActiveScriptEventConsumer",
        "NTEventLogEventConsumer",
        "LogFileEventConsumer"
        
    ]
    print("\n=== Event Consumer Instances ===")
    for cls_name in consumer_classes:
        try:
            if cls_name.lower() in [c.name.lower() for c in subscription_ns.classes]:
                cls = subscription_ns.class_(cls_name)
                instances = list(cls.instances)
                if instances:
                    print(f"\n[{cls_name}] ({len(instances)} instance(s))")
                    for inst in instances:
                        idict = instance_to_dict(inst, subscription_ns)
                        # store consumers keyed by class + index
                        results["consumers"].setdefault(cls_name, []).append(idict)
                        print("Instance:")
                        for k, v in idict.items():
                            if k.lower() == "creatorsid" and isinstance(v, dict):
                                print(f"  {k}: {v.get('sid')}")
                            else:
                                print(f"  {k}: {v}")
        except Exception as e:
            print(f"Error reading {cls_name}: {e}")

    # === filters ===
    print("\n=== __EventFilter Instances ===")
    try:
        if "__EventFilter".lower() in [c.name.lower() for c in subscription_ns.classes]:
            filt_class = subscription_ns.class_("__EventFilter")
            filters = list(filt_class.instances)
            print(f"Found {len(filters)} filter(s).")
            for inst in filters:
                fdict = instance_to_dict(inst, subscription_ns)
                results["filters"].append(fdict)
                print("\nFilter Instance:")
                for k, v in fdict.items():
                    if k.lower() == "creatorsid" and isinstance(v, dict):
                        print(f"  {k}: {v.get('sid')}")
                    else:
                        print(f"  {k}: {v}")
    except Exception as e:
        print("Error reading filters:", e)

    # write JSON
    try:
        with open(output_json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
        print(f"\n✅ Results written to: {output_json}")
    except Exception as e:
        print("Failed to write JSON:", e, file=sys.stderr)

    print("\n✅ Scan complete.")

if __name__ == "__main__":
    main()

