#!/usr/bin/env python3
"""Turn `cargo metadata` output into a minimal CycloneDX 1.5 SBOM."""
import json, sys
meta = json.load(open(sys.argv[1]))
comps = []
for p in sorted(meta.get("packages", []), key=lambda x: (x["name"], x["version"])):
    comps.append({
        "type": "library",
        "name": p["name"],
        "version": p["version"],
        "purl": f'pkg:cargo/{p["name"]}@{p["version"]}',
        "licenses": ([{"license": {"id": p["license"]}}] if p.get("license") else []),
    })
sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {"component": {"type": "application", "name": "acp", "version": "0.0.0"}},
    "components": comps,
}
print(json.dumps(sbom, indent=2))
