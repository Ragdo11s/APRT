"""
Stage 1 — real ZAP baseline against the manifest target -> normalize -> evaluate.

The lightest real test. Also produces the real zap-report.json so the ZAP
normalizer's field mapping can be verified against your ZAP version.

Needs in place:
  - normalizers/base.py  (with the Cvss / Mappings.cve / Risk audit additions)
  - evaluation/          (package)
  - normalizers/zap_normalizer.py
Does NOT need: selection/, core/progressive, the nuclei patches.

Run from repo root:
  python scripts/run_stage1_zap.py configs/<your-manifest>.yaml
"""
import os
import sys

# run-from-anywhere: put the repo root (parent of scripts/) on the import path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adapters.zap_adapter import ZapAdapter
from normalizers.zap_normalizer import ZapNormalizer
from evaluation import Evaluator

manifest = sys.argv[1] if len(sys.argv) > 1 else "configs/manifest.yaml"

# ZAP baseline is unauthenticated here (current zap_adapter doesn't inject auth).
status = ZapAdapter(manifest_path=manifest).run()
print(f"ZAP run: {status.status}   report: {status.raw_output_file}")
if status.status != "success":
    print("failed - see:", status.stderr_file)
    sys.exit(1)

findings = ZapNormalizer(
    run_id=status.run_id, target_id=status.target_id
).normalize_file(status.raw_output_file)
findings = Evaluator().evaluate_all(findings)

print(f"\n{len(findings)} findings (sorted by score):")
for f in sorted(findings, key=lambda x: x.risk.final_score, reverse=True):
    r = f.risk
    print(f"  {r.final_score:>4} [{r.provenance:<11}] {f.severity:<8} {f.title[:45]:<45} {f.url}")
