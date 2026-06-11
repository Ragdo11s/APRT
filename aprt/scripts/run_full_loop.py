"""
Stage 2 — full progressive loop against the manifest target.

Seeds with one baseline nuclei run, then runs the progressive cycle
(evaluate -> select -> dispatch -> normalize -> repeat) until it converges.

Needs in place: everything + the 3 patches
  - normalizers/base.py additions
  - nuclei_normalizer cve/cvss extraction
  - nuclei_adapter `-tags` support  (else tag-targeted pivots run untargeted)

Run from repo root:
  python scripts/run_full_loop.py configs/<your-manifest>.yaml
"""
import os
import sys

# run-from-anywhere: put the repo root (parent of scripts/) on the import path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import copy
import tempfile

import yaml

from adapters.nuclei_adapter import NucleiAdapter
from adapters.zap_adapter import ZapAdapter
from normalizers.nuclei_normalizer import NucleiNormalizer
from normalizers.zap_normalizer import ZapNormalizer
from evaluation import Evaluator
from core.progressive import ProgressiveLoop
from core.discovery import run_discovery_prepass
from core.auth import bearer_token

manifest_path = sys.argv[1] if len(sys.argv) > 1 else "configs/manifest.yaml"
manifest = yaml.safe_load(open(manifest_path, encoding="utf-8"))


def run_adapter(name, mpath, target_id):
    cls = {"nuclei": NucleiAdapter, "zap": ZapAdapter}[name]
    return cls(manifest_path=mpath).run(target_id)


# NOTE: adjust these lambdas to your real BaseNormalizer.__init__ signature.
normalizers = {
    "nuclei": lambda run_id, tid: NucleiNormalizer(run_id=run_id, target_id=tid),
    "zap":    lambda run_id, tid: ZapNormalizer(run_id=run_id, target_id=tid),
}

# seed = a RECON nuclei pass. It MUST include `info` severity: the progressive
# pivots key off tech/banner fingerprints (Spring, nginx, OpenSSH detection),
# which nuclei rates `info`. The manifest's own nuclei.severity is the reporting
# filter (low+); we widen it for recon ONLY, via a derived manifest. exclude_tags
# (intrusive/dos/fuzz/brute-force) stay intact, so recon is still safe.
recon = copy.deepcopy(manifest)
recon.setdefault("scan_profiles", {}).setdefault("nuclei", {})["severity"] = \
    ["info", "low", "medium", "high", "critical"]
recon_path = os.path.join(tempfile.mkdtemp(prefix="aprt_recon_"), "recon_manifest.yaml")
with open(recon_path, "w", encoding="utf-8") as fh:
    yaml.safe_dump(recon, fh, sort_keys=False, allow_unicode=True)

seed_status = run_adapter("nuclei", recon_path, None)
seed = []
if seed_status.status == "success":
    seed = NucleiNormalizer(
        run_id=seed_status.run_id, target_id=seed_status.target_id
    ).normalize_file(seed_status.raw_output_file)
print(f"seed: {len(seed)} findings from recon nuclei ({seed_status.status})")

# --- 외부 발견 프리패스: 프론트엔드 크롤 -> /api 엔드포인트 -> 미니 스펙 ->
#     ZAP openapi import에 openapi_file로 주입.
target = manifest["targets"][0]
base_url = str(target["base_url"])
token, _ = bearer_token(manifest, target)
disc = run_discovery_prepass(
    base_url,
    f"runs/_discovery/{target['id']}-spec.json",
    token=token,
)
if disc:
    spec_path, endpoints = disc
    manifest.setdefault("scan_profiles", {}).setdefault("zap", {})["openapi_file"] = spec_path
    print(f"[discovery] {len(endpoints)} endpoints -> {spec_path}")
else:
    print("[discovery] no /api endpoints in front-end (brute-force는 나중에 active로)")

loop = ProgressiveLoop(manifest, run_adapter=run_adapter, normalizers=normalizers,
                       max_waves=3, max_actions_per_wave=5)

loop = ProgressiveLoop(manifest, run_adapter=run_adapter, normalizers=normalizers,
                       max_waves=3, max_actions_per_wave=5)
result = loop.run(seed)

print("\nWAVES:")
for w in result.waves:
    print(f"  wave {w.wave}: executed {len(w.executed)} | skipped {len(w.skipped)} | new {w.new_findings}")
print(f"\nfindings: {len(result.findings)}")
for f in sorted(result.findings, key=lambda x: x.risk.final_score, reverse=True)[:20]:
    r = f.risk
    print(f"  {r.final_score:>4} [{r.provenance:<11}] {f.severity:<8} {f.title[:45]} {f.url}")
print("\nblocked leads:")
for a in result.blocked:
    print(f"  {a.rationale}  ({a.blocked_reason})")
