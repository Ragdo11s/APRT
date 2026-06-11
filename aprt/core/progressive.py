"""
Progressive loop (core orchestrator).

Closes the APRT cycle:

    seed findings
        -> evaluate (risk)
        -> select   (ranked NextActions)
        -> for each ready action: merge profile_override into the manifest,
           run the adapter, normalize the raw output, evaluate the new findings
        -> repeat until no new ready actions or the wave budget is spent.

This module decides the *control flow* only. It does not know how to run a tool
or parse its output -- those are injected, so the same loop drives the real
adapters/normalizers in production and mocks in tests:

    run_adapter(adapter_name, manifest_path, target_id) -> status
        status has: .status ("success"|...), .run_id, .target_id, .raw_output_file
    normalizers: { tool_name: factory(run_id, target_id) -> obj.normalize_file(path) }

Safety: the selector already drops out-of-scope / over-risk proposals, and the
adapters enforce scope again at execution. The loop only runs actions the
selector returned as `ready`; `blocked` proposals are surfaced, never executed.
"""
from __future__ import annotations

import copy
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from normalizers.base import Finding
from evaluation import Evaluator
from selection import Selector, NextAction


@dataclass
class WaveRecord:
    wave: int
    executed: list[str] = field(default_factory=list)   # action_ids
    skipped: list[str] = field(default_factory=list)     # adapter has no normalizer
    new_findings: int = 0


@dataclass
class LoopResult:
    findings: list[Finding]
    waves: list[WaveRecord]
    blocked: list[NextAction]       # surfaced leads that need scope/capability


class ProgressiveLoop:
    def __init__(
        self,
        manifest: dict,
        run_adapter: Callable[[str, str, str], Any],
        normalizers: dict[str, Callable[[str, str], Any]],
        evaluator: Evaluator | None = None,
        selector: Selector | None = None,
        max_waves: int = 3,
        max_actions_per_wave: int = 5,
        work_dir: str | Path | None = None,
    ) -> None:
        self.manifest = manifest
        self.run_adapter = run_adapter
        self.normalizers = normalizers
        self.evaluator = evaluator or Evaluator()
        self.selector = selector or Selector()
        self.max_waves = max_waves
        self.max_actions_per_wave = max_actions_per_wave
        self.work_dir = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="aprt_eff_"))

    def run(self, seed_findings: list[Finding]) -> LoopResult:
        store: dict[str, Finding] = {}
        self._ingest(store, self.evaluator.evaluate_all(seed_findings))

        done: set[str] = set()
        waves: list[WaveRecord] = []
        last_blocked: list[NextAction] = []

        for wave_no in range(1, self.max_waves + 1):
            proposals = self.selector.select(list(store.values()), self.manifest, done=done)
            last_blocked = proposals["blocked"]
            ready = proposals["ready"][: self.max_actions_per_wave]
            if not ready:
                break  # converged: nothing new worth doing

            rec = WaveRecord(wave=wave_no)
            for action in ready:
                done.add(action.action_id)
                status = self._dispatch(action)
                rec.executed.append(action.action_id)

                factory = self.normalizers.get(action.adapter)
                if factory is None:
                    rec.skipped.append(action.action_id)   # e.g. zap: no normalizer yet
                    continue
                if getattr(status, "status", None) != "success":
                    continue

                normalizer = factory(status.run_id, status.target_id)
                new = normalizer.normalize_file(status.raw_output_file)
                new = self.evaluator.evaluate_all(new)
                rec.new_findings += self._ingest(store, new)

            waves.append(rec)

        return LoopResult(findings=list(store.values()), waves=waves, blocked=last_blocked)

    # ---- internals ----

    def _dispatch(self, action: NextAction):
        """Merge the action's profile override into the manifest, persist it, run."""
        eff = copy.deepcopy(self.manifest)
        eff.setdefault("scan_profiles", {}).setdefault(action.adapter, {}).update(action.profile_override)
        eff_path = self.work_dir / f"manifest_{action.action_id}.yaml"
        eff_path.write_text(yaml.safe_dump(eff, sort_keys=False, allow_unicode=True), encoding="utf-8")
        return self.run_adapter(action.adapter, str(eff_path), action.target_id)

    @staticmethod
    def _ingest(store: dict[str, Finding], findings: list[Finding]) -> int:
        added = 0
        for f in findings:
            if f.finding_id not in store:
                added += 1
            store[f.finding_id] = f   # stable id -> dedup / upsert
        return added
