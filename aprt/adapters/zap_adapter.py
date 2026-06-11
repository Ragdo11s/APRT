# adapters/zap_adapter.py
"""
ZAP Adapter — Windows 로컬 ZAP 을 헤드리스(-cmd -autorun)로 실행.

Docker 없이 ZAP.exe 를 직접 호출한다.
Automation Framework plan(YAML)을 manifest 기반으로 생성 -> ZAP 에 넘김.

nuclei_adapter 와 동일 책임:
  manifest 읽기 -> scope 검증 -> 실행 -> raw 저장 -> RunStatus 반환

ZAP 고유:
  - plan.yaml 을 생성해서 runs/<run_id>/raw/zap-plan.yaml 에 기록
  - spider(시간제한) -> passiveScan-wait -> report(traditional-json)
  - active scan 은 scope.active_scan_allowed=False 면 절대 plan 에 넣지 않음
  - 결과: runs/<run_id>/raw/zap-report.json

하지 않는 것: 결과 판단/정규화/점수 (각 후속 계층 책임)
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from core.openapi import enumerate_and_sanitize, fetch_spec
from core.auth import bearer_token, replacer_job


class ZapAdapterError(Exception):
    """ZAP adapter execution or validation error."""


@dataclass(frozen=True)
class ZapRunStatus:
    run_id: str
    target_id: str
    status: str  # success | failed | skipped
    command: list[str]
    return_code: int | None
    plan_file: str
    raw_output_file: str
    stdout_file: str
    stderr_file: str
    started_at: str
    finished_at: str
    duration_seconds: float
    message: str | None = None


class ZapAdapter:
    DEFAULT_TIMEOUT_SECONDS = 1200  # ZAP 은 nuclei 보다 느림 -> 넉넉히
    DEFAULT_SPIDER_MAX_DURATION = 3  # 분

    def __init__(
        self,
        manifest_path: str | Path,
        runs_dir: str | Path = "runs",
        zap_bin: str = r"C:\Program Files\ZAP\Zed Attack Proxy\ZAP.exe",
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.manifest_path = Path(manifest_path)
        self.runs_dir = Path(runs_dir).resolve()  # cwd 가 ZAP 폴더로 바뀌므로 절대경로 고정
        self.zap_bin = zap_bin
        self.timeout_seconds = timeout_seconds

    def run(self, target_id: str | None = None) -> ZapRunStatus:
        started = time.monotonic()
        started_at = self._utc_now()

        manifest = self._load_manifest()
        target = self._select_target(manifest, target_id)
        selected_target_id = str(target["id"])

        run_id = self._build_run_id(selected_target_id)
        raw_dir = self.runs_dir / run_id / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        plan_file = raw_dir / "zap-plan.yaml"
        raw_output_file = raw_dir / "zap-report.json"
        stdout_file = raw_dir / "zap.stdout.log"
        stderr_file = raw_dir / "zap.stderr.log"

        command: list[str] = []

        try:
            self._validate_scope(manifest, target)

            plan = self._build_plan(
                manifest=manifest,
                target=target,
                report_dir=raw_dir,
                report_file=raw_output_file.name,
            )
            plan_file.write_text(
                yaml.safe_dump(plan, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )

            command = [
                self.zap_bin,
                "-cmd",
                "-autorun",
                str(plan_file),
            ]

            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
                cwd=str(Path(self.zap_bin).parent),  # zap.bat 이 jar 를 상대경로로 찾으므로
            )

            stdout_file.write_text(completed.stdout or "", encoding="utf-8")
            stderr_file.write_text(completed.stderr or "", encoding="utf-8")

            finished_at = self._utc_now()
            duration = round(time.monotonic() - started, 3)

            # ZAP 은 baseline 에서 경고 발견 시 비0 코드를 줄 수 있다.
            # report 파일 존재 여부로 성공을 판정 (return code 만으론 부족).
            if raw_output_file.exists() and raw_output_file.stat().st_size > 0:
                status = "success"
                message = None if completed.returncode == 0 else (
                    f"zap exited with code {completed.returncode} but report produced"
                )
            else:
                status = "failed"
                message = (
                    f"zap produced no report (exit code {completed.returncode}); "
                    "check zap.stderr.log"
                )

            return ZapRunStatus(
                run_id=run_id,
                target_id=selected_target_id,
                status=status,
                command=command,
                return_code=completed.returncode,
                plan_file=str(plan_file),
                raw_output_file=str(raw_output_file),
                stdout_file=str(stdout_file),
                stderr_file=str(stderr_file),
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=duration,
                message=message,
            )

        except subprocess.TimeoutExpired as exc:
            finished_at = self._utc_now()
            duration = round(time.monotonic() - started, 3)
            stdout_file.write_text(getattr(exc, "stdout", None) or "", encoding="utf-8")
            stderr_file.write_text(getattr(exc, "stderr", None) or "", encoding="utf-8")
            return self._fail(
                run_id, selected_target_id, command, plan_file, raw_output_file,
                stdout_file, stderr_file, started_at, finished_at, duration,
                f"zap execution timed out after {self.timeout_seconds}s",
            )

        except Exception as exc:
            finished_at = self._utc_now()
            duration = round(time.monotonic() - started, 3)
            return self._fail(
                run_id, selected_target_id, command, plan_file, raw_output_file,
                stdout_file, stderr_file, started_at, finished_at, duration, str(exc),
            )

    # ---------- plan 생성 ----------

    def _build_plan(
        self,
        manifest: dict[str, Any],
        target: dict[str, Any],
        report_dir: Path,
        report_file: str,
    ) -> dict[str, Any]:
        base_url = str(target["base_url"])

        scope = manifest.get("scope", {})
        active_allowed = bool(scope.get("active_scan_allowed", False))

        scan_profiles = manifest.get("scan_profiles", {})
        zap_profile = scan_profiles.get("zap", {}) if isinstance(scan_profiles, dict) else {}
        if not isinstance(zap_profile, dict):
            zap_profile = {}

        spider_max = zap_profile.get("spider_max_duration", self.DEFAULT_SPIDER_MAX_DURATION)
        ajax = bool(zap_profile.get("ajax_spider", False))

        # (A) Bearer auth: 모든 요청에 Authorization 주입 (반드시 1순위)
        auth_job = None
        token, auth_note = bearer_token(manifest, target)
        if token:
            auth_job = replacer_job(token)
        if auth_note:
            print(f"[zap] {auth_note}")

        # (B) OpenAPI: 정제 스펙 import. 스펙 endpoint도 인증 뒤일 수 있어 token 실어 fetch.
        #     실패해도 ZAP 전체는 안 죽이고 spider+passive는 계속 (graceful degrade).
        openapi_job = None
        openapi_src = zap_profile.get("openapi_import")
        if openapi_src and self._is_url_allowed(openapi_src, scope.get("allowed_hosts", [])):
            try:
                result = enumerate_and_sanitize(
                    fetch_spec(openapi_src, token=token),     # <- token 추가
                    scope.get("denied_paths", []),
                    allow_active=active_allowed,
                )
                sanitized_file = report_dir / "openapi-sanitized.json"
                sanitized_file.write_text(json.dumps(result["sanitized"]), encoding="utf-8")
                openapi_job = {"type": "openapi", "parameters": {
                    "apiFile": str(sanitized_file), "targetUrl": base_url, "context": "target"}}
                print(f"[zap] openapi import: {len(result['safe_endpoints'])} safe endpoints, "
                      f"{len(result['denied'])} denied dropped")
            except Exception as exc:
                print(f"[zap] openapi import skipped ({exc}); running spider+passive only")
        # (C) 조립: auth -> openapi -> spider
        jobs: list[dict[str, Any]] = []
        if auth_job:
            jobs.append(auth_job)
        if openapi_job:
            jobs.append(openapi_job)
        jobs.append({
            "type": "spider",
            "parameters": {
                "context": "target",
                "url": base_url,
                "maxDuration": int(spider_max),
            },
        })

        if ajax:
            jobs.append({
                "type": "spiderAjax",
                "parameters": {"context": "target", "url": base_url,
                               "maxDuration": int(spider_max)},
            })

        jobs.append({"type": "passiveScan-wait", "parameters": {}})

        # active scan 은 명시적으로 허용된 경우에만. 기본은 절대 넣지 않음.
        if active_allowed and zap_profile.get("active_scan") is True:
            jobs.append({
                "type": "activeScan",
                "parameters": {"context": "target"},
            })

        jobs.append({
            "type": "report",
            "parameters": {
                "template": "traditional-json",
                "reportDir": str(report_dir),
                "reportFile": report_file,
            },
        })

        return {
            "env": {
                "contexts": [
                    {
                        "name": "target",
                        "urls": [base_url],
                        "includePaths": [],
                        "excludePaths": self._build_exclude_paths(scope, base_url),
                    }
                ],
                "parameters": {
                    "failOnError": True,
                    "progressToStdout": True,
                },
            },
            "jobs": jobs,
        }

    def _build_exclude_paths(self, scope: dict[str, Any], base_url: str) -> list[str]:
        """denied_paths 를 ZAP excludePaths 정규식으로 변환."""
        denied = scope.get("denied_paths", []) or []
        origin = self._origin(base_url)
        patterns: list[str] = []
        for d in denied:
            if not isinstance(d, str) or not d:
                continue
            path = d if d.startswith("/") else f"/{d}"
            # 해당 경로 및 하위 전체 제외
            patterns.append(f"{origin}{path}.*")
        return patterns

    # ---------- scope 검증 (nuclei adapter 와 동일 정책) ----------

    def _validate_scope(self, manifest: dict[str, Any], target: dict[str, Any]) -> None:
        scope = manifest.get("scope", {})
        if not isinstance(scope, dict):
            raise ZapAdapterError("manifest.scope must be an object")

        allowed_hosts = scope.get("allowed_hosts", [])
        if not isinstance(allowed_hosts, list) or not allowed_hosts:
            raise ZapAdapterError("scope.allowed_hosts must contain at least one host")

        self._reject_broad_allowed_hosts(allowed_hosts)

        base_url = target.get("base_url")
        if not isinstance(base_url, str) or not base_url:
            raise ZapAdapterError("target.base_url is required")

        if not self._is_url_allowed(base_url, allowed_hosts):
            raise ZapAdapterError(f"target.base_url is outside allowed_hosts: {base_url}")

        denied_paths = scope.get("denied_paths", []) or []
        if not isinstance(denied_paths, list):
            raise ZapAdapterError("scope.denied_paths must be a list")
        self._reject_denied_target_url(base_url, denied_paths)

        scan_profiles = manifest.get("scan_profiles", {})
        zap_profile = scan_profiles.get("zap", {}) if isinstance(scan_profiles, dict) else {}
        if isinstance(zap_profile, dict) and zap_profile.get("enabled") is False:
            raise ZapAdapterError("zap profile is disabled")

    def _reject_broad_allowed_hosts(self, allowed_hosts: list[Any]) -> None:
        for host in allowed_hosts:
            if not isinstance(host, str):
                raise ZapAdapterError("allowed_hosts entries must be strings")
            normalized = host.strip().lower()
            if normalized in {"http://", "https://", "*", "http://*", "https://*"}:
                raise ZapAdapterError(f"too broad allowed_hosts entry: {host}")
            parsed = urlparse(normalized)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ZapAdapterError(f"allowed_hosts entry must include scheme and host: {host}")

    def _is_url_allowed(self, url: str, allowed_hosts: list[Any]) -> bool:
        target_origin = self._origin(url)
        for allowed in allowed_hosts:
            if isinstance(allowed, str) and target_origin == self._origin(allowed):
                return True
        return False

    def _origin(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ZapAdapterError(f"invalid URL: {url}")
        return f"{parsed.scheme}://{parsed.netloc}".lower()

    def _reject_denied_target_url(self, url: str, denied_paths: list[Any]) -> None:
        parsed = urlparse(url)
        path = parsed.path or "/"
        for denied in denied_paths:
            if not isinstance(denied, str) or not denied:
                continue
            normalized_denied = denied if denied.startswith("/") else f"/{denied}"
            if path == normalized_denied or path.startswith(normalized_denied.rstrip("/") + "/"):
                raise ZapAdapterError(f"target URL path is denied by scope policy: {url}")

    # ---------- 공통 ----------

    def _load_manifest(self) -> dict[str, Any]:
        if not self.manifest_path.exists():
            raise ZapAdapterError(f"manifest file not found: {self.manifest_path}")
        with self.manifest_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
        if not isinstance(data, dict):
            raise ZapAdapterError("manifest must be a YAML object")
        return data

    def _select_target(self, manifest: dict[str, Any], target_id: str | None) -> dict[str, Any]:
        targets = manifest.get("targets")
        if not isinstance(targets, list) or not targets:
            raise ZapAdapterError("manifest.targets must contain at least one target")
        if target_id is None:
            if not isinstance(targets[0], dict):
                raise ZapAdapterError("target entry must be an object")
            return targets[0]
        for target in targets:
            if isinstance(target, dict) and target.get("id") == target_id:
                return target
        raise ZapAdapterError(f"target not found: {target_id}")

    def _build_run_id(self, target_id: str) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in target_id)
        return f"{timestamp}_{safe}_zap"

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _fail(self, run_id, target_id, command, plan_file, raw_output_file,
              stdout_file, stderr_file, started_at, finished_at, duration, message) -> ZapRunStatus:
        return ZapRunStatus(
            run_id=run_id, target_id=target_id, status="failed",
            command=command, return_code=None,
            plan_file=str(plan_file), raw_output_file=str(raw_output_file),
            stdout_file=str(stdout_file), stderr_file=str(stderr_file),
            started_at=started_at, finished_at=finished_at,
            duration_seconds=duration, message=message,
        )


def run_zap_from_manifest(
    manifest_path: str | Path,
    target_id: str | None = None,
    runs_dir: str | Path = "runs",
    zap_bin: str = r"C:\Program Files\ZAP\Zed Attack Proxy\ZAP.exe",
) -> dict[str, Any]:
    adapter = ZapAdapter(manifest_path=manifest_path, runs_dir=runs_dir, zap_bin=zap_bin)
    return asdict(adapter.run(target_id=target_id))
