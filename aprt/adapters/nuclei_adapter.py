# aprt/adapters/nuclei_adapter.py

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


class NucleiAdapterError(Exception):
    """Nuclei adapter execution or validation error."""


@dataclass(frozen=True)
class NucleiRunStatus:
    run_id: str
    target_id: str
    status: str  # success | failed | skipped
    command: list[str]
    return_code: int | None
    raw_output_file: str
    stdout_file: str
    stderr_file: str
    started_at: str
    finished_at: str
    duration_seconds: float
    message: str | None = None


class NucleiAdapter:
    DEFAULT_TIMEOUT_SECONDS = 600

    def __init__(
        self,
        manifest_path: str | Path,
        runs_dir: str | Path = "runs",
        nuclei_bin: str = "nuclei",
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.manifest_path = Path(manifest_path)
        self.runs_dir = Path(runs_dir)
        self.nuclei_bin = nuclei_bin
        self.timeout_seconds = timeout_seconds

    def run(self, target_id: str | None = None) -> NucleiRunStatus:
        started = time.monotonic()
        started_at = self._utc_now()

        manifest = self._load_manifest()
        target = self._select_target(manifest, target_id)
        selected_target_id = str(target["id"])

        run_id = self._build_run_id(selected_target_id)
        run_dir = self.runs_dir / run_id
        raw_dir = run_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        raw_output_file = raw_dir / "nuclei.jsonl"
        stdout_file = raw_dir / "nuclei.stdout.log"
        stderr_file = raw_dir / "nuclei.stderr.log"

        command: list[str] = []

        try:
            self._validate_scope(manifest, target)
            command = self._build_command(
                manifest=manifest,
                target=target,
                output_file=raw_output_file,
            )

            raw_output_file.touch(exist_ok=True)

            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
            )

            stdout_file.write_text(completed.stdout or "", encoding="utf-8")
            stderr_file.write_text(completed.stderr or "", encoding="utf-8")

            finished_at = self._utc_now()
            duration = round(time.monotonic() - started, 3)

            if completed.returncode == 0:
                status = "success"
                message = None
            else:
                status = "failed"
                message = f"nuclei exited with return code {completed.returncode}"

            return NucleiRunStatus(
                run_id=run_id,
                target_id=selected_target_id,
                status=status,
                command=command,
                return_code=completed.returncode,
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
            stdout_file.write_text(exc.stdout or "", encoding="utf-8")
            stderr_file.write_text(exc.stderr or "", encoding="utf-8")
            return NucleiRunStatus(
                run_id=run_id,
                target_id=selected_target_id,
                status="failed",
                command=command,
                return_code=None,
                raw_output_file=str(raw_output_file),
                stdout_file=str(stdout_file),
                stderr_file=str(stderr_file),
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=duration,
                message=f"nuclei execution timed out after {self.timeout_seconds} seconds",
            )

        except Exception as exc:
            finished_at = self._utc_now()
            duration = round(time.monotonic() - started, 3)
            return NucleiRunStatus(
                run_id=run_id,
                target_id=selected_target_id,
                status="failed",
                command=command,
                return_code=None,
                raw_output_file=str(raw_output_file),
                stdout_file=str(stdout_file),
                stderr_file=str(stderr_file),
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=duration,
                message=str(exc),
            )

    def _load_manifest(self) -> dict[str, Any]:
        if not self.manifest_path.exists():
            raise NucleiAdapterError(f"manifest file not found: {self.manifest_path}")
        with self.manifest_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
        if not isinstance(data, dict):
            raise NucleiAdapterError("manifest must be a YAML object")
        return data

    def _select_target(self, manifest: dict[str, Any], target_id: str | None) -> dict[str, Any]:
        targets = manifest.get("targets")
        if not isinstance(targets, list) or not targets:
            raise NucleiAdapterError("manifest.targets must contain at least one target")
        if target_id is None:
            target = targets[0]
            if not isinstance(target, dict):
                raise NucleiAdapterError("target entry must be an object")
            return target
        for target in targets:
            if isinstance(target, dict) and target.get("id") == target_id:
                return target
        raise NucleiAdapterError(f"target not found: {target_id}")

    def _validate_scope(self, manifest: dict[str, Any], target: dict[str, Any]) -> None:
        scope = manifest.get("scope", {})
        if not isinstance(scope, dict):
            raise NucleiAdapterError("manifest.scope must be an object")

        allowed_hosts = scope.get("allowed_hosts", [])
        if not isinstance(allowed_hosts, list) or not allowed_hosts:
            raise NucleiAdapterError("scope.allowed_hosts must contain at least one host")

        self._reject_broad_allowed_hosts(allowed_hosts)

        base_url = target.get("base_url")
        if not isinstance(base_url, str) or not base_url:
            raise NucleiAdapterError("target.base_url is required")

        if not self._is_url_allowed(base_url, allowed_hosts):
            raise NucleiAdapterError(f"target.base_url is outside allowed_hosts: {base_url}")

        openapi_url = target.get("openapi_url")
        if isinstance(openapi_url, str) and openapi_url:
            if not self._is_url_allowed(openapi_url, allowed_hosts):
                raise NucleiAdapterError(f"target.openapi_url is outside allowed_hosts: {openapi_url}")

        denied_paths = scope.get("denied_paths", [])
        if denied_paths is None:
            denied_paths = []
        if not isinstance(denied_paths, list):
            raise NucleiAdapterError("scope.denied_paths must be a list")

        self._reject_denied_target_url(base_url, denied_paths)
        if isinstance(openapi_url, str) and openapi_url:
            self._reject_denied_target_url(openapi_url, denied_paths)

        scan_profiles = manifest.get("scan_profiles", {})
        nuclei_profile = scan_profiles.get("nuclei", {}) if isinstance(scan_profiles, dict) else {}
        if isinstance(nuclei_profile, dict):
            if nuclei_profile.get("enabled") is False:
                raise NucleiAdapterError("nuclei profile is disabled")

    def _build_command(self, manifest: dict[str, Any], target: dict[str, Any], output_file: Path) -> list[str]:
        base_url = str(target["base_url"])
        scan_profiles = manifest.get("scan_profiles", {})
        nuclei_profile = scan_profiles.get("nuclei", {}) if isinstance(scan_profiles, dict) else {}
        if not isinstance(nuclei_profile, dict):
            nuclei_profile = {}

        command = [
            self.nuclei_bin,
            "-u", base_url,
            "-jsonl",
            "-o", str(output_file),
            "-silent",
            "-no-color",
        ]

        severities = nuclei_profile.get("severity")
        if isinstance(severities, list) and severities:
            command.extend(["-severity", ",".join(str(item) for item in severities)])

        exclude_tags = nuclei_profile.get("exclude_tags")
        if isinstance(exclude_tags, list) and exclude_tags:
            command.extend(["-exclude-tags", ",".join(str(item) for item in exclude_tags)])

        tags = nuclei_profile.get("tags")
        if isinstance(tags, list) and tags:
            command.extend(["-tags", ",".join(str(t) for t in tags)])
        elif isinstance(tags, str) and tags:
            command.extend(["-tags", tags])

        templates = nuclei_profile.get("templates")
        if isinstance(templates, list) and templates:
            for template in templates:
                command.extend(["-templates", str(template)])
        elif isinstance(templates, str) and templates:
            command.extend(["-templates", templates])

        rate_limit = nuclei_profile.get("rate_limit")
        if isinstance(rate_limit, int) and rate_limit > 0:
            command.extend(["-rate-limit", str(rate_limit)])

        concurrency = nuclei_profile.get("concurrency")
        if isinstance(concurrency, int) and concurrency > 0:
            command.extend(["-concurrency", str(concurrency)])

        request_timeout = nuclei_profile.get("request_timeout")
        if isinstance(request_timeout, int) and request_timeout > 0:
            command.extend(["-timeout", str(request_timeout)])

        auth_header = self._build_auth_header(manifest, target)
        if auth_header is not None:
            command.extend(["-H", auth_header])

        return command

    def _build_auth_header(self, manifest: dict[str, Any], target: dict[str, Any]) -> str | None:
        auth_profile_id = target.get("auth_profile")
        if not auth_profile_id:
            return None

        auth_profiles = manifest.get("auth_profiles", [])
        if not isinstance(auth_profiles, list):
            raise NucleiAdapterError("manifest.auth_profiles must be a list")

        profile = None
        for item in auth_profiles:
            if isinstance(item, dict) and item.get("id") == auth_profile_id:
                profile = item
                break

        if profile is None:
            raise NucleiAdapterError(f"auth profile not found: {auth_profile_id}")

        auth_type = profile.get("type")
        if auth_type != "bearer":
            raise NucleiAdapterError(f"unsupported auth profile type: {auth_type}")

        token_env = profile.get("token_env")
        if not isinstance(token_env, str) or not token_env:  # <- 수정: 'ㅑ' 제거
            raise NucleiAdapterError("bearer auth profile requires token_env")

        token = os.getenv(token_env)
        if not token:
            raise NucleiAdapterError(f"environment variable is not set: {token_env}")

        return f"Authorization: Bearer {token}"

    def _reject_broad_allowed_hosts(self, allowed_hosts: list[Any]) -> None:
        for host in allowed_hosts:
            if not isinstance(host, str):
                raise NucleiAdapterError("allowed_hosts entries must be strings")
            normalized = host.strip().lower()
            if normalized in {"http://", "https://", "*", "http://*", "https://*"}:
                raise NucleiAdapterError(f"too broad allowed_hosts entry is not allowed: {host}")
            parsed = urlparse(normalized)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise NucleiAdapterError(f"allowed_hosts entry must include scheme and host: {host}")

    def _is_url_allowed(self, url: str, allowed_hosts: list[Any]) -> bool:
        target_origin = self._origin(url)
        for allowed in allowed_hosts:
            if not isinstance(allowed, str):
                continue
            if target_origin == self._origin(allowed):
                return True
        return False

    def _origin(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise NucleiAdapterError(f"invalid URL: {url}")
        return f"{parsed.scheme}://{parsed.netloc}".lower()

    def _reject_denied_target_url(self, url: str, denied_paths: list[Any]) -> None:
        parsed = urlparse(url)
        path = parsed.path or "/"
        for denied in denied_paths:
            if not isinstance(denied, str) or not denied:
                continue
            normalized_denied = denied if denied.startswith("/") else f"/{denied}"
            if path == normalized_denied or path.startswith(normalized_denied.rstrip("/") + "/"):
                raise NucleiAdapterError(f"target URL path is denied by scope policy: {url}")

    def _build_run_id(self, target_id: str) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_target_id = "".join(
            ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in target_id
        )
        return f"{timestamp}_{safe_target_id}_nuclei"

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


def run_nuclei_from_manifest(
    manifest_path: str | Path,
    target_id: str | None = None,
    runs_dir: str | Path = "runs",
) -> dict[str, Any]:
    adapter = NucleiAdapter(manifest_path=manifest_path, runs_dir=runs_dir)
    status = adapter.run(target_id=target_id)
    return asdict(status)
