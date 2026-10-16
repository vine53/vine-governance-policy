#!/usr/bin/env python3
"""GitHub 標準 attestation 的受保護 host 驗證 library。

Purpose: 在既有 pre-merge receipt 入口驗證外部 admission，不能產生 GO。
Existing capability checked: gh attestation verify、pre-merge-gate-receipt.py；沿用其 Sigstore 驗證。
Owner: governance / pre-merge-gate-receipt.py。
Runtime: Python 3.10+ stdlib、受保護且固定 digest 的 GitHub CLI。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import tempfile
import time

REPOSITORY = "vine53/vine-governance-policy"
REPOSITORY_ID = "1421871068"
ISSUER = "https://token.actions.githubusercontent.com"
MAX_FILE = 1024 * 1024
MAX_BUNDLE = 16 * MAX_FILE
MAX_CONFIG = 65536
MAX_OUTPUT = MAX_FILE
TIMEOUT = 20
ENROLLMENT_NAME = "host-enrollment.json"
INVOCATION_NAME = "host-invocation.json"
ENROLLMENT_KEYS = frozenset((
    "contract", "activation", "repo", "repo_id", "signer_workflow", "workflow_sha",
    "source_sha", "cert_identity", "issuer", "policy_release_sha256", "gh_path",
    "gh_sha256", "issued_at", "expires_at", "revocation_epoch",
    "revocation_checked_at", "revocation_expires_at", "credential_reference",
))
SCOPE_KEYS = frozenset(("mode", "diff_ref", "paths_sha256", "count"))
REQUEST_KEYS = frozenset((
    "contract", "purpose", "invocation_id", "repository", "branch", "base_sha",
    "head_sha", "scope", "policy_release_sha256", "workflow_sha", "issued_at",
    "expires_at", "credential_required",
))
POLICY_KEYS = frozenset(("contract", "purpose", "policy_release_sha256", "workflow_sha",
                         "source_sha", "issued_at", "expires_at", "revocation_epoch"))
ADMISSION_KEYS = (REQUEST_KEYS - {"credential_required"}) | frozenset((
    "run_id", "dispatches_sha256", "result_sha256", "revocation_epoch",
))


class Rejected(ValueError):
    """不完整或不可信證據，必須停止而不能降級。"""


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected("nonfinite_json")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Rejected("invalid_json") from exc


def exact(value, keys, reason):
    require(isinstance(value, dict) and set(value) == keys, reason)


def sha(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def timestamp(value):
    require(isinstance(value, str) and value.endswith("Z"), "invalid_timestamp")
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00").timestamp()
    except (ValueError, OverflowError) as exc:
        raise Rejected("invalid_timestamp") from exc


def window(value, now):
    start, end = timestamp(value["issued_at"]), timestamp(value["expires_at"])
    require(start <= now < end and end - start <= 3600, "expired_or_invalid_window")
    return start, end


def safe_path(path, *, protected=False, directory=False):
    p = Path(path)
    require(p.is_absolute() and p == p.resolve(strict=True), "noncanonical_or_symlink_path")
    for part in (p, *p.parents):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode), "symlink_path")
        if protected:
            require(info.st_uid == 0 and not info.st_mode & 0o022, "unprotected_host_path")
    info = p.stat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "invalid_file_type")
    return p


def capture(path, limit, *, protected=False):
    p = safe_path(path, protected=protected)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "file_size_limit")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(data) <= limit and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "file_capture_drift")
    return data


def protected_host_context(module_file=__file__):
    """只從已安裝 module 旁取 host policy；待審 checkout 沒有可用入口。"""
    module = safe_path(module_file, protected=True)
    root = module.parent
    enrollment = strict_json(capture(root / ENROLLMENT_NAME, MAX_CONFIG, protected=True))
    request = strict_json(capture(root / INVOCATION_NAME, MAX_CONFIG, protected=True))
    return {"module": str(module), "enrollment": enrollment, "request": request}


def validate_host_context(context):
    exact(context, {"module", "enrollment", "request"}, "host_context_schema")
    module = safe_path(context["module"], protected=True)
    # 同 uid、只讀父目錄仍不足以把 application checkout 變成可信 host。
    require(not any((p / ".git").exists() for p in module.parents), "host_inside_checkout")
    enrollment = strict_json(capture(module.parent / ENROLLMENT_NAME, MAX_CONFIG, protected=True))
    request = strict_json(capture(module.parent / INVOCATION_NAME, MAX_CONFIG, protected=True))
    require(enrollment == context["enrollment"] and request == context["request"], "host_context_drift")


def execute_gh(argv, env, timeout, output_limit):
    """限制時間與實際讀取量，不能將 CLI 的無界輸出載入記憶體。"""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env, cwd="/")
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "gh_timeout")
                for key, _ in selector.select(min(remaining, 0.25)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    output.extend(chunk)
                    require(len(output) <= output_limit, "gh_output_limit")
            code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        return code, bytes(output)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()


def validate_enrollment(e, now):
    exact(e, ENROLLMENT_KEYS, "enrollment_schema")
    require(e["contract"] == "premerge-github-enrollment/v1", "enrollment_contract")
    require(e["activation"] is True, "trust_anchor_inactive")
    require(e["repo"] == REPOSITORY and e["repo_id"] == REPOSITORY_ID, "enrollment_repository")
    require(e["issuer"] == ISSUER, "enrollment_issuer")
    require(isinstance(e["signer_workflow"], str) and re.fullmatch(
        re.escape(REPOSITORY) + r"/\.github/workflows/[A-Za-z0-9_-]+\.ya?ml", e["signer_workflow"]),
        "enrollment_workflow")
    require(all(sha(e[k], 40) for k in ("workflow_sha", "source_sha")), "enrollment_source_digest")
    require(all(sha(e[k]) for k in ("policy_release_sha256", "gh_sha256")), "enrollment_digest")
    identity_prefix = "https://github.com/" + e["signer_workflow"] + "@"
    require(isinstance(e["cert_identity"], str) and e["cert_identity"].startswith(identity_prefix)
            and re.fullmatch(r"(?:refs/(?:heads|tags)/[A-Za-z0-9_./-]+|[0-9a-f]{40})",
                             e["cert_identity"][len(identity_prefix):]), "enrollment_certificate_identity")
    window(e, now)
    require(type(e["revocation_epoch"]) is int and e["revocation_epoch"] >= 0, "revocation_epoch")
    checked, expires = timestamp(e["revocation_checked_at"]), timestamp(e["revocation_expires_at"])
    require(checked <= now < expires and expires - checked <= 3600, "revocation_stale")
    require(e["credential_reference"] is None or (isinstance(e["credential_reference"], str)
            and re.fullmatch(r"[A-Za-z0-9_./:-]{1,256}", e["credential_reference"])), "credential_reference")


def validate_request(r, e, purpose, now):
    exact(r, REQUEST_KEYS, "host_invocation_schema")
    exact(r["scope"], SCOPE_KEYS, "scope_schema")
    require(r["contract"] == "premerge-host-invocation/v1" and r["purpose"] == purpose,
            "host_invocation_contract")
    require(isinstance(r["invocation_id"], str) and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", r["invocation_id"]),
            "host_invocation_nonce")
    require(isinstance(r["repository"], str) and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", r["repository"]),
            "host_repository")
    require(isinstance(r["branch"], str) and 0 < len(r["branch"]) <= 256, "host_branch")
    require(sha(r["base_sha"], 40) and sha(r["head_sha"], 40), "host_ref")
    validate_scope(r["scope"], r["branch"])
    require(r["policy_release_sha256"] == e["policy_release_sha256"]
            and r["workflow_sha"] == e["workflow_sha"], "host_policy_binding")
    require(type(r["credential_required"]) is bool, "credential_required_schema")
    require(not r["credential_required"] or e["credential_reference"] is not None,
            "private_policy_credential_missing")
    window(r, now)


def validate_scope(scope, branch):
    """沿用 snapshot 的 base...branch；base 可為既有 producer 解析的 Git ref。"""
    exact(scope, SCOPE_KEYS, "scope_schema")
    require(scope["mode"] in ("service", "repository") and sha(scope["paths_sha256"])
            and type(scope["count"]) is int and scope["count"] >= 0
            and isinstance(scope["diff_ref"], str) and 0 < len(scope["diff_ref"]) <= 1024, "scope_value")
    refs = scope["diff_ref"].split("...")
    require(len(refs) == 2 and bool(refs[0]) and refs[1] == branch
            and not any(char.isspace() or ord(char) < 32 or ord(char) == 127
                        for char in scope["diff_ref"]), "scope_diff_ref")


def validate_artifact(a, e, r, purpose, now):
    require(purpose in ("policy_release", "review_admission"), "unsupported_purpose")
    exact(a, POLICY_KEYS if purpose == "policy_release" else ADMISSION_KEYS, "artifact_schema")
    require(a["purpose"] == purpose and a["contract"] == (
        "premerge-policy-release/v1" if purpose == "policy_release" else "premerge-github-admission/v1"),
        "artifact_contract")
    require(a["policy_release_sha256"] == e["policy_release_sha256"]
            and a["workflow_sha"] == e["workflow_sha"]
            and type(a["revocation_epoch"]) is int
            and a["revocation_epoch"] == e["revocation_epoch"], "artifact_policy_binding")
    start, end = window(a, now)
    if purpose == "policy_release":
        # A 是可重驗的 immutable release；不繫結到之後每次新 host invocation。
        require(a["source_sha"] == e["source_sha"], "artifact_source_digest")
    else:
        require(timestamp(r["issued_at"]) <= start and end <= timestamp(r["expires_at"]), "artifact_invocation_window")
        validate_scope(a["scope"], a["branch"])
        for key in ("invocation_id", "repository", "branch", "base_sha", "head_sha", "scope"):
            require(a[key] == r[key], "artifact_" + key + "_mismatch")
        require(isinstance(a["run_id"], str) and re.fullmatch(r"[1-9][0-9]{0,24}", a["run_id"]), "artifact_run_id")
        require(sha(a["dispatches_sha256"]) and sha(a["result_sha256"]), "artifact_result_digest")


def validate_verified_output(data, artifact_digest, now, signed_window):
    results = strict_json(data)
    require(isinstance(results, list) and 0 < len(results) <= 16, "gh_output_shape")
    for item in results:
        require(isinstance(item, dict) and isinstance(item.get("verificationResult"), dict), "gh_result_missing")
        result = item["verificationResult"]
        signature = result.get("signature")
        require(isinstance(signature, dict) and isinstance(signature.get("certificate"), dict), "gh_certificate_missing")
        require(signature["certificate"].get("sourceRepositoryIdentifier") == REPOSITORY_ID,
                "gh_certificate_repository_mismatch")
        timestamps = result.get("verifiedTimestamps")
        require(isinstance(timestamps, list) and 0 < len(timestamps) <= 16, "gh_verified_timestamp_missing")
        for entry in timestamps:
            require(isinstance(entry, dict) and isinstance(entry.get("type"), str), "gh_verified_timestamp_invalid")
            witnessed = timestamp(entry.get("timestamp"))
            # 尚無 clock-skew 授權契約：不能放寬未來或窗口外的已驗證時間。
            require(signed_window[0] <= witnessed < signed_window[1] and witnessed <= now,
                    "gh_verified_timestamp_outside_window")
        statement = result.get("statement")
        require(isinstance(statement, dict) and statement.get("predicateType") == "https://slsa.dev/provenance/v1",
                "gh_statement_shape")
        subjects = statement.get("subject")
        require(isinstance(subjects, list) and len(subjects) == 1 and isinstance(subjects[0], dict), "gh_subject_shape")
        require(subjects[0].get("digest") == {"sha256": artifact_digest}, "gh_artifact_digest_mismatch")


def verify_admission(*, host_context, artifact_path, bundle_path, purpose, now=None, executor=None):
    """回傳 evidence 狀態，永不產生 gate PASS／GO；DI 僅供函式 fixture。"""
    try:
        current = time.time() if now is None else now
        validate_host_context(host_context)
        enrollment, request = host_context["enrollment"], host_context["request"]
        validate_enrollment(enrollment, current)
        validate_request(request, enrollment, purpose, current)
        gh = safe_path(enrollment["gh_path"], protected=True)
        gh_bytes = capture(gh, 128 * MAX_FILE, protected=True)
        require(hashlib.sha256(gh_bytes).hexdigest() == enrollment["gh_sha256"], "gh_executable_digest")
        artifact = capture(artifact_path, MAX_FILE)
        bundle = capture(bundle_path, MAX_BUNDLE)
        payload = strict_json(artifact)
        wire = strict_json(bundle)
        require(isinstance(wire, dict) and set(wire) in (
            {"mediaType", "verificationMaterial", "dsseEnvelope"},
            {"mediaType", "verificationMaterial", "messageSignature"}), "gh_bundle_shape")
        validate_artifact(payload, enrollment, request, purpose, current)
        with tempfile.TemporaryDirectory(prefix="premerge-attestation-") as folder:
            scratch = Path(folder).resolve()
            artifact_copy, bundle_copy = scratch / "artifact.json", scratch / "bundle.json"
            for path, data in ((artifact_copy, artifact), (bundle_copy, bundle)):
                path.write_bytes(data)
                path.chmod(0o400)
            argv = [str(gh), "attestation", "verify", str(artifact_copy), "--bundle", str(bundle_copy),
                    "--repo", REPOSITORY, "--signer-workflow", enrollment["signer_workflow"],
                    "--signer-digest", enrollment["workflow_sha"], "--source-digest", enrollment["source_sha"],
                    "--cert-identity", enrollment["cert_identity"], "--cert-oidc-issuer", ISSUER,
                    "--deny-self-hosted-runners", "--predicate-type", "https://slsa.dev/provenance/v1",
                    "--format", "json"]
            env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch), "GH_CONFIG_DIR": str(scratch / "gh"),
                   "LANG": "C.UTF-8", "GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1"}
            code, output = (executor or execute_gh)(argv, env, TIMEOUT, MAX_OUTPUT)
            require(type(code) is int and code == 0, "gh_verification_failed")
            require(isinstance(output, bytes) and len(output) <= MAX_OUTPUT, "gh_output_limit")
            require(artifact_copy.read_bytes() == artifact and bundle_copy.read_bytes() == bundle, "verification_capture_drift")
            require(capture(gh, 128 * MAX_FILE, protected=True) == gh_bytes, "gh_executable_drift")
            signed_window = (timestamp(payload["issued_at"]), timestamp(payload["expires_at"]))
            if purpose == "review_admission":
                signed_window = (max(signed_window[0], timestamp(request["issued_at"])),
                                 min(signed_window[1], timestamp(request["expires_at"])))
            validate_verified_output(output, hashlib.sha256(artifact).hexdigest(), current, signed_window)
        validate_host_context(host_context)
        return {"status": "VERIFIED_POLICY" if purpose == "policy_release" else "VERIFIED_ADMISSION_EVIDENCE",
                "purpose": purpose, "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
                "invocation_id": request["invocation_id"], "gate_authorized": False,
                "next_action": "須另驗完整 review GO 與既有 owner authorization；本結果不能解鎖整合。"}
    except (Rejected, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        return {"status": "BLOCKED", "reason": str(exc) if isinstance(exc, Rejected) else "attestation_evidence_unavailable",
                "gate_authorized": False, "next_action": "由外部 control plane 補齊受保護 enrollment／證據，不使用 candidate 自證。"}
