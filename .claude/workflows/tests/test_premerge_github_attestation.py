#!/usr/bin/env python3
"""Purpose: 以隔離合成資料驗證 GH admission 契約，無網路／provider。

Existing capability checked: unittest、generic GH attestation library；只用 function DI。
Owner: governance；Runtime: Python 3.10+ stdlib。
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "scripts/governance/lib/premerge_github_attestation.py"
SPEC = importlib.util.spec_from_file_location("premerge_github_attestation", MODULE)
lib = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lib)
NOW = lib.timestamp("2026-10-16T10:10:00Z")


class AdmissionContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="premerge-admission-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.artifact = self.root / "artifact.json"
        self.bundle = self.root / "bundle.json"
        # 真實受保護系統檔只讀取 digest；executor DI 不執行它。
        self.gh = Path("/usr/bin/true").resolve()
        self.enrollment = dict(contract="premerge-github-enrollment/v1", activation=True,
            repo=lib.REPOSITORY, repo_id=lib.REPOSITORY_ID,
            signer_workflow=lib.REPOSITORY + "/.github/workflows/admit.yml",
            workflow_sha="a" * 40, source_sha="b" * 40,
            cert_identity="https://github.com/" + lib.REPOSITORY + "/.github/workflows/admit.yml@refs/heads/main",
            issuer=lib.ISSUER, policy_release_sha256="c" * 64,
            gh_path=str(self.gh), gh_sha256=hashlib.sha256(self.gh.read_bytes()).hexdigest(),
            issued_at="2026-10-16T10:00:00Z", expires_at="2026-10-16T10:30:00Z",
            revocation_epoch=3, revocation_checked_at="2026-10-16T10:00:00Z",
            revocation_expires_at="2026-10-16T10:30:00Z", credential_reference=None)
        self.request = dict(contract="premerge-host-invocation/v1", purpose="review_admission",
            invocation_id="n" * 32, repository="example/private-app", branch="codex/fixture",
            base_sha="d" * 40, head_sha="e" * 40,
            scope=dict(mode="repository", diff_ref="origin/main...codex/fixture", paths_sha256="f" * 64, count=2),
            policy_release_sha256="c" * 64, workflow_sha="a" * 40,
            issued_at="2026-10-16T10:00:00Z", expires_at="2026-10-16T10:30:00Z",
            credential_required=False)
        self.payload = {k: v for k, v in copy.deepcopy(self.request).items() if k != "credential_required"}
        self.payload.update(contract="premerge-github-admission/v1", run_id="123", dispatches_sha256="1" * 64,
                            result_sha256="2" * 64, revocation_epoch=3)
        self.bundle.write_text(json.dumps(dict(mediaType="application/vnd.dev.sigstore.bundle.v0.3+json",
                                              verificationMaterial={}, dsseEnvelope={})))
        self.calls = []

    def context(self):
        return dict(module=str(MODULE), enrollment=self.enrollment, request=self.request)

    def response(self, digest):
        return [dict(verificationResult=dict(
            signature=dict(certificate=dict(sourceRepositoryIdentifier=lib.REPOSITORY_ID)),
            verifiedTimestamps=[dict(type="tlog", timestamp="2026-10-16T10:05:00Z")],
            statement=dict(predicateType="https://slsa.dev/provenance/v1",
                           subject=[dict(name="artifact.json", digest=dict(sha256=digest))], predicate={}))) ]

    def executor(self, argv, env, timeout, output_limit):
        self.calls.append((argv, env, timeout, output_limit))
        captured = Path(argv[3]).read_bytes()
        self.assertNotEqual(Path(argv[3]), self.artifact)
        self.assertNotIn("GH_TOKEN", env)
        self.assertEqual(env["PATH"], "/usr/bin:/bin")
        self.assertEqual(captured, self.artifact.read_bytes())
        return 0, json.dumps(self.response(hashlib.sha256(captured).hexdigest())).encode()

    def verify(self, executor=None, guard=True):
        self.artifact.write_text(json.dumps(self.payload))
        # 只在函式 fixture 模擬已安裝 host；production CLI 沒有這個選項。
        with patch.object(lib, "validate_host_context", return_value=None) if guard else patch.object(
                lib, "validate_host_context", wraps=lib.validate_host_context):
            return lib.verify_admission(host_context=self.context(), artifact_path=self.artifact,
                bundle_path=self.bundle, purpose=self.request["purpose"], now=NOW,
                executor=executor or self.executor)

    def blocked(self, result):
        self.assertEqual(result["status"], "BLOCKED", result)
        self.assertIs(result["gate_authorized"], False)

    def test_evidence_is_not_go_and_all_identity_flags_are_pinned(self):
        result = self.verify()
        self.assertEqual(result["status"], "VERIFIED_ADMISSION_EVIDENCE", result)
        self.assertFalse(result["gate_authorized"])
        argv = self.calls[0][0]
        for flag, value in {"--repo": lib.REPOSITORY, "--signer-workflow": self.enrollment["signer_workflow"],
                "--signer-digest": "a" * 40, "--source-digest": "b" * 40,
                "--cert-identity": self.enrollment["cert_identity"], "--cert-oidc-issuer": lib.ISSUER}.items():
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertIn("--deny-self-hosted-runners", argv)

    def test_policy_release_never_becomes_review_go(self):
        self.request["purpose"] = "policy_release"
        self.payload = {k: self.enrollment[k] for k in ("policy_release_sha256", "workflow_sha", "source_sha",
                        "issued_at", "expires_at", "revocation_epoch")}
        self.payload.update(contract="premerge-policy-release/v1", purpose="policy_release")
        result = self.verify()
        self.assertEqual(result["status"], "VERIFIED_POLICY", result)
        self.assertFalse(result["gate_authorized"])

    def test_existing_policy_release_reverification_predates_current_invocation(self):
        self.request["purpose"] = "policy_release"
        self.payload = {k: self.enrollment[k] for k in ("policy_release_sha256", "workflow_sha", "source_sha",
                        "issued_at", "expires_at", "revocation_epoch")}
        self.payload.update(contract="premerge-policy-release/v1", purpose="policy_release",
                            issued_at="2026-10-16T09:45:00Z", expires_at="2026-10-16T10:15:00Z")
        def fake(argv, *args):
            entries = self.response(hashlib.sha256(Path(argv[3]).read_bytes()).hexdigest())
            entries[0]["verificationResult"]["verifiedTimestamps"][0]["timestamp"] = "2026-10-16T09:50:00Z"
            return 0, json.dumps(entries).encode()
        result = self.verify(fake)
        self.assertEqual(result["status"], "VERIFIED_POLICY", result)
        self.assertFalse(result["gate_authorized"])
        # 相同舊 release 不能換 purpose 當成當次 review admission。
        self.request["purpose"] = "review_admission"
        self.blocked(self.verify(fake))

    def test_inactive_or_missing_private_credential_never_invokes_gh(self):
        for key, value in (("activation", False), ("repo_id", "1"), ("issuer", "https://evil.invalid"),
                           ("workflow_sha", "bad"), ("extra", True)):
            with self.subTest(key=key), patch.dict(self.enrollment, {key: value}):
                self.blocked(self.verify())
        self.request["credential_required"] = True
        self.blocked(self.verify())
        self.assertEqual(self.calls, [])

    def test_host_scope_nonce_and_binding_drift(self):
        for key, value in (("invocation_id", "x" * 32), ("repository", "other/repo"), ("branch", "main"),
                ("base_sha", "0" * 40), ("head_sha", "0" * 40), ("workflow_sha", "0" * 40),
                ("policy_release_sha256", "0" * 64), ("revocation_epoch", 4), ("purpose", "policy_release")):
            with self.subTest(key=key), patch.dict(self.payload, {key: value}):
                self.blocked(self.verify())
        for key, value in (("count", 3), ("paths_sha256", "0" * 64), ("diff_ref", "HEAD"), ("extra", True)):
            with self.subTest(scope=key), patch.dict(self.payload["scope"], {key: value}):
                self.blocked(self.verify())
        self.assertEqual(self.calls, [])

    def test_expiry_revocation_and_unknown_fields(self):
        for record, key, value in ((self.enrollment, "revocation_expires_at", "2026-10-16T10:01:00Z"),
                (self.enrollment, "expires_at", "2026-10-16T10:01:00Z"),
                (self.request, "expires_at", "2026-10-16T10:01:00Z"),
                (self.payload, "issued_at", "2026-10-16T10:20:00Z"),
                (self.payload, "extra", 1), (self.request, "extra", 1)):
            with self.subTest(key=key), patch.dict(record, {key: value}):
                self.blocked(self.verify())
        self.assertEqual(self.calls, [])

    def test_both_scope_records_reject_invalid_values_before_equality(self):
        for key, value in (("count", -1), ("count", True), ("count", 1.5),
                ("paths_sha256", "a" * 63), ("paths_sha256", "g" * 64),
                ("paths_sha256", "A" * 64), ("mode", "all"),
                ("diff_ref", "origin/main..codex/fixture"), ("diff_ref", "...codex/fixture"),
                ("diff_ref", "origin/main...other"), ("diff_ref", "origin/main ...codex/fixture")):
            for record in (self.request, self.payload):
                with self.subTest(record=record["contract"], key=key, value=value), patch.dict(record["scope"], {key: value}):
                    self.blocked(self.verify())
            with self.subTest(equal_invalid=key, value=value), patch.dict(self.request["scope"], {key: value}), patch.dict(self.payload["scope"], {key: value}):
                self.blocked(self.verify())
        self.assertEqual(self.calls, [])

    def test_verified_timestamps_must_be_inside_host_and_artifact_windows(self):
        for witnessed, artifact_start, artifact_end in (
                ("2025-10-16T10:05:00Z", "2026-10-16T10:00:00Z", "2026-10-16T10:30:00Z"),
                ("2026-10-16T09:59:59Z", "2026-10-16T10:00:00Z", "2026-10-16T10:30:00Z"),
                ("2026-10-16T10:04:59Z", "2026-10-16T10:05:00Z", "2026-10-16T10:30:00Z"),
                ("2026-10-16T10:30:00Z", "2026-10-16T10:00:00Z", "2026-10-16T10:30:00Z"),
                ("2026-10-16T10:11:00Z", "2026-10-16T10:00:00Z", "2026-10-16T10:30:00Z")):
            def fake(argv, *args):
                entries = self.response(hashlib.sha256(Path(argv[3]).read_bytes()).hexdigest())
                entries[0]["verificationResult"]["verifiedTimestamps"][0]["timestamp"] = witnessed
                return 0, json.dumps(entries).encode()
            with self.subTest(witnessed=witnessed), patch.dict(self.payload,
                    issued_at=artifact_start, expires_at=artifact_end):
                result = self.verify(fake)
                self.blocked(result)
                self.assertEqual(result["reason"], "gh_verified_timestamp_outside_window")

    def test_missing_fields_and_boolean_numbers_fail_closed(self):
        for record, key in ((self.enrollment, "repo_id"), (self.request, "invocation_id"), (self.payload, "result_sha256")):
            value = record.pop(key)
            try:
                with self.subTest(key=key):
                    self.blocked(self.verify())
            finally:
                record[key] = value
        self.request["scope"]["count"] = True
        self.blocked(self.verify())
        self.request["scope"]["count"] = 1
        self.payload["scope"]["count"] = True
        self.blocked(self.verify())
        self.payload["scope"]["count"] = 1
        self.enrollment["revocation_epoch"] = 1
        self.payload["revocation_epoch"] = True
        self.blocked(self.verify())

    def test_gh_failure_output_bounds_and_unknown_shape(self):
        for code, data in ((1, b"failed"), (0, b"[]"), (0, b"{}"), (0, b"invalid"),
                           (0, b"x" * (lib.MAX_OUTPUT + 1))):
            with self.subTest(code=code, size=len(data)):
                self.blocked(self.verify(lambda *args: (code, data)))

    def test_each_verified_entry_must_match_not_predicate(self):
        def run(mutator):
            def fake(argv, *args):
                entries = self.response(hashlib.sha256(Path(argv[3]).read_bytes()).hexdigest())
                mutator(entries)
                return 0, json.dumps(entries).encode()
            self.blocked(self.verify(fake))
        run(lambda entries: entries[0]["verificationResult"]["signature"]["certificate"].update(
            sourceRepositoryIdentifier="different"))
        run(lambda entries: entries[0]["verificationResult"].pop("signature"))
        run(lambda entries: entries[0]["verificationResult"].update(verifiedTimestamps=[]))
        run(lambda entries: entries[0]["verificationResult"]["statement"]["subject"][0].update(digest={"sha256": "0" * 64}))
        def mixed(entries):
            entries.append(copy.deepcopy(entries[0]))
            entries[1]["verificationResult"]["signature"]["certificate"]["sourceRepositoryIdentifier"] = "wrong"
            entries[1]["verificationResult"]["statement"]["predicate"] = {"repo_id": lib.REPOSITORY_ID}
        run(mixed)

    def test_duplicate_json_and_bundle_unknown_fields(self):
        for value in (b'{"x":1,"x":2}', b'{"nested":{"x":1,"x":2}}', b'{"x":NaN}'):
            with self.subTest(value=value), self.assertRaises(lib.Rejected):
                lib.strict_json(value)
        self.bundle.write_text('{"mediaType":"x","verificationMaterial":{},"dsseEnvelope":{},"extra":1}')
        self.blocked(self.verify())
        self.assertEqual(self.calls, [])

    def test_captured_copies_cannot_change_during_verification(self):
        def fake(argv, *args):
            path = Path(argv[3]); path.chmod(0o600); path.write_bytes(b"{}")
            return 0, b"[]"
        result = self.verify(fake)
        self.blocked(result)
        self.assertEqual(result["reason"], "verification_capture_drift")

    def test_original_bundle_drift_cannot_change_verified_bytes(self):
        original = self.bundle.read_bytes()
        def fake(argv, *args):
            self.bundle.write_bytes(b"{}")
            self.assertEqual(Path(argv[argv.index("--bundle") + 1]).read_bytes(), original)
            return self.executor(argv, *args)
        self.assertEqual(self.verify(fake)["status"], "VERIFIED_ADMISSION_EVIDENCE")

    def test_symlink_size_and_gh_digest_rejected(self):
        self.enrollment["gh_sha256"] = "0" * 64
        self.blocked(self.verify())
        self.assertEqual(self.calls, [])
        link = self.root / "link"; link.symlink_to(self.bundle)
        with self.assertRaises(lib.Rejected):
            lib.capture(link, lib.MAX_BUNDLE)
        with self.assertRaises(lib.Rejected):
            lib.capture(self.bundle, 1)
        with self.assertRaises(lib.Rejected):
            lib.safe_path(self.root, protected=True, directory=True)

    def test_checkout_cannot_be_trusted_host(self):
        self.blocked(self.verify(guard=False))
        self.assertEqual(self.calls, [])

    def test_missing_installed_host_anchor_blocks_before_gh(self):
        context = self.context()
        context["module"] = str(self.root / "missing-installed-host-module.py")
        result = lib.verify_admission(host_context=context, artifact_path=self.artifact,
            bundle_path=self.bundle, purpose="review_admission", now=NOW, executor=self.executor)
        self.blocked(result)
        self.assertEqual(result["reason"], "attestation_evidence_unavailable")
        self.assertEqual(self.calls, [], "host anchor 缺失時不得啟動 gh 或 provider")


if __name__ == "__main__":
    unittest.main()
