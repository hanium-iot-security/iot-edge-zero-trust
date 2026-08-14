# Phase 5 Verified Collection Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 기존 정상 Packet Capture 16 Sessions와 ESP32 공격 Session 53을 재수집하지 않고, 읽기 전용 검증·연쇄 SHA256·세션별 수집 Commit을 보존하는 `packet-if-dataset-v2` 입력 패키지로 이관한다.

**Architecture:** 순수 Python `VerifiedCollectionManifest` 계약이 수동 실기기 수집 Provenance와 Evidence Hash를 표현한다. Batch Importer는 일관 SQLite Snapshot과 처리 완료 PCAP을 읽기 전용으로 검증해 Collection Manifest, DATA_ONLY Run Manifest, Evidence, Dataset Export Spec을 임시 Directory에 생성하고 전체 성공 시 원자적으로 게시한다. 기존 Dataset v2 Exporter와 Loader는 세션별 Source Commit과 선택적 Collection Manifest 연쇄 검증만 하위 호환 방식으로 확장한다.

**Tech Stack:** Python 3.11+, dataclasses, pathlib, sqlite3, SQLAlchemy, pytest, 기존 `edge.phase5.contracts`, 기존 Packet Capture Policy·PCAP Naming·Packet IF Dataset v2 계약

## Global Constraints

- 기준 브랜치는 `develop`; 구현 브랜치는 `feature/woomin-phase5-verified-collection-import`이다.
- 운영 DB에는 `INSERT`, `UPDATE`, `DELETE`를 실행하지 않는다.
- SQLite 입력은 절대경로 Snapshot만 허용하고 `mode=ro`, `PRAGMA query_only=ON`으로 연다.
- PCAP은 읽기·Hash 검증만 하며 복사·이동·삭제하지 않는다.
- 정상 16 Sessions와 Session 53만 공식 Dataset 후보로 이관한다.
- Session 51·52와 `esp32_02` 정상 Holdout 2개는 Dataset에 넣지 않는다.
- Dataset Train·Validation은 정상만, Test는 정상과 공격을 모두 포함한다.
- `source_capture_group_id` 기본값은 각 `session_id`이다.
- Dataset 전체 `normal_policy_version`은 `phase5-normal-policy-v1.1` 하나만 허용한다.
- Session 53 Payload Schema는 `phase5-packet-rate-udp-payload-v1`, Provenance는 `RETROSPECTIVE_SOURCE_AND_PCAP_VERIFICATION`으로 기록한다.
- Session 53의 `sender=960`, `gateway=880`, `feature=880`, 원인 `UNRESOLVED`를 보존한다.
- 기존 Scenario Runner와 Dataset v2 Fixture는 하위 호환되어야 한다.
- 출력 Package가 이미 존재하면 덮어쓰지 않는다.
- 전체 Batch가 성공한 경우에만 최종 Directory를 게시한다.

---

## File Structure

### Create

- `edge/phase5/verified_collection_contract.py`
  - Collection Manifest·Evidence Reference·Session Observation 순수 계약
  - Canonical JSON, SHA256, Sidecar Load·검증
  - Run/Dataset Identity 대조
- `edge/phase5/import_verified_collection.py`
  - Import Spec Parser
  - SQLite Snapshot read-only Preflight
  - Segment·Feature·PCAP·Device·Split 검증
  - Evidence·Collection Manifest·Run Manifest·Export Spec 생성
  - Check-only와 원자적 Batch 게시 CLI
- `tests/test_verified_collection_contract.py`
- `tests/test_import_verified_collection.py`
- `docs/phase5-verified-collection-import.md`

### Modify

- `ai/export_packet_if_dataset.py`
  - `PacketIFSessionAnnotation.source_commit_sha`
  - Session별 Source Commit 정규화·Manifest 기록
  - 기존 최상위 Commit fallback
- `ai/packet_if_phase5_manifest.py`
  - Run Manifest의 선택적 `session_manifest_ref` 실제 파일·Sidecar 검증
  - Verified Collection Identity·Evidence 검증 호출
- `ai/packet_if_dataset.py`
  - Dataset Load 시 Run → Collection 연쇄 검증
- `tests/test_export_packet_if_dataset.py`
  - Session별 Commit·fallback·Collection 연쇄 검증 통합
- `tests/test_packet_if_phase5_manifest.py`
  - Collection Manifest 변조·경로 탈출·Identity 불일치

---

### Task 1: Verified Collection Pure Contract

**Files:**
- Create: `edge/phase5/verified_collection_contract.py`
- Test: `tests/test_verified_collection_contract.py`

**Interfaces:**
- Produces: `VERIFIED_COLLECTION_SCHEMA_VERSION: str`
- Produces: `VerifiedCollectionArtifact(relative_path: str, artifact_type: str, size_bytes: int, sha256: str)`
- Produces: `VerifiedCollectionObservation(sender_reported_packets: int | None, gateway_observed_packets: int | None, feature_packet_count: int, observation_gap_packets: int | None, observation_gap_cause: str | None, gateway_first_attack_packet_at: datetime | None)`
- Produces: `VerifiedCollectionManifest(...)`
- Produces: `verified_collection_sha256(manifest: VerifiedCollectionManifest) -> str`
- Produces: `load_verified_collection_manifest(path: Path, *, expected_sha256: str, verify_artifacts: bool = True) -> VerifiedCollectionManifest`
- Produces: `validate_verified_collection_identity(manifest, *, run_manifest, session_id, scenario, target_device_id, target_source_ip, included_device_ips) -> None`

- [ ] **Step 1: Write strict contract tests**

Add tests proving:

```python
def test_verified_collection_round_trip_and_canonical_hash():
    manifest = build_manifest_fixture()
    restored = VerifiedCollectionManifest.from_json(manifest.to_json())
    assert restored == manifest
    assert verified_collection_sha256(restored) == verified_collection_sha256(manifest)
```

```python
def test_verified_collection_rejects_unknown_fields():
    payload = json.loads(build_manifest_fixture().to_json())
    payload["unexpected"] = True
    with pytest.raises(ValueError, match="unknown fields"):
        VerifiedCollectionManifest.from_dict(payload)
```

```python
def test_load_verified_collection_checks_canonical_hash_sidecar_and_artifacts(tmp_path):
    manifest_path = write_collection_fixture(tmp_path)
    loaded = load_verified_collection_manifest(
        manifest_path,
        expected_sha256=verified_collection_sha256(build_manifest_fixture()),
    )
    assert loaded.session_id == SESSION_ID
```

Include negative tests for sidecar mismatch, artifact size mismatch, artifact SHA256 mismatch, unsafe relative paths, non-UUID4 Session ID, invalid SHA1 Commit, invalid IPv4, duplicate included devices, invalid timestamp order, and Session 53 observation arithmetic.

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
pytest -q tests/test_verified_collection_contract.py
```

Expected: import failure because `edge.phase5.verified_collection_contract` does not exist.

- [ ] **Step 3: Implement minimal strict dataclasses and canonical JSON**

Implementation rules:

```python
VERIFIED_COLLECTION_SCHEMA_VERSION = "phase5-verified-collection-v1"
VERIFIED_COLLECTION_SHA256_SIDECAR_SUFFIX = ".sha256"
```

- Every `from_dict` enumerates allowed and required fields.
- Datetimes serialize as UTC ISO-8601 ending in `Z`.
- Canonical JSON uses `sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=False`.
- Relative paths reuse the existing portable path semantics without importing from `ai`.
- Artifact paths are resolved beneath the Collection Manifest Directory.
- Artifact verification compares both `size_bytes` and exact file-byte SHA256.
- Sidecar accepts `<sha>` or `<sha>  <filename>` and rejects another filename.

- [ ] **Step 4: Run contract tests and adjacent Run Manifest tests**

```bash
pytest -q tests/test_verified_collection_contract.py tests/test_phase5_evaluation_contracts.py
```

Expected: PASS.

- [ ] **Step 5: Commit Task 1**

```bash
git add edge/phase5/verified_collection_contract.py tests/test_verified_collection_contract.py
git commit -m "feat: add verified collection manifest contract"
```

---

### Task 2: Run-to-Collection Chain Verification

**Files:**
- Modify: `ai/packet_if_phase5_manifest.py`
- Modify: `ai/packet_if_dataset.py`
- Modify: `tests/test_packet_if_phase5_manifest.py`
- Test: `tests/test_verified_collection_contract.py`

**Interfaces:**
- Consumes: `load_verified_collection_manifest`, `validate_verified_collection_identity`
- Produces: `load_verified_session_manifest(run_manifest_path: Path, run_manifest: RunManifest, *, session_id: str, scenario: str, target_device_id: str | None, target_source_ip: str | None, included_device_ips: Mapping[str, str], required: bool = False) -> VerifiedCollectionManifest | None`

- [ ] **Step 1: Write failing chain-verification tests**

Add tests showing:

```python
def test_dataset_run_reference_verifies_collection_manifest(tmp_path):
    run_path, reference = write_run_with_collection(tmp_path)
    run = load_verified_run_manifest(run_path, expected_sha256=reference.sha256)
    collection = load_verified_session_manifest(
        run_path,
        run,
        session_id=SESSION_ID,
        scenario="normal_stable",
        target_device_id=None,
        target_source_ip=None,
        included_device_ips={"esp32_01": "192.168.0.4"},
        required=True,
    )
    assert collection is not None
```

Negative cases:

- Collection Manifest canonical hash mismatch
- Collection sidecar mismatch
- `session_manifest_ref` path escaping Run Directory
- Session·Scenario·Device·IP mismatch
- Evidence tampering
- `required=True` with missing `session_manifest_ref`
- Existing Scenario Runner Run with `required=False` and null reference still accepted

- [ ] **Step 2: Run tests and verify RED**

```bash
pytest -q tests/test_packet_if_phase5_manifest.py tests/test_verified_collection_contract.py
```

Expected: missing `load_verified_session_manifest` or missing chained validation.

- [ ] **Step 3: Implement chain loader in `ai/packet_if_phase5_manifest.py`**

Rules:

- Resolve `session_manifest_ref.relative_path` relative to `run_manifest_path.parent`.
- Reject paths escaping that Directory.
- Validate referenced schema is `phase5-verified-collection-v1`.
- Call Collection loader with `session_manifest_ref.sha256`.
- Validate identity against the already verified Run Manifest and Dataset session fields.
- Return `None` only when reference is null and `required=False`.

- [ ] **Step 4: Call chain loader from Dataset v2 reference validation**

In `ai/packet_if_dataset.py`, after `validate_run_manifest_identity()` and before `assert_run_manifest_complete()`, call:

```python
load_verified_session_manifest(
    run_manifest_path,
    run_manifest,
    session_id=spec.session_id,
    scenario=spec.scenario,
    target_device_id=spec.target_device_id,
    target_source_ip=spec.target_source_ip,
    included_device_ips={device.device_id: device.peer_ip for device in spec.devices},
    required=False,
)
```

This preserves existing Scenario Runner manifests while verifying Collection references when present.

- [ ] **Step 5: Run focused tests**

```bash
pytest -q tests/test_packet_if_phase5_manifest.py tests/test_packet_if_dataset.py tests/test_verified_collection_contract.py
```

Expected: PASS.

- [ ] **Step 6: Commit Task 2**

```bash
git add ai/packet_if_phase5_manifest.py ai/packet_if_dataset.py tests/test_packet_if_phase5_manifest.py tests/test_verified_collection_contract.py
git commit -m "feat: verify packet dataset collection provenance chain"
```

---

### Task 3: Session-Level Capture Source Commit

**Files:**
- Modify: `ai/export_packet_if_dataset.py`
- Modify: `tests/test_export_packet_if_dataset.py`

**Interfaces:**
- Extends: `PacketIFSessionAnnotation.source_commit_sha: str | None = None`
- Existing parameter retained: `export_packet_if_dataset(..., source_commit_sha: str, ...)`
- Export Spec session field: optional `source_commit_sha`

- [ ] **Step 1: Write failing per-session Commit tests**

```python
def test_export_records_distinct_session_source_commits(...):
    annotations = [
        annotation(SESSION_ID, source_commit_sha="a" * 40),
        annotation(OTHER_SESSION_ID, source_commit_sha="b" * 40),
    ]
    result = export(..., annotations=annotations, source_commit_sha="c" * 40)
    sessions = load_manifest(result)
    assert sessions[SESSION_ID]["source_commit_sha"] == "a" * 40
    assert sessions[OTHER_SESSION_ID]["source_commit_sha"] == "b" * 40
```

```python
def test_export_falls_back_to_top_level_source_commit(...):
    annotation = annotation(SESSION_ID, source_commit_sha=None)
    result = export(..., annotations=[annotation], source_commit_sha="c" * 40)
    assert load_manifest(result)[SESSION_ID]["source_commit_sha"] == "c" * 40
```

Also test invalid Session commit and JSON Export Spec parsing.

- [ ] **Step 2: Run tests and verify RED**

```bash
pytest -q tests/test_export_packet_if_dataset.py -k "source_commit"
```

Expected: dataclass or manifest assertion failure.

- [ ] **Step 3: Implement minimal extension**

- Add nullable field to `PacketIFSessionAnnotation`.
- Normalize and validate it with the existing 40-hex Git SHA validator.
- Parse optional session `source_commit_sha` from Export Spec.
- In `_build_manifest_payload`, use `annotation.source_commit_sha or source_commit_sha` per Session.
- Keep top-level `source_commit_sha` required for old callers and as fallback.

- [ ] **Step 4: Run Exporter and Dataset tests**

```bash
pytest -q tests/test_export_packet_if_dataset.py tests/test_packet_if_dataset.py
```

Expected: PASS.

- [ ] **Step 5: Commit Task 3**

```bash
git add ai/export_packet_if_dataset.py tests/test_export_packet_if_dataset.py
git commit -m "feat: preserve per-session packet capture commits"
```

---

### Task 4: Import Spec and Read-Only Session Preflight

**Files:**
- Create: `edge/phase5/import_verified_collection.py`
- Create: `tests/test_import_verified_collection.py`

**Interfaces:**
- Produces: `VerifiedCollectionImportSpec.from_json(text: str) -> VerifiedCollectionImportSpec`
- Produces: `VerifiedCollectionSessionSpec`
- Produces: `connect_snapshot_read_only(path: Path) -> sqlite3.Connection`
- Produces: `preflight_verified_collection(*, db_snapshot: Path, processed_pcap_dir: Path, spec: VerifiedCollectionImportSpec, verification_commit_sha: str) -> VerifiedCollectionBatchPlan`
- Produces: `build_session_plan(...) -> VerifiedCollectionSessionPlan`

- [ ] **Step 1: Build a migrated SQLite fixture and failing preflight tests**

Fixture must contain:

- `devices`: `esp32_01=192.168.0.4`, `esp32_02=192.168.0.5`
- COMPLETED Session
- contiguous 10-second PROCESSED/EMPTY Segments
- Capture timing metadata satisfying `CapturePolicy`
- registered INBOUND Packet Feature Row
- matching dummy PCAP files using `build_pcap_filename()`

Tests:

```python
def test_preflight_reads_snapshot_without_modifying_it(...):
    before = file_sha256(snapshot)
    plan = preflight_verified_collection(...)
    assert plan.sessions[0].eligible_row_count == 1
    assert file_sha256(snapshot) == before
```

Negative cases:

- relative Snapshot path
- `integrity_check` failure fixture or invalid SQLite file
- foreign-key violation
- missing Session
- non-COMPLETED Session
- READY or FAILED Segment
- PROCESSED without Feature
- EMPTY with Feature
- Window gap or duplicate
- Feature/Segment Window mismatch
- no eligible INBOUND Row
- device/IP mismatch
- PCAP missing
- PCAP filename metadata mismatch
- duplicate Slot
- missing Dataset Split or missing normal/attack Test label
- holdout Session explicitly rejected

- [ ] **Step 2: Run tests and verify RED**

```bash
pytest -q tests/test_import_verified_collection.py
```

Expected: missing importer module.

- [ ] **Step 3: Implement strict Import Spec parser**

Rules:

- Allowed scenarios are exactly:
  - `normal_stable`
  - `normal_interval_jitter`
  - `normal_payload_variation`
  - `normal_combined_variation`
  - `packet_rate_flood`
- Normal rows require `collection_device_id=esp32_01`, no target fields.
- Attack rows require `esp32_02`, target `esp32_02`, IP `192.168.0.5`, Split `test`.
- Normal Firmware/Payload pair must be `phase5-normal-pilot-v1` and `phase5-normal-payload-v1`.
- Session 53 Firmware/Payload pair must be `phase5-packet-rate-sender-v2` and `phase5-packet-rate-udp-payload-v1`.
- Commit SHA is exact 40-hex.
- Run ID derives as `verified-<collection_slot_id>`.
- Source Capture Group defaults to Session UUID.

- [ ] **Step 4: Implement read-only DB and Session/PCAP validation**

- Use SQLite URI `file:<absolute-posix-path>?mode=ro`.
- Set `row_factory=sqlite3.Row`, `PRAGMA query_only=ON`, `PRAGMA busy_timeout=5000`.
- Read devices, Session, Segments, Packet Features directly.
- Reuse `CapturePolicy.from_env()` only when explicitly injected; tests pass a fixed `CapturePolicy()`.
- Parse PCAP filenames with `parse_pcap_filename()`.
- Compute exact file SHA256.
- Determine `included_device_ids` from exported eligible rows.
- Determine background traffic from eligible registered INBOUND rows before attack target filtering.
- Compare Feature Ready Through to last Segment End, not Session `ended_at` string.

- [ ] **Step 5: Run preflight tests**

```bash
pytest -q tests/test_import_verified_collection.py
```

Expected: PASS.

- [ ] **Step 6: Commit Task 4**

```bash
git add edge/phase5/import_verified_collection.py tests/test_import_verified_collection.py
git commit -m "feat: add read-only verified collection preflight"
```

---

### Task 5: Evidence, DATA_ONLY Run Manifest, Export Spec, Atomic Package

**Files:**
- Modify: `edge/phase5/import_verified_collection.py`
- Modify: `tests/test_import_verified_collection.py`

**Interfaces:**
- Produces: `write_verified_collection_package(plan: VerifiedCollectionBatchPlan, *, db_snapshot: Path, processed_pcap_dir: Path, output_root: Path) -> Path`
- Produces CLI:

```bash
python -m edge.phase5.import_verified_collection \
  --project-root /home/pi/iot-edge-zero-trust \
  --db-snapshot /absolute/path/iot_security.snapshot.db \
  --processed-pcap-dir /home/pi/iot-edge-zero-trust/data/pcap/processed \
  --spec /absolute/path/import-spec.json \
  --output-root /home/pi/iot-edge-zero-trust/data/exports \
  --verification-commit-sha <40-hex> \
  --check-only
```

Write mode replaces `--check-only` with `--write`.

- [ ] **Step 1: Write failing package tests**

Test exact output tree and contents:

- copied DB Snapshot and metadata
- Collection Manifest + Sidecar
- DATA_ONLY Run Manifest + Sidecar
- `session-snapshot.json`
- `feature-qc.json`
- `pcap-inventory.json`
- `source-evidence.json`
- `packet-if-export-spec-v2.json`
- `import-summary.json` + Sidecar

Assertions:

```python
assert run_manifest.session_manifest_ref.relative_path == "verified-collection-manifest.json"
assert run_manifest.statuses.scenario_status == ManifestStatus.SUCCESS
assert run_manifest.statuses.data_status == ManifestStatus.SUCCESS
assert run_manifest.statuses.detection_status == ManifestStatus.NOT_APPLICABLE
```

Session 53 assertions:

```python
assert observation.sender_reported_packets == 960
assert observation.gateway_observed_packets == 880
assert observation.feature_packet_count == 880
assert observation.observation_gap_packets == 80
assert observation.observation_gap_cause == "UNRESOLVED"
```

Atomicity tests:

- failure on Session N leaves no final Package
- `--check-only` leaves no output
- existing Package rejects overwrite
- all Manifest references reload successfully after final rename

- [ ] **Step 2: Run package tests and verify RED**

```bash
pytest -q tests/test_import_verified_collection.py -k "package or atomic or check_only"
```

Expected: missing writer/CLI behavior.

- [ ] **Step 3: Implement deterministic Evidence writers**

- JSON writes use canonical UTF-8 plus final newline.
- Evidence SHA256 is file byte hash.
- Add Evidence references to both Collection Manifest and Run Manifest Artifacts.
- Run timestamps map to original Capture Session.
- `verified_at` uses injected clock for tests and current UTC in CLI.
- `attack_started_at` remains null unless an absolute UTC value is in validated Source Evidence.

- [ ] **Step 4: Implement Export Spec generation**

Each Session contains:

- exact Session-level Source Commit
- Dataset target fields per label
- `source_capture_group_id=session_id`
- Run Manifest relative path and canonical SHA256
- actual Firmware/Payload/Normal Policy
- computed included devices and background traffic

Top-level fallback `source_commit_sha` is the verification Commit only for compatibility; every official Session entry includes its own capture Commit.

- [ ] **Step 5: Implement atomic Batch publication**

- Create temp Directory under `output_root`.
- Copy Snapshot, verify hash.
- Write all files.
- Reload all Collection and Run Manifests and verify references.
- `fsync` written files and relevant Directories where supported.
- Rename temp Directory to final `dataset_package_id` on same filesystem.
- Delete temp Directory on failure.
- Reject pre-existing final Directory.

- [ ] **Step 6: Implement CLI**

- Exactly one of `--check-only` or `--write` is required.
- Print one concise JSON summary to stdout.
- Exit 0 on PASS, 2 on validation/input error, 1 on unexpected runtime failure.
- Never print secret environment values.

- [ ] **Step 7: Run importer tests**

```bash
pytest -q tests/test_import_verified_collection.py
```

Expected: PASS.

- [ ] **Step 8: Commit Task 5**

```bash
git add edge/phase5/import_verified_collection.py tests/test_import_verified_collection.py
git commit -m "feat: publish verified collection dataset packages"
```

---

### Task 6: Dataset Export Integration and Documentation

**Files:**
- Modify: `tests/test_export_packet_if_dataset.py`
- Modify: `tests/test_packet_if_phase5_manifest.py`
- Create: `docs/phase5-verified-collection-import.md`

**Interfaces:**
- Uses importer output without manual manifest editing.

- [ ] **Step 1: Write an end-to-end integration test**

The test must:

1. Create normal Train, Validation, normal Test, attack Test Sessions.
2. Run preflight and package writer.
3. Load generated Export Spec.
4. Run `export_packet_if_dataset()` on the same Snapshot-backed SQLAlchemy Session.
5. Load generated Dataset with `load_packet_if_dataset()`.
6. Assert Split membership and distinct Session Commit values.
7. Tamper with Collection Evidence and confirm subsequent Dataset load fails.

- [ ] **Step 2: Run integration test and verify RED if any link is missing**

```bash
pytest -q tests/test_export_packet_if_dataset.py -k "verified_collection"
```

Expected before final wiring: failure at the missing integration point.

- [ ] **Step 3: Complete minimal wiring only**

Do not add model training or Pi runtime behavior. Fix only the package → Export Spec → Dataset v2 path.

- [ ] **Step 4: Write operator Runbook**

Document:

- Phase 5 Pi #1 + ESP32 #2 + management laptop topology
- Pi #2 deferred to Phase 6
- prerequisite Snapshot creation and integrity checks
- Import Spec source-of-truth rules
- check-only command
- write command
- generated files
- Dataset Export command using Package paths
- PASS/HOLD/FAIL interpretation
- Session 53 960/880 limitation
- rollback: delete only unpublished temp or explicitly approved generated Package; never alter DB/PCAP

- [ ] **Step 5: Run integration and documentation checks**

```bash
pytest -q \
  tests/test_verified_collection_contract.py \
  tests/test_import_verified_collection.py \
  tests/test_packet_if_phase5_manifest.py \
  tests/test_export_packet_if_dataset.py \
  tests/test_packet_if_dataset.py
python -m compileall -q edge ai tests

git diff --check
```

Expected: PASS with no diff-check output.

- [ ] **Step 6: Commit Task 6**

```bash
git add tests/test_export_packet_if_dataset.py tests/test_packet_if_phase5_manifest.py docs/phase5-verified-collection-import.md
git commit -m "docs: add verified collection import runbook"
```

---

### Task 7: Full Verification and Pull Request

**Files:**
- Review all branch changes

- [ ] **Step 1: Run focused test suite from a clean checkout**

```bash
pytest -q \
  tests/test_verified_collection_contract.py \
  tests/test_import_verified_collection.py \
  tests/test_packet_if_phase5_manifest.py \
  tests/test_export_packet_if_dataset.py \
  tests/test_packet_if_dataset.py \
  tests/test_phase5_evaluation_contracts.py \
  tests/test_scenario_runner.py
```

- [ ] **Step 2: Run broader regression excluding the known Windows-only firewall wrapper issue when applicable**

```bash
pytest -q --ignore=tests/test_firewall_rule_wrapper.py
```

- [ ] **Step 3: Run static verification**

```bash
python -m compileall -q edge ai backend db tests
git diff --check develop...HEAD
git status --short
```

Expected: compile pass, no diff-check output, clean worktree.

- [ ] **Step 4: Review security and data-integrity boundaries**

Confirm from diff:

- no DB writes
- no PCAP mutation
- no secrets or real DB/PCAP committed
- no Trust/Firewall policy change
- no Dataset threshold/model behavior change
- existing Scenario Runner manifests remain accepted

- [ ] **Step 5: Open PR as ready for review, not merged**

PR title:

```text
feat: Phase 5 Verified Collection Dataset 이관 지원
```

PR body must include:

- problem and provenance rationale
- exact included/excluded Sessions
- Dataset v2 compatibility changes
- test outputs actually run
- Pi execution not yet performed
- Codex review requested before merge
- no DB/Migration/API/Frontend/Trust/Firewall changes

- [ ] **Step 6: Leave branch unmerged for Codex review**

After PR creation, provide the PR number and a compact Codex review prompt focusing on:

- retrospective provenance honesty
- path traversal and hash-chain verification
- SQLite query-only enforcement
- atomic package publication
- backward compatibility
- Session-level Commit semantics

Do not merge until review feedback is addressed and verification is rerun.
