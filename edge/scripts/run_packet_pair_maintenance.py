"""Seal and dispatch one explicitly approved Pi maintenance operation.

Without --execute this command only prints HOLD. The systemd controller survives
the caller disconnecting. Never dispatch again because a response was lost; use
the returned state directory and the actual audit classifier instead.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time

PROJECT = Path('/home/pi/iot-edge-zero-trust')
BASE = Path('/run/hanium-pair-maintenance')
OPS = PROJECT / 'output/packet-pair-maintenance'
CONTROLLER = PROJECT / 'edge/scripts/packet_pair_maintenance_controller.py'

PI_CAPTURE = """import json,os,pathlib,sqlite3,time
assert os.getuid()==os.getgid()==1000
path=pathlib.Path('/home/pi/iot-edge-zero-trust/backend/data/iot_security.db')
deadline=time.monotonic()+2
db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.25)
try:
 db.execute('PRAGMA query_only=ON');db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
 db.row_factory=sqlite3.Row
 rows=db.execute("SELECT * FROM packet_capture_sessions WHERE status='RUNNING'").fetchall()
 assert len(rows)==1
 print(json.dumps(dict(rows[0])))
finally: db.close()
"""

PI_ARTIFACT = """import os,pathlib,sys
assert os.getuid()==os.getgid()==1000
os.umask(0o077)
parent=pathlib.Path(sys.argv[1]); target=parent/sys.argv[2]
parent.mkdir(mode=0o700,exist_ok=True)
assert parent.resolve(strict=True)==parent
target.mkdir(mode=0o700)
"""


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def reviewed_bytes(path, expected):
    require(re.fullmatch(r'[0-9a-f]{64}', expected or ''), 'Reviewed file SHA256 required')
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path
            and path.is_file(), 'Reviewed file must have an exact absolute path')
    value = path.read_bytes()
    require(hashlib.sha256(value).hexdigest() == expected, 'Reviewed file bytes changed')
    return value


def directory(path, owner, mode, create=True):
    if create:
        try:
            path.mkdir(mode=mode)
            os.chown(path, owner, owner)
        except FileExistsError:
            pass
    metadata = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == owner and not metadata.st_mode & 0o022,
            'Directory ownership or writable path differs')
    return path


def seal(path, data, mode):
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def launch(*, request_file, request_file_sha256, controller_sha256,
           approval_reference, approve_capture_pause=False, approve_processing_pause=False, wait_seconds=190):
    require(os.name == 'posix' and os.getuid() == 0, 'Root Linux launcher only')
    require(type(approve_capture_pause) is bool and type(approve_processing_pause) is bool
        and approve_capture_pause != approve_processing_pause and approval_reference.strip(),
        'Exactly one explicit operating pause and recovery approval required')
    require(0 <= wait_seconds <= 210, 'Observer wait must be between 0 and 210 seconds')
    request_bytes = reviewed_bytes(request_file, request_file_sha256)
    driver_bytes = reviewed_bytes(CONTROLLER, controller_sha256)
    request = json.loads(request_bytes)
    require(request.get('plan_schema_version') == 'packet-pair-maintenance-request-v1'
            and re.fullmatch(r'[0-9a-f]{64}', request.get('plan_sha256', ''))
            and request['scope']['repository_root'] == str(PROJECT)
            and request['scope']['database_path'] == str(PROJECT / 'backend/data/iot_security.db'),
            'Request schema or operating paths differ')
    keep_capture = request['scope'].get('allow_capture_appends', False)
    require(type(keep_capture) is bool and keep_capture == approve_processing_pause,
            'Pause approval differs from signed capture mode')
    # This is the only SQLite preflight, and it runs as pi in a read-only process.
    observed = subprocess.run(['/usr/sbin/runuser', '-u', 'pi', '--', '/usr/bin/python3',
        '-I', '-B', '-c', PI_CAPTURE], capture_output=True, text=True, check=True, timeout=3)
    capture = json.loads(observed.stdout)
    require(type(capture.get('id')) is int and capture['id'] > 0
            and capture.get('status') == 'RUNNING' and capture.get('ended_at') is None,
            'Exactly one actual RUNNING Capture is required')
    require(not keep_capture or request.get('capture_session_identity') == capture,
            'Reviewed retained Capture identity changed')
    process = subprocess.run(['/usr/bin/systemctl', 'show', 'packet-capture.service',
        '--property=ActiveState,MainPID'], capture_output=True, text=True, check=True, timeout=2)
    fields = dict(line.split('=', 1) for line in process.stdout.splitlines() if '=' in line)
    pid = int(fields.get('MainPID', '0'))
    require(fields.get('ActiveState') == 'active' and pid > 1, 'Capture process is not active')
    birth = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]
    token = secrets.token_hex(6)
    directory(BASE, 0, 0o755)
    frozen = BASE / ('frozen-' + token)
    artifacts = OPS / token
    state = BASE / token
    require(not any(path.exists() for path in (frozen, artifacts, state)), 'One-use token already exists')
    directory(frozen, 0, 0o755)
    # Never create/chown through the pi-writable project tree as root.
    subprocess.run(['/usr/sbin/runuser', '-u', 'pi', '--', '/usr/bin/python3', '-I', '-B',
        '-c', PI_ARTIFACT, str(OPS), token], capture_output=True, check=True, timeout=3)
    directory(OPS, 1000, 0o700, create=False)
    directory(artifacts, 1000, 0o700, create=False)
    source_file, request_copy, spec_file = (frozen / name for name in
                                           ('controller.py', 'request.json', 'spec.json'))
    seal(source_file, driver_bytes, 0o555)
    # pi must read the request and source; only the root specification is private.
    seal(request_copy, request_bytes, 0o444)
    spec = dict(schema='packet-pair-maintenance-v1', token=token,
        approval_received=True, approval_scope=('capture-retained-canonical-pair-recovery' if keep_capture
            else 'capture-pause-canonical-pair-recovery'), allow_capture_appends=keep_capture,
        approval_reference=approval_reference,
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        capture_session_id=capture['id'], capture_session_uuid=capture['session_id'],
        capture_session=capture, capture_main_pid=pid, capture_main_birth=birth,
        preflight_observed_at=time.time(),
        controller_unit='hanium-pair-maintenance-controller-' + token + '.service',
        worker_unit='hanium-pair-maintenance-job-' + token + '.service',
        classifier_unit='hanium-pair-maintenance-classifier-' + token + '.service',
        rescue_unit='hanium-pair-maintenance-rescue-' + token,
        driver_sha256=controller_sha256, request_file=str(request_copy),
        request_file_sha256=request_file_sha256, request_sha256=request['plan_sha256'],
        artifact_dir=str(artifacts))
    seal(spec_file, json.dumps(spec, sort_keys=True).encode(), 0o400)
    receipt = dict(token=token, state_dir=str(state), artifact_dir=str(artifacts),
                   spec_file=str(spec_file), rerun=False, recovery_complete=False)
    # Publish identity before dispatch; a timeout never proves the job did not start.
    print(json.dumps(dict(receipt, status='DISPATCH_REQUESTED')), flush=True)
    try:
        subprocess.run(['/usr/bin/systemd-run', '--unit=' + spec['controller_unit'].removesuffix('.service'),
            '--property=Type=exec', '--property=RuntimeMaxSec=145', '--property=TimeoutStopSec=3',
            '--property=KillMode=control-group', '/usr/bin/python3', '-I', '-B', str(source_file),
            '--execute', '--spec', str(spec_file)], capture_output=True, check=True, timeout=5)
    except (subprocess.SubprocessError, OSError) as error:
        return dict(receipt, status='DISPATCH_UNCONFIRMED', error_type=type(error).__name__)
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        restored = state / 'restored.json'
        if restored.exists():
            return dict(receipt, status='RESTORATION_REPORTED', restoration=json.loads(restored.read_text()))
        time.sleep(.2)
    return dict(receipt, status='OBSERVATION_PENDING')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--approve-capture-pause', action='store_true')
    parser.add_argument('--approve-processing-pause', action='store_true')
    parser.add_argument('--approval-reference', default='')
    parser.add_argument('--request-file', type=Path)
    parser.add_argument('--request-file-sha256')
    parser.add_argument('--controller-sha256')
    parser.add_argument('--wait-seconds', type=int, default=190)
    args = vars(parser.parse_args(argv))
    if not args.pop('execute'):
        print(json.dumps(dict(status='HOLD', service_actions=False, recovery_complete=False)))
        return 0
    result = launch(**args)
    print(json.dumps(result, sort_keys=True))
    # Restoration is not proof that both detectors and Trust have progressed.
    return 3


if __name__ == '__main__':
    raise SystemExit(main())
