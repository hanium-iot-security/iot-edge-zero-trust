"""One-use approved processing pause around the canonical Rule/IF pair command.

Root only controls OS services. The database worker and audit classifier run as
pi. The caller must seal this source/spec/request, launch the controller with
RuntimeMaxSec=145 and arm its independent 150s rescue before any pause. Unknown
writer teardown prevents restoration. Capture-retained mode controls only packet
processing; legacy pause mode restores ingress but holds Orchestrator/Firewall
on partial or unknown audits. Default HOLD; no automatic retry.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

BASE = Path('/run/hanium-pair-maintenance')
PROJECT = Path('/home/pi/iot-edge-zero-trust')
OPS = PROJECT / 'output/packet-pair-maintenance'
CAPTURE = 'packet-capture.service'
BROKER = 'mosquitto.service'
TIMERS = ('packet-feature-extractor.timer', 'firewall-runtime-snapshot.timer')
WRITERS = ('mqtt-subscriber.service', 'detection-orchestrator.service',
    'mqtt-feature-builder.service', 'packet-feature-extractor.service',
    'firewall-runtime-snapshot.service', 'firewall-worker.service',
    'gateway-metrics.service', 'iot-edge-api.service')
ALL = (CAPTURE, BROKER, *TIMERS, *WRITERS)


class Hold(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise Hold(reason)


def service_scope(spec):
    keep = spec.get('allow_capture_appends', False)
    require(type(keep) is bool, 'Invalid capture mode')
    timers = ('packet-feature-extractor.timer',) if keep else TIMERS
    writers = ('detection-orchestrator.service', 'packet-feature-extractor.service') if keep else WRITERS
    paused = (*timers, *writers) if keep else (CAPTURE, *WRITERS, *TIMERS)
    return dict(keep=keep, timers=timers, writers=writers, paused=paused,
        held=frozenset(paused) if keep else PROCESSING,
        retained=tuple(name for name in ALL if name not in paused))


def relevant_jobs(spec):
    value = jobs()
    scope = service_scope(spec)
    if not scope['keep']:
        return value
    units = {*scope['paused'], spec['worker_unit'], spec['classifier_unit']}
    return '\n'.join(line for line in value.splitlines() if set(line.split()) & units)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sealed(path):
    path = Path(path)
    meta = path.lstat()
    require(path.is_absolute() and path.resolve(strict=True) == path
        and stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022,
        'Unsealed root file')
    return path


def record(state, name, value, public=False):
    target = state / (name + '.json')
    temporary = target.with_name(target.name + '.' + str(os.getpid()) + '.tmp')
    with temporary.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o444 if public else 0o600)
    temporary.replace(target)


def operation_owner(spec):
    return dict(boot_id=spec['boot_id'], token=spec['token'], request_sha256=spec['request_sha256'],
        database_path=str(PROJECT / 'backend/data/iot_security.db'),
        paused_units=list(service_scope(spec)['paused']))


def claim_operation(spec):
    # mkdir arbitrates all tokens/modes; the owner survives controller death.
    fence = BASE / 'active-operation'
    try:
        fence.mkdir(mode=0o700)
    except FileExistsError:
        raise Hold('Another maintenance operation owns this host; inspect its HOLD, no takeover')
    record(fence, 'owner', operation_owner(spec))


def require_owner(spec):
    owner = BASE / 'active-operation/owner.json'
    require(owner.exists() and json.loads(sealed(owner).read_text()) == operation_owner(spec),
            'Maintenance operation ownership differs; no service actions')


def release_operation(spec):
    # Called only under this token's restore.lock, after quiescence/restoration.
    require_owner(spec)
    (BASE / 'active-operation/owner.json').unlink()
    (BASE / 'active-operation').rmdir()


def finished(state):
    if (state / 'not-started.json').exists():
        return True
    receipt = state / 'restored.json'
    return receipt.exists() and json.loads(receipt.read_text())['classification'] in (
        'NOT_STARTED', 'NOT_COMMITTED_VERIFIED', 'COMMITTED_VERIFIED')


def ctl(*args, timeout=2, check=True):
    result = subprocess.run(['/usr/bin/systemctl', *args], capture_output=True,
        text=True, timeout=timeout)
    require(not check or result.returncode == 0, 'systemctl failed: ' + repr(args))
    return result.stdout.strip()


def show(unit):
    return dict(row.split('=', 1) for row in ctl('show', unit,
        '--property=ActiveState,MainPID,ControlGroup,Result,ExecMainStatus,User,Group').splitlines() if '=' in row)


def jobs():
    return ctl('list-jobs', '--no-legend', '--no-pager')


def poll(predicate, deadline, reason):
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.02)
    raise Hold(reason)


def kernel_empty(group):
    require(isinstance(group, str) and group.startswith('/') and '..' not in Path(group).parts,
            'Unknown owned cgroup')
    path = Path('/sys/fs/cgroup') / group.lstrip('/')
    if not path.exists():
        return True
    require(path.resolve().is_relative_to(Path('/sys/fs/cgroup')), 'cgroup escaped kernel scope')
    events = dict(row.split() for row in (path / 'cgroup.events').read_text().splitlines())
    return events.get('populated') == '0' and not (path / 'cgroup.procs').read_text().strip()


def stopped(unit, known_group=None):
    row = show(unit)
    if row['ActiveState'] not in ('inactive', 'failed') or row.get('MainPID', '0' if unit.endswith('.timer') else None) != '0':
        return False
    group = known_group or row.get('ControlGroup')
    return not group or kernel_empty(group)


def worker_command(spec, role):
    require(role in ('execute', 'classify'), 'Unknown worker role')
    return [str(PROJECT / 'venv/bin/python'), '-B', '-m',
        'edge.detection.packet_pair_maintenance_worker', role,
        '--request-file', spec['request_file'], '--request-sha256', spec['request_sha256'],
        '--artifact-dir', spec['artifact_dir']]


def load_spec(path, fresh=False):
    require(os.name == 'posix' and os.getuid() == 0, 'Root Linux controller only')
    spec = json.loads(sealed(path).read_text())
    require(spec['schema'] == 'packet-pair-maintenance-v1' and spec['approval_received'] is True
        and spec['approval_scope'] == ('capture-retained-canonical-pair-recovery'
            if service_scope(spec)['keep'] else 'capture-pause-canonical-pair-recovery')
        and type(spec['capture_session_id']) is int and spec['capture_session_id'] > 0
        and re.fullmatch(r'[0-9a-f-]{36}', spec['capture_session_uuid']),
        'Operating maintenance approval/header missing')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == spec['boot_id'], 'Boot header changed')
    if fresh:
        require(0 <= time.time() - spec['preflight_observed_at'] <= 60, 'Stale initial preflight header')
    token = spec['token']
    require(re.fullmatch(r'[0-9a-f]{12}', token), 'Invalid owned operation token')
    require(Path(path).parent == BASE / ('frozen-' + token)
        and Path(__file__).resolve().parent == Path(path).parent, 'Spec and driver must be frozen siblings')
    require(spec['controller_unit'] == 'hanium-pair-maintenance-controller-' + token + '.service'
        and spec['worker_unit'] == 'hanium-pair-maintenance-job-' + token + '.service'
        and spec['classifier_unit'] == 'hanium-pair-maintenance-classifier-' + token + '.service'
        and spec['rescue_unit'] == 'hanium-pair-maintenance-rescue-' + token, 'Owned unit names changed')
    require(digest(sealed(Path(__file__).resolve())) == spec['driver_sha256'], 'Controller source changed')
    request = sealed(spec['request_file'])
    require(request.parent == Path(path).parent and digest(request) == spec['request_file_sha256']
        and json.loads(request.read_text())['plan_sha256'] == spec['request_sha256'], 'Reviewed request changed')
    reviewed = json.loads(request.read_text())
    require(type(reviewed['scope'].get('allow_capture_appends', False)) is bool
        and reviewed['scope'].get('allow_capture_appends', False) == service_scope(spec)['keep'],
        'Signed capture mode changed')
    require(not service_scope(spec)['keep'] or reviewed.get('capture_session_identity') == spec['capture_session'],
        'Signed retained Capture identity changed')
    artifact = Path(spec['artifact_dir'])
    require(artifact == OPS / token and artifact.resolve() == artifact and artifact.is_dir()
        and artifact.stat().st_uid == 1000 and not artifact.stat().st_mode & 0o077,
        'Owned pi artifact directory required')
    return spec, BASE / token


PI_SESSION = """from contextlib import closing
import json,os,pathlib,sqlite3,sys,time
assert os.getuid()==os.getgid()==1000
path=pathlib.Path('/home/pi/iot-edge-zero-trust/backend/data/iot_security.db')
deadline=time.monotonic()+2
with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.25)) as db:
 db.execute('PRAGMA query_only=ON');db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
 db.row_factory=sqlite3.Row
 row=db.execute('SELECT * FROM packet_capture_sessions WHERE id=?',(int(sys.argv[1]),)).fetchone()
 print(json.dumps(dict(row) if row else {}))
"""


def session_row(spec):
    value = subprocess.run(['/usr/sbin/runuser', '-u', 'pi', '--', '/usr/bin/python3', '-I', '-B',
        '-c', PI_SESSION, str(spec['capture_session_id'])], capture_output=True, text=True, check=True, timeout=3)
    row = json.loads(value.stdout)
    require(row.get('id') == spec['capture_session_id'] and row.get('session_id') == spec['capture_session_uuid'],
            'Fresh actual Capture session identity differs')
    return row


def process_birth(pid):
    return Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]


def verify_retained_capture(spec):
    if not service_scope(spec)['keep']:
        return
    def same_process():
        current = show(CAPTURE)
        return (current['ActiveState'] == 'active'
            and current.get('MainPID') == str(spec['capture_main_pid'])
            and process_birth(spec['capture_main_pid']) == spec['capture_main_birth'])
    require(same_process(), 'Retained Capture process changed')
    current = session_row(spec)
    require(current == spec['capture_session'] and current['status'] == 'RUNNING'
        and current['ended_at'] is None and same_process(), 'Retained Capture full identity changed')


def graceful_capture_term(original):
    pid = int(original['MainPID'])
    descriptor = os.pidfd_open(pid)
    try:
        require(show(CAPTURE)['MainPID'] == str(pid) and process_birth(pid) == original['birth'],
                'Original Capture PID identity changed')
        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
    finally:
        os.close(descriptor)


def hold(state, reason, **fields):
    record(state, 'hold', dict(state='HOLD', reason=reason,
        measured_180_seconds_guarantee=False, root_operating_sqlite_connections=0, **fields))


def stop_owned(unit, group, deadline):
    ctl('--no-block', 'stop', unit, check=False)
    poll(lambda: stopped(unit, group) and unit not in jobs(), deadline,
         'Owned unit not positively terminated: ' + unit)


PROCESSING = frozenset(('detection-orchestrator.service', 'firewall-worker.service'))


def classify(spec, state, original):
    """The stopped pi worker's actual audits decide restoration, never exit code."""
    if not (state / 'worker-launch-requested.json').exists():
        return {'state': 'NOT_STARTED', 'database_committed': False, 'rerun': False}
    verify_retained_capture(spec)
    require(all(stopped(name, original[name].get('ControlGroup')) for name in service_scope(spec)['paused']),
            'Classification requires approved processing units quiescent')
    stop_owned(spec['classifier_unit'], None, time.monotonic() + 5)
    output = state / ('classification-output-' + str(time.monotonic_ns()) + '.json')
    with output.open('x'):
        pass
    output.chmod(0o600)
    subprocess.run(['/usr/bin/systemd-run', '--unit=' + spec['classifier_unit'].removesuffix('.service'),
        '--property=Type=exec', '--property=User=pi', '--property=Group=pi',
        '--property=WorkingDirectory=' + str(PROJECT), '--property=RuntimeMaxSec=20',
        *(('--property=Nice=10', '--property=IOSchedulingClass=idle') if service_scope(spec)['keep'] else ()),
        '--property=TimeoutStopSec=3', '--property=KillMode=control-group',
        '--property=StandardOutput=append:' + str(output),
        *worker_command(spec, 'classify')], check=True, capture_output=True, timeout=3)
    try:
        poll(lambda: stopped(spec['classifier_unit']), time.monotonic() + 23, 'Classifier exceeded bounded read')
        completed = show(spec['classifier_unit'])
        require(completed['Result'] in ('success', 'exit-code')
            and completed['ExecMainStatus'] in ('0', '3'), 'Classifier did not return a complete observation')
        require(output.stat().st_size <= 262144, 'Classifier response oversized')
        result = json.loads(output.read_text())
        require(result.get('request_sha256') == spec['request_sha256']
            and result.get('artifact_dir') == spec['artifact_dir'] and result.get('rerun') is False
            and result.get('state') in ('NOT_COMMITTED_VERIFIED', 'COMMITTED_VERIFIED', 'PARTIAL_HOLD', 'UNKNOWN_HOLD'),
            'Actual classification response binding failed')
        expected = {'NOT_COMMITTED_VERIFIED': (0, False), 'COMMITTED_VERIFIED': (2, True),
                    'PARTIAL_HOLD': (1, True), 'UNKNOWN_HOLD': (None, None)}[result['state']]
        require((result.get('verified_audit_count'), result.get('database_committed')) == expected,
                'Classifier state and verified audit result disagree')
        if expected[0] is not None:
            require(type(result['verified_audit_count']) is int
                and result['database_committed'] is expected[1], 'Classifier result types differ')
            children = result.get('children', {})
            require(set(children) == {'packet_rule', 'packet_if'}
                and all(value in ('PENDING', 'APPLIED') for value in children.values())
                and sum(value == 'APPLIED' for value in children.values()) == expected[0]
                and not (children['packet_if'] == 'APPLIED' and children['packet_rule'] != 'APPLIED'),
                'Classifier child ordering/count differs')
        verify_retained_capture(spec)
        return result
    finally:
        stop_owned(spec['classifier_unit'], None, time.monotonic() + 5)


def restoration_units(original, result, spec=None):
    scope = service_scope(spec or {})
    full = result['state'] in ('NOT_STARTED', 'NOT_COMMITTED_VERIFIED', 'COMMITTED_VERIFIED')
    units = scope['writers'] if scope['keep'] else (CAPTURE, *scope['writers'])
    return [name for name in units if original[name]['ActiveState'] == 'active'
            and (full or name not in scope['held'])]


def restore(spec, state, independent):
    require(state.exists(), 'Original state missing; inspect only')
    if not (BASE / 'active-operation').exists() and finished(state):
        return
    require_owner(spec)
    record(state, 'cancelled', dict(monotonic=time.monotonic()), public=True)
    if independent:
        try:
            group = json.loads((state / 'controller-cgroup.json').read_text())['group']
            stop_owned(spec['controller_unit'], group, time.monotonic() + 5)
        except Exception as error:
            hold(state, 'Controller teardown unproved; no resume: ' + str(error))
            raise
    with (state / 'restore.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        try:
            # A delayed rescuer may have waited while the owner completed.
            if not (BASE / 'active-operation').exists() and finished(state):
                return
            require_owner(spec)
            if not (state / 'pause-requested.json').exists():
                # No shared service action or worker dispatch was possible.
                record(state, 'not-started', dict(service_actions=False, database_committed=False))
                release_operation(spec)
                return
            original = json.loads((state / 'original.json').read_text())
            scope = service_scope(spec)
            receipt = state / 'worker-cgroup.json'
            group = json.loads(receipt.read_text())['group'] if receipt.exists() else None
            stop_owned(spec['worker_unit'], group, time.monotonic() + 5)
            require(stopped(spec['worker_unit'], group), 'Operating writer may remain; no service resume')
            stop_owned(spec['classifier_unit'], None, time.monotonic() + 5)
            require(show(BROKER)['MainPID'] == original[BROKER]['MainPID']
                and show(BROKER)['ActiveState'] == 'active', 'Retained Broker identity changed')
            verify_retained_capture(spec)
            if (state / 'restored.json').exists():
                previous = json.loads((state / 'restored.json').read_text())
                require(all(show(name)['ActiveState'] == 'active' for name in previous['restored_units']),
                    'Previously restored state changed')
                require(all(stopped(name) for name in previous['held_processing_units']), 'Held processing unexpectedly active')
                if finished(state):
                    release_operation(spec)
                return
            if (state / 'capture-term.json').exists() and not (state / 'capture-closed.json').exists():
                poll(lambda: stopped(CAPTURE), time.monotonic() + 5,
                     'Capture TERM not converged; no forced kill/restart race')
            try:
                result = classify(spec, state, original)
            except Exception as error:
                # A failed read never establishes that a write did not happen.
                require(stopped(spec['classifier_unit']), 'Classifier teardown unconfirmed')
                result = {'state': 'UNKNOWN_HOLD', 'database_committed': None, 'rerun': False,
                          'error': type(error).__name__}
            record(state, 'classification', result)
            verify_retained_capture(spec)
            active = restoration_units(original, result, spec)
            full = result['state'] in ('NOT_STARTED', 'NOT_COMMITTED_VERIFIED', 'COMMITTED_VERIFIED')
            timers = [name for name in scope['timers'] if original[name]['ActiveState'] == 'active'
                      and (full or name not in scope['held'])]
            held = [] if full else sorted(name for name in scope['held']
                if scope['keep'] or original[name]['ActiveState'] == 'active')
            require(all(stopped(name, original[name].get('ControlGroup')) for name in held),
                    'Held processing unit unexpectedly active')
            deadline = time.monotonic() + 25
            if active:
                ctl('--no-block', 'start', *active)
            poll(lambda: all(show(name)['ActiveState'] == 'active' for name in active), deadline,
                 'Original active service restoration incomplete')
            require(all(show(name)['ActiveState'] != 'active' for name in scope['paused']
                if original[name]['ActiveState'] != 'active'), 'Originally inactive unit unexpectedly activated')
            if timers:
                ctl('--no-block', 'start', *timers)
            poll(lambda: all(show(name)['ActiveState'] == 'active' for name in timers), deadline,
                 'Original timers did not resume')
            require(all(stopped(name) for name in held), 'Restoration dependency started held processing')
            verify_retained_capture(spec)
            record(state, 'restored', dict(monotonic=time.monotonic(), independent=independent,
                allow_capture_appends=scope['keep'], retained_units=list(scope['retained']),
                elapsed_since_first_stop=time.monotonic() - original['_first_stop'],
                original_active_only=True, measured_180_seconds_guarantee=False,
                worker_quiesced=True, classifier_quiesced=True, root_operating_sqlite_connections=0,
                classification=result['state'], restored_units=active + timers, held_processing_units=held,
                recovery_complete=False))
            if full:
                release_operation(spec)
        except Exception as error:
            hold(state, str(error), error_type=type(error).__name__, services_resume_unverified=True)
            raise


def execute(spec, state):
    service_scope(spec)
    require(not state.exists(), 'One-use state already exists; no retry')
    BASE.mkdir(mode=0o755, exist_ok=True)
    state.mkdir(mode=0o755)
    claim_operation(spec)
    try:
        execute_owned(spec, state)
    except Exception as error:
        hold(state, str(error), error_type=type(error).__name__, audit_classification_required=True)
    finally:
        restore(spec, state, independent=False)
        if (state / 'restored.json').exists():
            ctl('--no-block', 'stop', spec['rescue_unit'] + '.timer', check=False)


def execute_owned(spec, state):
    scope = service_scope(spec)
    owned = show(spec['controller_unit'])
    group = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
    require(owned['MainPID'] == str(os.getpid()) and owned['ControlGroup'] == group,
        'Independent Type=exec controller ownership missing')
    record(state, 'controller-cgroup', dict(group=group))
    original = {unit: show(unit) for unit in ALL}
    require(original[BROKER]['ActiveState'] == 'active' and int(original[BROKER]['MainPID']) > 1,
            'Broker must stay active')
    poll(lambda: not relevant_jobs(spec), time.monotonic() + 3, 'Controller Type=exec startup jobs did not settle')
    require(original[CAPTURE]['ActiveState'] == 'active' and int(original[CAPTURE]['MainPID']) > 1,
            'Fresh active Capture required')
    original[CAPTURE]['birth'] = process_birth(int(original[CAPTURE]['MainPID']))
    require(original[CAPTURE]['MainPID'] == str(spec['capture_main_pid'])
        and original[CAPTURE]['birth'] == spec['capture_main_birth'], 'Capture preflight PID/birth pin changed')
    require(original['detection-orchestrator.service']['ActiveState'] != 'active'
        or original['mqtt-feature-builder.service']['ActiveState'] == 'active',
        'Orchestrator Wants builder would change originally inactive state')
    original['_first_stop'] = time.monotonic()
    record(state, 'original', original)
    record(state, 'launch', dict(command=worker_command(spec, 'execute'), cwd=str(PROJECT),
        request_file=spec['request_file'], request_file_sha256=spec['request_file_sha256'],
        driver_sha256=spec['driver_sha256'], boot_id=spec['boot_id']), public=True)
    subprocess.run(['/usr/bin/systemd-run', '--unit=' + spec['rescue_unit'], '--on-active=150s',
        '--timer-property=AccuracySec=1s', '--property=Type=exec', '--property=TimeoutStopSec=3',
        '--property=KillMode=control-group', '/usr/bin/python3', '-I', '-B', str(Path(__file__).resolve()),
        '--rescue', '--spec', spec['spec_file']], check=True, capture_output=True, timeout=3)
    require(show(spec['rescue_unit'] + '.timer')['ActiveState'] == 'active', 'Independent rescue timer not armed')
    try:
        fresh = session_row(spec)
        require(fresh['status'] == 'RUNNING' and fresh['ended_at'] is None, 'Fresh Capture is not RUNNING')
        require(fresh == spec['capture_session'], 'Capture full identity changed')
        record(state, 'capture-before', fresh)
        record(state, 'pause-requested', dict(monotonic=time.monotonic()))
        if scope['keep']:
            verify_retained_capture(spec)
        else:
            record(state, 'capture-term', dict(monotonic=time.monotonic()))
            graceful_capture_term(original[CAPTURE])
            poll(lambda: stopped(CAPTURE) and show(CAPTURE)['ActiveState'] == 'inactive'
                and show(CAPTURE)['Result'] == 'success' and show(CAPTURE)['ExecMainStatus'] == '0',
                time.monotonic() + 15, 'Capture graceful TERM incomplete; recovery forbidden')
            closed = session_row(spec)
            require(closed['status'] == 'COMPLETED' and closed['ended_at'] is not None,
                    'Actual Capture closure unproved; recovery forbidden')
            record(state, 'capture-closed', closed)
        ctl('--no-block', 'stop', *scope['timers'])
        poll(lambda: all(stopped(name) for name in scope['timers']), time.monotonic() + 3, 'Writer timers did not stop')
        require(all(show(name)['ActiveState'] != 'active' for name in scope['writers']
            if original[name]['ActiveState'] != 'active'), 'Previously inactive writer started during timer stop')
        active = [name for name in scope['writers'] if original[name]['ActiveState'] == 'active']
        if active:
            ctl('--no-block', 'stop', *active)
        poll(lambda: all(stopped(name, original[name].get('ControlGroup')) for name in scope['writers'])
            and not relevant_jobs(spec), time.monotonic() + 30, 'Operating writers not quiescent; recovery forbidden')
        verify_retained_capture(spec)
        require(not (state / 'cancelled.json').exists(), 'Rescue cancelled operation before private launch')
        record(state, 'worker-launch-requested', dict(monotonic=time.monotonic()))
        subprocess.run(['/usr/bin/systemd-run', '--unit=' + spec['worker_unit'].removesuffix('.service'),
            '--property=Type=exec', '--property=User=pi', '--property=Group=pi', '--property=RuntimeMaxSec=90',
            '--property=TimeoutStopSec=3', '--property=KillMode=control-group',
            *(('--property=Nice=10', '--property=IOSchedulingClass=idle') if scope['keep'] else ('--property=Nice=0',)),
            '/usr/bin/python3', '-I', '-B', str(Path(__file__).resolve()), '--worker', '--state', str(state)],
            check=True, capture_output=True, timeout=3)
        private = show(spec['worker_unit'])
        require(private['ActiveState'] == 'active' and int(private['MainPID']) > 1
            and private['User'] == private['Group'] == 'pi', 'Recovery UID unit missing')
        record(state, 'worker-cgroup', dict(group=private['ControlGroup']))
        poll(lambda: not relevant_jobs(spec), time.monotonic() + 3, 'Type=exec startup job did not settle')
        require(all(stopped(name, original[name].get('ControlGroup')) for name in scope['paused'])
            and not (state / 'cancelled.json').exists(), 'Inactive/uncancelled accepted-GO gate failed')
        verify_retained_capture(spec)
        record(state, 'accepted', dict(monotonic=time.monotonic()), public=True)
        poll(lambda: stopped(spec['worker_unit'], private['ControlGroup']), time.monotonic() + 93,
             'Recovery worker exceeded90s+teardown; HOLD')
        verify_retained_capture(spec)
        record(state, 'worker-exited', dict(monotonic=time.monotonic(),
            service_result=show(spec['worker_unit'])['Result'],
            exit_status=show(spec['worker_unit'])['ExecMainStatus'], classification_required=True))
    except Exception as error:
        hold(state, str(error), error_type=type(error).__name__, audit_classification_required=True)


def worker(state):
    require(os.getuid() == os.getgid() == 1000, 'Recovery worker UID1000 only')
    state = Path(state)
    require(state.parent == BASE and re.fullmatch(r'[0-9a-f]{12}', state.name), 'Owned state path required')
    launch = json.loads(sealed(state / 'launch.json').read_text())
    require(digest(sealed(Path(__file__).resolve())) == launch['driver_sha256']
        and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == launch['boot_id'], 'Worker source/Boot changed')
    poll(lambda: (state / 'accepted.json').exists() or (state / 'cancelled.json').exists(),
         time.monotonic() + 6, 'Root accepted-GO missing')
    require(not (state / 'cancelled.json').exists() and (state / 'accepted.json').exists(), 'Late cancelled worker forbidden')
    sealed(state / 'accepted.json')
    require(digest(sealed(launch['request_file'])) == launch['request_file_sha256'], 'Worker request changed')
    require(launch['cwd'] == str(PROJECT) and launch['command'][:4] ==
        [str(PROJECT / 'venv/bin/python'), '-B', '-m', 'edge.detection.packet_pair_maintenance_worker'],
        'Worker command changed')
    # Deliberately preserve real project .env/lock configuration; never use an in-memory DB override.
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/home/pi', 'PYTHONDONTWRITEBYTECODE': '1',
           'OMP_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1'}
    result = subprocess.run(launch['command'], cwd=launch['cwd'], env=env)
    raise SystemExit(result.returncode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--rescue', action='store_true')
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--spec', type=Path)
    parser.add_argument('--state', type=Path)
    args = parser.parse_args()
    require(sum((args.execute, args.rescue, args.worker)) <= 1, 'Choose one role')
    if not any((args.execute, args.rescue, args.worker)):
        print(json.dumps(dict(status='HOLD', execution_ready=False, root_operating_sqlite_connections=0,
            service_actions=False, measured_180_seconds_guarantee=False)))
        return
    if args.worker:
        worker(args.state)
        return
    spec, state = load_spec(args.spec, fresh=args.execute)
    spec['spec_file'] = str(sealed(args.spec))
    if args.execute:
        execute(spec, state)
    else:
        restore(spec, state, independent=True)


if __name__ == '__main__':
    main()
