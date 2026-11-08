#!/usr/bin/env python3
"""Run bounded ModelGate process fixtures in a Windows kill-on-close Job Object.

No Docker/Kubernetes client, shared cluster, service or existing process is queried.
Only this runner's suspended child and its descendants enter the job.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def run(command, output, timeout, assets, toolchain=None, workdir=None):
    if os.name != 'nt':
        raise RuntimeError('This runner specifically enforces Windows Job Object isolation')
    workdir = (workdir or ROOT).resolve()
    if not workdir.is_relative_to(ROOT) or not workdir.is_dir():
        raise ValueError('Working directory must be an existing directory within this repository')
    output = output.resolve()
    if not output.is_relative_to(ROOT / '.tools'):
        raise ValueError('Evidence and fixture state must remain under repository .tools')
    output.mkdir(parents=True, exist_ok=False)
    tmp = output / 'tmp'
    tmp.mkdir()
    env = {key: value for key, value in os.environ.items() if key.upper() in {
        'PATH', 'SYSTEMROOT', 'WINDIR', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'HOMEDRIVE', 'HOMEPATH'}}
    env.update(TEMP=str(tmp), TMP=str(tmp), KUBECONFIG=str(tmp / 'nonexistent-kubeconfig'),
               USE_EXISTING_CLUSTER='false', GOPROXY='off', GOSUMDB='off',
               GOMAXPROCS='2', GOMEMLIMIT='512MiB', CGO_ENABLED='0',
               KUBEBUILDER_CONTROLPLANE_START_TIMEOUT='60s', KUBEBUILDER_CONTROLPLANE_STOP_TIMEOUT='5s',
               MODELGATE_EVIDENCE_DIR=str(output))
    env['GOTOOLCHAIN'] = 'local'
    if toolchain:
        toolchain = toolchain.resolve()
        if not (toolchain / 'bin/go.exe').is_file():
            raise ValueError('Explicit installed toolchain root has no bin/go.exe')
        env['GOROOT'] = str(toolchain)
        env['PATH'] = str(toolchain / 'bin') + os.pathsep + env.get('PATH', '')
    if assets:
        env['KUBEBUILDER_ASSETS'] = str(assets.resolve())
        env['MODELGATE_NATIVE_ADMISSION'] = '1'
    oracle = Path(os.environ.get('MODELGATE_TEST_TOOLS', ROOT / '.tools/test-tools'))
    env['PATH'] = str(oracle) + os.pathsep + env.get('PATH', '')
    executable = shutil.which(command[0], path=env['PATH'])
    if not executable:
        raise RuntimeError('Requested executable not found')
    command = [executable, *command[1:]]
    k = c.WinDLL('kernel32', use_last_error=True)
    size = c.c_size_t

    class Basic(c.Structure):
        _fields_ = [('process_time', c.c_int64), ('job_time', c.c_int64), ('flags', w.DWORD),
                    ('min_ws', size), ('max_ws', size), ('active', w.DWORD), ('affinity', size),
                    ('priority', w.DWORD), ('scheduling', w.DWORD)]

    class IO(c.Structure):
        _fields_ = [(name, c.c_uint64) for name in ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]

    class Limits(c.Structure):
        _fields_ = [('basic', Basic), ('io', IO), ('process_memory', size), ('job_memory', size), ('peak_process', size), ('peak_job', size)]

    class Accounting(c.Structure):
        _fields_ = [(name, c.c_int64) for name in ('user', 'kernel', 'period_user', 'period_kernel')] + [(name, w.DWORD) for name in ('faults', 'processes', 'active', 'terminated')]

    class Startup(c.Structure):
        _fields_ = [('cb', w.DWORD), ('reserved', w.LPWSTR), ('desktop', w.LPWSTR), ('title', w.LPWSTR),
                    *[(name, w.DWORD) for name in ('x', 'y', 'xsize', 'ysize', 'xchars', 'ychars', 'fill', 'flags')],
                    ('show', w.WORD), ('reserved_size', w.WORD), ('reserved_data', c.POINTER(c.c_byte)),
                    ('stdin', w.HANDLE), ('stdout', w.HANDLE), ('stderr', w.HANDLE)]

    class Process(c.Structure):
        _fields_ = [('process', w.HANDLE), ('thread', w.HANDLE), ('pid', w.DWORD), ('tid', w.DWORD)]

    k.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]
    k.CreateJobObjectW.restype = w.HANDLE
    for name in ('SetInformationJobObject', 'QueryInformationJobObject'):
        getattr(k, name).argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p] if name.startswith('Query') else [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
        getattr(k, name).restype = w.BOOL
    k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    k.AssignProcessToJobObject.restype = w.BOOL
    k.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
    k.TerminateJobObject.restype = w.BOOL
    k.CloseHandle.argtypes = [w.HANDLE]
    k.CreateProcessW.argtypes = [w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD,
                                c.c_void_p, w.LPCWSTR, c.POINTER(Startup), c.POINTER(Process)]
    k.CreateProcessW.restype = w.BOOL
    k.ResumeThread.argtypes = [w.HANDLE]
    k.ResumeThread.restype = w.DWORD
    k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    k.WaitForSingleObject.restype = w.DWORD
    k.GetExitCodeProcess.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
    job = k.CreateJobObjectW(None, None)
    if not job:
        raise c.WinError(c.get_last_error())
    limits = Limits()
    limits.basic.flags = 0x2000 | 0x200 | 0x8  # kill-on-close, total memory, process count
    limits.basic.active = 128
    limits.job_memory = 2 * 1024**3
    process = Process()
    receipt = {'command': command, 'timeout_seconds': timeout, 'job_memory_limit_bytes': limits.job_memory,
               'max_processes': 128, 'shared_runtime_access': False, 'temporary_root': str(tmp),
               'existing_cluster': False, 'assets': str(assets) if assets else None}

    def members():
        buffer = c.create_string_buffer(8 + c.sizeof(size) * 128)
        if not k.QueryInformationJobObject(job, 3, buffer, len(buffer), None):
            raise c.WinError(c.get_last_error())
        count = c.cast(buffer, c.POINTER(w.DWORD))[1]
        return [int(value) for value in (size * count).from_buffer(buffer, 8)]

    started = time.monotonic()
    try:
        if not k.SetInformationJobObject(job, 9, c.byref(limits), c.sizeof(limits)):
            raise c.WinError(c.get_last_error())
        import msvcrt
        with (output / 'output.log').open('wb') as log, open(os.devnull, 'rb') as null:
            for stream in (log, null):
                os.set_handle_inheritable(msvcrt.get_osfhandle(stream.fileno()), True)
            si = Startup()
            si.cb = c.sizeof(si)
            si.flags = 0x100
            si.stdin = msvcrt.get_osfhandle(null.fileno())
            si.stdout = si.stderr = msvcrt.get_osfhandle(log.fileno())
            environment = c.create_unicode_buffer(''.join(key + '=' + value + '\0' for key, value in sorted(env.items())) + '\0')
            if not k.CreateProcessW(executable, c.create_unicode_buffer(subprocess.list2cmdline(command)), None, None,
                                    True, 0x4 | 0x400 | 0x08000000, environment, str(workdir), c.byref(si), c.byref(process)):
                raise c.WinError(c.get_last_error())
            if not k.AssignProcessToJobObject(job, process.process):
                # The child is still suspended and has not run any code.
                k.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
                k.TerminateProcess(process.process, 125)
                raise c.WinError(c.get_last_error())
            receipt['root_pid'] = process.pid
            (output / 'running.json').write_text(json.dumps({'root_pid': process.pid, 'command': command, 'started_utc': __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()}))
            if k.ResumeThread(process.thread) == 0xffffffff:
                raise c.WinError(c.get_last_error())
            until = time.monotonic() + timeout
            wait = 258
            while time.monotonic() < until:
                wait = k.WaitForSingleObject(process.process, 100)
                if wait != 258 or (output / 'cancel').exists():
                    break
            exit_code = w.DWORD()
            k.GetExitCodeProcess(process.process, c.byref(exit_code))
            receipt['exit'] = 'TIMEOUT' if wait == 258 else int(exit_code.value)
            receipt['owned_pids_before_cleanup'] = members()
            measured = Limits()
            if k.QueryInformationJobObject(job, 9, c.byref(measured), c.sizeof(measured), None):
                receipt['peak_job_memory_bytes'] = measured.peak_job
            accounting = Accounting()
            if k.QueryInformationJobObject(job, 1, c.byref(accounting), c.sizeof(accounting), None):
                receipt['process_tree_user_cpu_seconds'] = accounting.user / 10_000_000
                receipt['process_tree_kernel_cpu_seconds'] = accounting.kernel / 10_000_000
                receipt['resource_scope'] = 'whole command including compilation/setup, client, webhook and fixture processes; not phase-specific'
    finally:
        k.TerminateJobObject(job, 125)
        for _ in range(100):
            if not members():
                break
            time.sleep(.05)
        receipt['owned_pids_after_cleanup'] = members()
        receipt['elapsed_seconds'] = time.monotonic() - started
        for handle in (process.thread, process.process, job):
            if handle:
                k.CloseHandle(handle)
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2))
    return 0 if receipt.get('exit') == 0 and receipt['owned_pids_after_cleanup'] == [] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=240, choices=range(1, 301))
    parser.add_argument('--assets', type=Path)
    parser.add_argument('--toolchain', type=Path, help='explicit already-installed Go root; no toolchain downloads')
    parser.add_argument('--workdir', type=Path, help='existing repository-confined candidate directory')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('an explicit command is required')
    raise SystemExit(run(command, args.output, args.timeout, args.assets, args.toolchain, args.workdir))
