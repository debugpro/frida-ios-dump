#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : AloneMonkey
# blog: www.alonemonkey.com

from __future__ import print_function
from __future__ import unicode_literals
import sys
import codecs
import frida
import threading
import queue
import os
import shutil
import time
import argparse
import tempfile
import subprocess
import re
import paramiko
from paramiko import SSHClient
from scp import SCPClient
from tqdm import tqdm
import traceback
import getpass
import json
import frida_tools
from pathlib import Path

IS_PY2 = sys.version_info[0] < 3
if IS_PY2:
    reload(sys)
    sys.setdefaultencoding('utf8')

script_dir = os.path.dirname(os.path.realpath(__file__))

DUMP_JS = os.path.join(script_dir, 'dump.js')
DEFAULT_KNOWN_HOSTS = str(Path(script_dir) / '.known_hosts')

User = 'root'
Password = None
Host = '127.0.0.1'
Port = 2222
KeyFileName = None

TEMP_DIR = None
PAYLOAD_DIR = 'Payload'
PAYLOAD_PATH = None
file_dict = {}

messages = queue.Queue()
dump_report = {'tool': 'frida-ios-dump', 'frida': frida.__version__, 'modules': []}
transfer_total = 0
last_progress_at = 0.0

def save_report():
    Path('dump-report.json').write_text(json.dumps(dump_report, ensure_ascii=False, indent=2) + '\n')


class DeviceHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Remember a device's first SSH key, independently of the forwarded port."""

    def __init__(self, path, alias):
        self.path = Path(path)
        self.alias = alias

    def missing_host_key(self, client, hostname, key):
        known = paramiko.HostKeys()
        if self.path.exists():
            known.load(str(self.path))
        pinned = known.lookup(self.alias)
        if pinned:
            expected = pinned.get(key.get_name()) or next(iter(pinned.values()))
            if expected != key:
                raise paramiko.BadHostKeyException(self.alias, key, expected)
        else:
            known.add(self.alias, key.get_name(), key)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix='.known_hosts-', dir=str(self.path.parent))
            os.close(fd)
            try:
                known.save(temporary)
                os.replace(temporary, self.path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            print('Saved SSH device key: {} ({})'.format(self.alias, self.path), flush=True)
        client.get_host_keys().add(hostname, key.get_name(), key)


def create_ssh_client(host, port, known_hosts_path, host_key_alias):
    known = paramiko.HostKeys()
    if Path(known_hosts_path).exists():
        known.load(known_hosts_path)
    client = paramiko.SSHClient()
    pinned = known.lookup(host_key_alias)
    if pinned:
        hostkey_name = host if int(port) == 22 else '[{}]:{}'.format(host, port)
        for algorithm, key in pinned.items():
            client.get_host_keys().add(hostkey_name, algorithm, key)
    client.set_missing_host_key_policy(DeviceHostKeyPolicy(known_hosts_path, host_key_alias))
    return client



def get_usb_iphone():
    Type = 'usb'
    if int(frida.__version__.split('.')[0]) < 12:
        Type = 'tether'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)

    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == Type]
        if len(devices) == 0:
            print('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]

    device_manager.off('changed', on_changed)

    return device


def generate_ipa(path, display_name):
    ipa_filename = display_name + '.ipa'

    print('Generating "{}"'.format(ipa_filename))
    try:
        app_name = file_dict['app']

        for key, value in file_dict.items():
            from_dir = os.path.join(path, key)
            to_dir = os.path.join(path, app_name, value)
            if key != 'app':
                shutil.move(from_dir, to_dir)

        target_dir = './' + PAYLOAD_DIR
        zip_args = ('zip', '-1qry', os.path.join(os.getcwd(), ipa_filename), target_dir)
        subprocess.check_call(zip_args, cwd=TEMP_DIR)
        dump_report['ipa'] = os.path.abspath(ipa_filename)
        dump_report['packaged'] = True
        save_report()
    except Exception as e:
        print(e)
        raise


def download(remote_path, local_path, progress, recursive=False, expected_size=None):
    """Retry independent SCP channels, without exposing partially received modules."""
    destination = Path(local_path)
    partial = destination if recursive else destination.with_name(destination.name + '.part')
    for attempt in range(1, 4):
        transport = ssh.get_transport()
        if transport is None or not transport.is_active():
            raise RuntimeError('SSH connection closed before downloading ' + remote_path)
        scp = SCPClient(transport, progress=progress, socket_timeout=60)
        try:
            scp.get(remote_path, str(partial), recursive=recursive)
            if not recursive:
                actual_size = partial.stat().st_size
                if expected_size is not None and actual_size != expected_size:
                    raise RuntimeError('Received {} of {} bytes'.format(actual_size, expected_size))
                partial.replace(destination)
            return
        except Exception as error:
            channel = scp.channel
            detail = {'path': remote_path, 'attempt': attempt, 'error': str(error),
                      'ssh_active': transport.is_active()}
            if not recursive and partial.exists():
                detail['received_bytes'] = partial.stat().st_size
            if channel is not None:
                if channel.recv_stderr_ready():
                    detail['stderr'] = channel.recv_stderr(4096).decode('utf-8', errors='replace')
                if channel.exit_status_ready():
                    detail['remote_exit_status'] = channel.recv_exit_status()
                # Close first: scp.close() otherwise waits indefinitely for an exit status.
                channel.close()
            dump_report.setdefault('transfer_attempt_errors', []).append(detail)
            save_report()
            if attempt == 3 or not transport.is_active():
                raise RuntimeError('Download failed for {}: {}'.format(remote_path, error)) from error
            print('Transfer interrupted; retrying file ({}/3): {}'.format(attempt + 1, Path(remote_path).name), flush=True)
        finally:
            scp.close()

def handle_transfer(message, data):
    t = tqdm(unit='B',unit_scale=True,unit_divisor=1024,miniters=1,disable=True)
    last_sent = [0]

    def progress(filename, size, sent):
        global transfer_total, last_progress_at
        if sent == 0:
            last_sent[0] = 0
        transfer_total += max(0, sent - last_sent[0])
        now = time.monotonic()
        if now - last_progress_at >= 5:
            print('Downloaded {:.1f} MiB'.format(transfer_total / 1024**2), flush=True)
            last_progress_at = now
        baseName = os.path.basename(filename)
        if IS_PY2 or isinstance(baseName, bytes):
            t.desc = baseName.decode("utf-8")
        else:
            t.desc = baseName
        t.total = size
        t.update(sent - last_sent[0])
        last_sent[0] = 0 if size == sent else sent

    if 'payload' in message:
        payload = message['payload']
        if 'dump' in payload:
            origin_path = payload['path']
            dump_path = payload['dump']

            scp_from = dump_path
            scp_to = os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))
            download(scp_from, scp_to, progress,
                     expected_size=payload.get('detail', {}).get('output_size'))

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))
            chmod_args = ('chmod', '755', chmod_dir)
            try:
                subprocess.check_call(chmod_args)
            except subprocess.CalledProcessError as err:
                print(err)

            index = origin_path.find('.app/')
            file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]

        if 'app' in payload:
            app_path = payload['app']

            scp_from = app_path
            scp_to = PAYLOAD_PATH + '/'
            download(scp_from, scp_to, progress, recursive=True)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(app_path))
            chmod_args = ('chmod', '755', chmod_dir)
            try:
                subprocess.check_call(chmod_args)
            except subprocess.CalledProcessError as err:
                print(err)

            file_dict['app'] = os.path.basename(app_path)

    t.close()

def on_message(message, data):
    # Frida callbacks must not perform network I/O or race SSH teardown.
    messages.put((message, data))


def process_message(script, message, data):
    if message.get('type') == 'log':
        print('[agent] ' + str(message.get('payload', '')), flush=True)
        return
    payload = message.get('payload', {})
    if message.get('type') == 'error' or 'dump_error' in payload:
        detail = message.get('stack', payload.get('stack', str(message)))
        raise RuntimeError('Agent error: ' + detail)
    if 'dump_directory' in payload:
        dump_report['remote_staging'] = payload['dump_directory']
    if 'app' in payload:
        print('Downloading application bundle...', flush=True)
        dump_report['bundle'] = payload['app']
    handle_transfer(message, data)
    if 'dump' in payload:
        dump_report['modules'].append({'source': payload['path'], 'remote_dump': payload['dump'], **payload.get('detail', {})})
        print('Saved decrypted module: ' + payload.get('detail', {}).get('name', '?'), flush=True)
    if 'done' in payload:
        dump_report['expected_module_count'] = payload['module_count']
    save_report()
    if 'dump' in payload or 'app' in payload:
        script.post({'type': 'transfer-result', 'ok': True})
    return 'done' in payload

def compare_applications(a, b):
    a_is_running = a.pid != 0
    b_is_running = b.pid != 0
    if a_is_running == b_is_running:
        if a.name > b.name:
            return 1
        elif a.name < b.name:
            return -1
        else:
            return 0
    elif a_is_running:
        return -1
    else:
        return 1


def cmp_to_key(mycmp):
    """Convert a cmp= function into a key= function"""

    class K:
        def __init__(self, obj):
            self.obj = obj

        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0

        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0

        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0

        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0

        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0

        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0

    return K


def get_applications(device):
    try:
        applications = device.enumerate_applications()
    except Exception as e:
        sys.exit('Failed to enumerate applications: %s' % e)

    return applications


def list_applications(device):
    applications = get_applications(device)

    if len(applications) > 0:
        pid_column_width = max(map(lambda app: len('{}'.format(app.pid)), applications))
        name_column_width = max(map(lambda app: len(app.name), applications))
        identifier_column_width = max(map(lambda app: len(app.identifier), applications))
    else:
        pid_column_width = 0
        name_column_width = 0
        identifier_column_width = 0

    header_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(
        identifier_column_width) + 's'
    print(header_format % ('PID', 'Name', 'Identifier'))
    print('%s  %s  %s' % (pid_column_width * '-', name_column_width * '-', identifier_column_width * '-'))
    line_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(
        identifier_column_width) + 's'
    for application in sorted(applications, key=cmp_to_key(compare_applications)):
        if application.pid == 0:
            print(line_format % ('-', application.name, application.identifier))
        else:
            print(line_format % (application.pid, application.name, application.identifier))


def load_js_file(session, filename):
    bridge = (Path(frida_tools.__file__).parent / 'bridges/objc.js').read_text()
    source = 'var ObjC = (function(){\n' + bridge + '\nreturn bridge;})();\n'
    source += (Path(script_dir) / 'compat17.js').read_text() + '\n'
    with open(filename, 'r', encoding='utf-8') as f:
        source = source + f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()

    return script


def create_dir(path):
    path = path.strip()
    path = path.rstrip('\\')
    if os.path.exists(path):
        shutil.rmtree(path)
    try:
        os.makedirs(path)
    except os.error as err:
        print(err)


def open_target_app(device, name_or_bundleid):
    print('Start the target app {}'.format(name_or_bundleid))

    pid = ''
    session = None
    display_name = ''
    bundle_identifier = ''
    for application in get_applications(device):
        if name_or_bundleid == application.identifier or name_or_bundleid == application.name:
            pid = application.pid
            display_name = application.name
            bundle_identifier = application.identifier

    try:
        if not pid:
            pid = device.spawn([bundle_identifier])
            session = device.attach(pid, thread_suspend_monitor=False, unwind_broker=False)
            device.resume(pid)
        else:
            session = device.attach(pid, thread_suspend_monitor=False, unwind_broker=False)
    except Exception as e:
        print(e)

    if session is None:
        raise RuntimeError('Could not attach to the requested application')
    keeper = session.create_script('void 0;')
    keeper.load()
    keeper.eternalize()
    dump_report.update(pid=pid, bundle_identifier=bundle_identifier,
                       session_options={'thread_suspend_monitor': False, 'unwind_broker': False},
                       keep_empty_agent_until_app_exit=True)
    save_report()
    return session, display_name, bundle_identifier


def start_dump(session, ipa_name):
    print('Dumping {} to {}'.format(display_name, TEMP_DIR))

    script = None
    try:
        script = load_js_file(session, DUMP_JS)
        preflight = script.exports_sync.preflight()
        dump_report['preflight'] = preflight
        save_report()
        if not preflight['objc']:
            raise RuntimeError('Objective-C bridge unavailable')
        print('Agent ready: PID {}, {} app modules'.format(preflight['pid'], len(preflight['modules'])), flush=True)
        script.post({'type': 'dump'})
        deadline = time.monotonic() + 1200
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Dump did not complete within 20 minutes')
            try:
                message, data = messages.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError('Dump did not complete within 20 minutes') from None
            if process_message(script, message, data):
                break
        expected = dump_report.get('expected_module_count')
        if expected is None or len(dump_report['modules']) != expected:
            raise RuntimeError('Incomplete module transfer')
        generate_ipa(PAYLOAD_PATH, ipa_name)
    except BaseException as error:
        dump_report['errors'] = [str(error) or type(error).__name__]
        if script is not None:
            try:
                script.post({'type': 'transfer-result', 'ok': False})
            except Exception:
                pass
        save_report()
        raise
    finally:
        if script is not None:
            script.off('message', on_message)
        if session:
            cancel = frida.Cancellable()
            timer = threading.Timer(10, cancel.cancel)
            timer.start()
            try:
                with cancel:
                    session.detach()
                dump_report['detached'] = True
            except Exception as error:
                dump_report['detach_error'] = str(error)
            finally:
                timer.cancel()
            save_report()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='frida-ios-dump (by AloneMonkey v2.0)')
    parser.add_argument('-l', '--list', dest='list_applications', action='store_true', help='List the installed apps')
    parser.add_argument('-o', '--output', dest='output_ipa', help='Specify name of the decrypted IPA')
    parser.add_argument('-H', '--host', dest='ssh_host', help='SSH hostname (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', dest='ssh_port', type=int, help='SSH port (default: 2222)')
    parser.add_argument('-u', '--user', dest='ssh_user', help='Specify SSH username')
    parser.add_argument('-P', '--password', dest='ssh_password', help='Specify SSH password')
    parser.add_argument('-K', '--key_filename', dest='ssh_key_filename', help='Specify SSH private key file path')
    parser.add_argument('--known-hosts', default=DEFAULT_KNOWN_HOSTS,
                        help='SSH device-key cache, created on first connection (default: .known_hosts next to this script)')
    parser.add_argument('--host-key-alias',
                        help='SSH device-key alias (default: ios-trace-usb- plus the USB device ID prefix)')
    parser.add_argument('target', nargs='?', help='Bundle identifier or display name of the target app')

    args = parser.parse_args()

    exit_code = 0
    ssh = None

    if not len(sys.argv[1:]):
        parser.print_help()
        sys.exit(exit_code)

    if not args.list_applications:
        if not args.target:
            parser.error('specify a target application or use --list')

    device = get_usb_iphone()

    if args.list_applications:
        list_applications(device)
        sys.exit(0)
    else:
        name_or_bundleid = args.target
        output_ipa = args.output_ipa
        # update ssh args
        if args.ssh_host:
            Host = args.ssh_host
        if args.ssh_port:
            Port = int(args.ssh_port)
        if args.ssh_user:
            User = args.ssh_user
        if args.ssh_password:
            Password = args.ssh_password
        if args.ssh_key_filename:
            KeyFileName = args.ssh_key_filename

        try:
            known_hosts_path = str(Path(args.known_hosts).expanduser().resolve())
            host_key_alias = args.host_key_alias or 'ios-trace-usb-' + device.id[:8]
            ssh = create_ssh_client(Host, Port, known_hosts_path, host_key_alias)
            print('SSH {}@{}:{} (device key: {})'.format(User, Host, Port, host_key_alias), flush=True)
            dump_report['ssh'] = {'host': Host, 'port': Port, 'user': User,
                                  'known_hosts': known_hosts_path, 'host_key_alias': host_key_alias}
            if Password is None and KeyFileName is None:
                Password = getpass.getpass('iPhone SSH password: ')
            ssh.connect(Host, port=Port, username=User, password=Password, key_filename=KeyFileName,
                        look_for_keys=False, allow_agent=False, timeout=10)
            ssh.get_transport().set_keepalive(15)
            Password = None

            TEMP_DIR = tempfile.mkdtemp(prefix='work-', dir=os.environ.get('FRIDA_DUMP_WORKDIR', tempfile.gettempdir()))
            PAYLOAD_PATH = os.path.join(TEMP_DIR, PAYLOAD_DIR)
            dump_report['staging'] = TEMP_DIR
            create_dir(PAYLOAD_PATH)
            (session, display_name, bundle_identifier) = open_target_app(device, name_or_bundleid)
            if output_ipa is None:
                output_ipa = display_name
            output_ipa = re.sub(r'\.ipa$', '', output_ipa)
            if session:
                start_dump(session, output_ipa)
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            print(e)
            print('Try specifying -H/--hostname and/or -p/--port')
            exit_code = 1
        except paramiko.AuthenticationException as e:
            print(e)
            print('Try specifying -u/--username and/or -P/--password')
            exit_code = 1
        except Exception as e:
            print('*** Caught exception: %s: %s' % (e.__class__, e))
            traceback.print_exc()
            exit_code = 1

    if ssh:
        ssh.close()

    # Preserve this run's isolated staging until archive validation is finished.
    dump_report['exit_code'] = exit_code
    save_report()
    sys.exit(exit_code)
