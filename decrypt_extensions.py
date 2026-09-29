#!/usr/bin/env python3
"""Fill encrypted appex ranges in a frida-ios-dump staging directory."""
import argparse
import contextlib
import hashlib
import json
import shutil
import struct
import threading
from pathlib import Path

import frida


@contextlib.contextmanager
def deadline(seconds):
    cancel = frida.Cancellable()
    timer = threading.Timer(seconds, cancel.cancel)
    timer.start()
    try:
        with cancel:
            yield
    finally:
        timer.cancel()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    root = args.directory.resolve()
    report = json.loads((root / 'dump-report.json').read_text())
    originals = json.loads((root / 'original-encryption.json').read_text())
    app = Path(report['staging']) / 'Payload/Taobao4iPhone.app'
    result = {'method': 'Frida mremap_encrypted supplement', 'pid': report['pid'], 'extensions': []}
    output = root / 'extension-decryption.json'
    original_dir = root / 'original-extensions'
    original_dir.mkdir(exist_ok=True)
    session = None

    def save():
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')

    def request(row, local):
        arch, = row['slices']
        enc, = arch['encryption']
        return {'path': row['path'], 'size': local.stat().st_size, **enc}

    try:
        device = frida.get_usb_device(timeout=5)
        with deadline(20):
            session = device.attach(report['pid'], thread_suspend_monitor=False, unwind_broker=False)
        keeper = session.create_script('void 0;')
        keeper.load()
        keeper.eternalize()
        script = session.create_script(Path(__file__).with_suffix('.js').read_text())
        with deadline(10):
            script.load()
        # Verify this method against the already dumped main executable before any patch.
        req = request(originals[0], app / 'Taobao4iPhone')
        with deadline(20):
            block = script.exports_sync.decrypt(req)
        with (app / 'Taobao4iPhone').open('rb') as stream:
            stream.seek(req['cryptoff'])
            expected = stream.read(req['cryptsize'])
        if block != expected:
            raise ValueError('Mapped plaintext differs from main-process frida-ios-dump output')
        result['main_cross_check_sha256'] = digest(block)
        save()
        print('Main decrypted bytes match frida-ios-dump', flush=True)
        for index, row in enumerate(originals[1:], 1):
            relative = row['path'].split('.app/', 1)[1]
            local = app / relative
            req = request(row, local)
            before = local.read_bytes()
            if struct.unpack_from('<I', before, req['cryptid_file_offset'])[0] != 1:
                raise ValueError('Expected original encrypted extension: ' + relative)
            with deadline(20):
                plaintext = script.exports_sync.decrypt(req)
            if len(plaintext) != req['cryptsize']:
                raise ValueError('Truncated plaintext')
            start, end = req['cryptoff'], req['cryptoff'] + req['cryptsize']
            ciphertext = before[start:end]
            if plaintext == ciphertext:
                raise ValueError('Encryption range did not change: ' + relative)
            shutil.copy2(local, original_dir / (str(index) + '.bin'))
            after = bytearray(before)
            after[start:end] = plaintext
            struct.pack_into('<I', after, req['cryptid_file_offset'], 0)
            temp = local.with_name(local.name + '.decrypted-tmp')
            temp.write_bytes(after)
            temp.chmod(local.stat().st_mode & 0o777)
            temp.replace(local)
            result['extensions'].append({'path': relative, 'bytes': len(after),
                'original_sha256': digest(before), 'decrypted_sha256': digest(after),
                'ciphertext_sha256': digest(ciphertext), 'plaintext_sha256': digest(plaintext),
                'cryptoff': start, 'cryptsize': req['cryptsize'], 'cryptid': 0,
                'changed_bytes_in_encrypted_range': sum(a != b for a, b in zip(ciphertext, plaintext))})
            save()
            print('Decrypted ' + local.name, flush=True)
        result['complete'] = len(result['extensions']) == len(originals) - 1
    except Exception as error:
        result['error'] = str(error)
        raise
    finally:
        if session:
            with deadline(10):
                session.detach()
            result['detached'] = True
        save()


if __name__ == '__main__':
    main()
