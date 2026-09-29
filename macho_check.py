#!/usr/bin/env python3
"""Inspect Mach-O encryption commands and independently validate a dumped IPA."""
import argparse
import hashlib
import io
import json
import plistlib
import struct
import zipfile
from pathlib import Path

MACH = {b'\xcf\xfa\xed\xfe': ('<', 64), b'\xce\xfa\xed\xfe': ('<', 32),
        b'\xfe\xed\xfa\xcf': ('>', 64), b'\xfe\xed\xfa\xce': ('>', 32)}
FAT = {b'\xca\xfe\xba\xbe': ('>', 32), b'\xbe\xba\xfe\xca': ('<', 32),
       b'\xca\xfe\xba\xbf': ('>', 64), b'\xbf\xba\xfe\xca': ('<', 64)}


def read_at(stream, offset, length):
    stream.seek(offset)
    data = stream.read(length)
    if len(data) != length:
        raise ValueError(f'truncated data at {offset:#x}: {len(data)} != {length}')
    return data


def thin(stream, offset=0, size=None):
    magic = read_at(stream, offset, 4)
    endian, bits = MACH[magic]
    header_size = 32 if bits == 64 else 28
    header = struct.unpack(endian + ('8I' if bits == 64 else '7I'), read_at(stream, offset, header_size))
    cpu, subtype, filetype, ncmds, command_bytes = header[1:6]
    if ncmds > 65536 or command_bytes > 16 * 1024 * 1024:
        raise ValueError('invalid load command bounds')
    commands = read_at(stream, offset + header_size, command_bytes)
    cursor = 0
    encryption = []
    segments = []
    for _ in range(ncmds):
        if cursor + 8 > len(commands):
            raise ValueError('truncated load command')
        cmd, length = struct.unpack_from(endian + 'II', commands, cursor)
        if length < 8 or cursor + length > len(commands):
            raise ValueError('invalid load command size')
        if cmd in (0x21, 0x2C):
            if length < (24 if cmd == 0x2C else 20):
                raise ValueError('truncated encryption command')
            cryptoff, cryptsize, cryptid = struct.unpack_from(endian + 'III', commands, cursor + 8)
            if size is not None and cryptoff + cryptsize > size:
                raise ValueError('encrypted range outside file/slice')
            encryption.append({'command': hex(cmd), 'cryptoff': cryptoff, 'cryptsize': cryptsize,
                               'cryptid': cryptid, 'cryptid_file_offset': offset + header_size + cursor + 16})
        if cmd == 0x19 and length >= 72:
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(endian + 'QQQQ', commands, cursor + 24)
            segments.append({'name': commands[cursor+8:cursor+24].split(b'\0', 1)[0].decode(),
                             'vmaddr': vmaddr, 'vmsize': vmsize, 'fileoff': fileoff, 'filesize': filesize})
        cursor += length
    if cursor != command_bytes:
        raise ValueError('load command byte count mismatch')
    return {'bits': bits, 'cpu_type': hex(cpu), 'cpu_subtype': hex(subtype), 'filetype': filetype,
            'offset': offset, 'size': size, 'encryption': encryption, 'segments': segments}


def inspect(stream, size=None):
    stream.seek(0)
    magic = stream.read(4)
    if magic in MACH:
        return [thin(stream, 0, size)]
    if magic not in FAT:
        return []
    endian, bits = FAT[magic]
    count, = struct.unpack(endian + 'I', read_at(stream, 4, 4))
    if count > 64:
        raise ValueError('invalid FAT arch count')
    slices = []
    stride = 32 if bits == 64 else 20
    for i in range(count):
        values = struct.unpack(endian + ('IIQQII' if bits == 64 else 'IIIII'), read_at(stream, 8 + i*stride, stride))
        offset, length = values[2:4]
        if size is not None and offset + length > size:
            raise ValueError('FAT slice outside file')
        slices.append(thin(stream, offset, length))
    return slices


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def validate_ipa(path, output):
    result = {'ipa': str(path.resolve()), 'bytes': path.stat().st_size, 'sha256': sha256(path),
              'macho_files': [], 'encrypted_remaining': []}
    with zipfile.ZipFile(path) as archive:
        bad = archive.testzip()
        if bad:
            raise ValueError('ZIP CRC failed: ' + bad)
        result['zip_crc_valid'] = True
        plist_names = [n for n in archive.namelist() if n.startswith('Payload/') and n.count('/') == 2 and n.endswith('.app/Info.plist')]
        if len(plist_names) != 1:
            raise ValueError('expected one main application bundle')
        info = plistlib.loads(archive.read(plist_names[0]))
        if not info.get('CFBundleIdentifier') or not info.get('CFBundleExecutable'):
            raise ValueError('main bundle is missing its identifier or executable name')
        result['info'] = {k: info.get(k) for k in ('CFBundleIdentifier', 'CFBundleExecutable', 'CFBundleShortVersionString', 'CFBundleVersion')}
        main = plist_names[0].rsplit('/', 1)[0] + '/' + info['CFBundleExecutable']
        result['main_executable'] = main
        for entry in archive.infolist():
            if entry.is_dir() or entry.file_size < 4:
                continue
            if entry.filename.startswith('/') or '..' in Path(entry.filename).parts:
                raise ValueError('unsafe archive path')
            with archive.open(entry) as stream:
                slices = inspect(stream, entry.file_size)
            if not slices:
                continue
            row = {'path': entry.filename, 'bytes': entry.file_size, 'slices': slices}
            result['macho_files'].append(row)
            for arch in slices:
                for enc in arch['encryption']:
                    if enc['cryptid']:
                        result['encrypted_remaining'].append({'path': entry.filename, 'cpu_type': arch['cpu_type'], **enc})
        main_row = next((m for m in result['macho_files'] if m['path'] == main), None)
        if not main_row:
            raise ValueError('main executable missing or not Mach-O')
        result['main_decrypted'] = all(e['cryptid'] == 0 for s in main_row['slices'] for e in s['encryption'])
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'macho_files'}, ensure_ascii=False, indent=2))
    return 0 if result['main_decrypted'] and not result['encrypted_remaining'] else 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('ipa', type=Path)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    raise SystemExit(validate_ipa(args.ipa, args.report))
