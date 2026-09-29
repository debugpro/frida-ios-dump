'use strict';
// Supplement frida-ios-dump for unloaded appex binaries; device files stay read-only.
// API reference: https://github.com/subdiox/UnFairPlay/blob/master/unfairplay.c
const syscall = (name, result, args) => new SystemFunction(Module.getGlobalExportByName(name), result, args);
const openRead = syscall('open', 'int', ['pointer', 'int']);
const closeFd = syscall('close', 'int', ['int']);
const seek = syscall('lseek', 'int64', ['int', 'int64', 'int']);
const mapFile = syscall('mmap', 'pointer', ['pointer', 'ulong', 'int', 'int', 'int', 'int64']);
const unmapFile = syscall('munmap', 'int', ['pointer', 'ulong']);
const decryptMap = syscall('mremap_encrypted', 'int', ['pointer', 'ulong', 'uint', 'uint', 'uint']);
const canonical = path => path.replace(/^\/private\/var\//, '/var/');
const appRoot = canonical(Process.mainModule.path).replace(/\/[^/]+$/, '');

rpc.exports.decrypt = request => {
    const path = canonical(request.path);
    if (!path.startsWith(appRoot + '/') || path.split('/').includes('..'))
        throw new Error('Path outside the target app');
    if (request.size < 32 || request.size > 256 * 1024 * 1024 ||
        request.cryptsize < 1 || request.cryptsize > 1024 * 1024 ||
        request.cryptoff < 0 || request.cryptoff + request.cryptsize > request.size)
        throw new Error('Invalid encryption range');
    const opened = openRead(Memory.allocUtf8String(request.path), 0);
    if (opened.value < 0) throw new Error('open errno=' + opened.errno);
    const fd = opened.value;
    let base = null;
    try {
        const length = seek(fd, 0, 2);
        if (Number(length.value) !== request.size) throw new Error('File size changed');
        const mapped = mapFile(NULL, request.size, 5, 2, fd, 0);
        if (mapped.value.equals(ptr(-1))) throw new Error('mmap errno=' + mapped.errno);
        base = mapped.value;
        if (base.readU32() !== 0xfeedfacf || base.add(4).readU32() !== 0x100000c)
            throw new Error('Expected thin ARM64 Mach-O');
        const enc = base.add(request.cryptid_file_offset - 16);
        if (enc.readU32() !== 0x2c || enc.add(8).readU32() !== request.cryptoff ||
            enc.add(12).readU32() !== request.cryptsize || enc.add(16).readU32() !== 1)
            throw new Error('Encryption command changed');
        const region = base.add(request.cryptoff);
        const alignedOffset = Math.floor(request.cryptoff / Process.pageSize) * Process.pageSize;
        const alignedLength = Math.ceil((request.cryptoff - alignedOffset + request.cryptsize) / Process.pageSize) * Process.pageSize;
        const result = decryptMap(base.add(alignedOffset), alignedLength, 1, base.add(4).readU32(), base.add(8).readU32());
        if (result.value !== 0) throw new Error('mremap_encrypted errno=' + result.errno);
        return region.readByteArray(request.cryptsize);
    } finally {
        if (base !== null) unmapFile(base, request.size);
        closeFd(fd);
    }
};
