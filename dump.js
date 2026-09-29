Module.ensureInitialized('Foundation');

var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;

var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

function allocStr(str) {
    return Memory.allocUtf8String(str);
}

function putStr(addr, str) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeUtf8String(addr, str);
}

function getByteArr(addr, l) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readByteArray(addr, l);
}

function getU8(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU8(addr);
}

function putU8(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU8(addr, n);
}

function getU16(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU16(addr);
}

function putU16(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU16(addr, n);
}

function getU32(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU32(addr);
}

function putU32(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU32(addr, n);
}

function getU64(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU64(addr);
}

function putU64(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU64(addr, n);
}

function getPt(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readPointer(addr);
}

function putPt(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    if (typeof n == "number") {
        n = ptr(n);
    }
    return Memory.writePointer(addr, n);
}

function malloc(size) {
    return Memory.alloc(size);
}

function getExportFunction(type, name, ret, args) {
    var nptr;
    nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        console.log("cannot find " + name);
        return null;
    } else {
        if (type === "f") {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof funclet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return funclet;
        } else if (type === "d") {
            var datalet = Memory.readPointer(nptr);
            if (typeof datalet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return datalet;
        }
    }
}

var NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
var wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "...", "int"]);
var nativeRead = getExportFunction("f", "read", "long", ["int", "pointer", "ulong"]);
function read(fd, data, length) {
    const result = Number(nativeRead(fd, data, length));
    if (result < 0) throw new Error('read failed');
    return result;
}
var nativeWrite = getExportFunction("f", "write", "long", ["int", "pointer", "ulong"]);
function write(fd, data, length) {
    let done = 0;
    while (done < length) {
        const result = Number(nativeWrite(fd, data.add(done), Math.min(length - done, 1024 * 1024)));
        if (result <= 0) throw new Error('write failed after ' + done + '/' + length);
        done += result;
    }
    return done;
}
var lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
var close = getExportFunction("f", "close", "int", ["int"]);
var remove = getExportFunction("f", "remove", "int", ["pointer"]);
var access = getExportFunction("f", "access", "int", ["pointer", "int"]);
var dlopen = getExportFunction("f", "dlopen", "pointer", ["pointer", "int"]);

var dumpDirectory = null;
function getDocumentDir() {
    if (dumpDirectory !== null) return dumpDirectory;
    const getenv = getExportFunction('f', 'getenv', 'pointer', ['pointer']);
    const mkdir = getExportFunction('f', 'mkdir', 'int', ['pointer', 'uint']);
    const tmp = getenv(allocStr('TMPDIR'));
    if (tmp.isNull()) throw new Error('Application TMPDIR unavailable');
    dumpDirectory = tmp.readUtf8String().replace(/\/$/, '') + '/frida-ios-dump-' + Process.id + '-' + Date.now();
    if (mkdir(allocStr(dumpDirectory), 448) !== 0) throw new Error('Cannot create private dump directory');
    send({dump_directory: dumpDirectory});
    return dumpDirectory;
}

function open(pathname, flags, mode) {
    if (typeof pathname == "string") {
        pathname = allocStr(pathname);
    }
    return wrapper_open(pathname, flags, mode);
}

var modules = null;
function getAllAppModules() {
    modules = new Array();
    var tmpmods = Process.enumerateModulesSync();
    for (var i = 0; i < tmpmods.length; i++) {
        if (tmpmods[i].path.indexOf(".app") != -1) {
            modules.push(tmpmods[i]);
        }
    }
    return modules;
}

var FAT_MAGIC = 0xcafebabe;
var FAT_CIGAM = 0xbebafeca;
var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_SEGMENT = 0x1;
var LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

function pad(str, n) {
    return Array(n-str.length+1).join("0")+str;
}

function swap32(value) {
    value = pad(value.toString(16),8)
    var result = "";
    for(var i = 0; i < value.length; i=i+2){
        result += value.charAt(value.length - i - 2);
        result += value.charAt(value.length - i - 1);
    }
    return parseInt(result,16)
}

function dumpModule(name) {
    if (modules == null) {
        modules = getAllAppModules();
    }

    var targetmod = null;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) != -1) {
            targetmod = modules[i];
            break;
        }
    }
    if (targetmod == null) {
        console.log("Cannot find module");
        return;
    }
    var modbase = modules[i].base;
    var modsize = modules[i].size;
    var newmodname = modules[i].name;
    var newmodpath = getDocumentDir() + "/" + i + "-" + newmodname + ".fid";
    var oldmodpath = modules[i].path;


    if(!access(allocStr(newmodpath),0)){
        remove(allocStr(newmodpath));
    }

    var fmodule = open(newmodpath, O_CREAT | O_RDWR | 2048, 384);
    var foldmodule = open(oldmodpath, O_RDONLY, 0);

    if (fmodule == -1 || foldmodule == -1) {
        if (fmodule !== -1) close(fmodule);
        if (foldmodule !== -1) close(foldmodule);
        throw new Error("Cannot open dump input/output: " + newmodpath);
    }

    try {
    const originalFileSize = Number(lseek(foldmodule, 0, SEEK_END));
    lseek(foldmodule, 0, SEEK_SET);
    var is64bit = false;
    var size_of_mach_header = 0;
    var magic = getU32(modbase);
    var cur_cpu_type = getU32(modbase.add(4));
    var cur_cpu_subtype = getU32(modbase.add(8));
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        is64bit = false;
        size_of_mach_header = 28;
    }else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64bit = true;
        size_of_mach_header = 32;
    }

    var BUFSIZE = 1024 * 1024;
    var buffer = malloc(BUFSIZE);

    read(foldmodule, buffer, BUFSIZE);

    var fileoffset = 0;
    var filesize = 0;
    magic = getU32(buffer);
    if(magic == FAT_CIGAM || magic == FAT_MAGIC){
        var off = 4;
        var archs = swap32(getU32(buffer.add(off)));
        for (var i = 0; i < archs; i++) {
            var cputype = swap32(getU32(buffer.add(off + 4)));
            var cpusubtype = swap32(getU32(buffer.add(off + 8)));
            if(cur_cpu_type == cputype && cur_cpu_subtype == cpusubtype){
                fileoffset = swap32(getU32(buffer.add(off + 12)));
                filesize = swap32(getU32(buffer.add(off + 16)));
                break;
            }
            off += 20;
        }

        if(fileoffset == 0 || filesize == 0)
            throw new Error('No matching Mach-O slice');

        lseek(fmodule, 0, SEEK_SET);
        lseek(foldmodule, fileoffset, SEEK_SET);
        for(var i = 0; i < parseInt(filesize / BUFSIZE); i++) {
            read(foldmodule, buffer, BUFSIZE);
            write(fmodule, buffer, BUFSIZE);
        }
        if(filesize % BUFSIZE){
            read(foldmodule, buffer, filesize % BUFSIZE);
            write(fmodule, buffer, filesize % BUFSIZE);
        }
    }else{
        var readLen = 0;
        lseek(foldmodule, 0, SEEK_SET);
        lseek(fmodule, 0, SEEK_SET);
        while(readLen = read(foldmodule, buffer, BUFSIZE)) {
            write(fmodule, buffer, readLen);
        }
    }

    var ncmds = getU32(modbase.add(16));
    var off = size_of_mach_header;
    var offset_cryptid = -1;
    var crypt_off = 0;
    var crypt_size = 0;
    var original_cryptid = 0;
    var segments = [];
    for (var i = 0; i < ncmds; i++) {
        var cmd = getU32(modbase.add(off));
        var cmdsize = getU32(modbase.add(off + 4));
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            offset_cryptid = off + 16;
            crypt_off = getU32(modbase.add(off + 8));
            crypt_size = getU32(modbase.add(off + 12));
            original_cryptid = getU32(modbase.add(off + 16));
        }
        off += cmdsize;
    }

    const expectedSize = filesize || originalFileSize;
    if (crypt_off + crypt_size > expectedSize) throw new Error('Encryption range exceeds file');
    if (offset_cryptid != -1 && original_cryptid !== 0) {
        var tpbuf = malloc(8);
        putU64(tpbuf, 0);
        lseek(fmodule, offset_cryptid, SEEK_SET);
        write(fmodule, tpbuf, 4);
        lseek(fmodule, crypt_off, SEEK_SET);
        write(fmodule, modbase.add(crypt_off), crypt_size);
    }

    const outputSize = Number(lseek(fmodule, 0, SEEK_END));
    if (outputSize !== expectedSize) throw new Error('Dump size mismatch');
    return {dump: newmodpath, detail: {
        name: newmodname, original_size: originalFileSize, output_size: outputSize,
        cpu_type: cur_cpu_type, cpu_subtype: cur_cpu_subtype,
        original_cryptid: original_cryptid, crypt_offset: crypt_off, crypt_size: crypt_size,
        decrypted_bytes: original_cryptid !== 0 ? crypt_size : 0,
        cryptid_file_offset: offset_cryptid
    }};
    } finally {
        close(fmodule);
        close(foldmodule);
    }
}

function loadAllDynamicLibrary(app_path) {
    var defaultManager = ObjC.classes.NSFileManager.defaultManager();
    var errorPtr = Memory.alloc(Process.pointerSize);
    Memory.writePointer(errorPtr, NULL);
    var filenames = defaultManager.contentsOfDirectoryAtPath_error_(app_path, errorPtr);
    for (var i = 0, l = filenames.count(); i < l; i++) {
        var file_name = filenames.objectAtIndex_(i);
        var file_path = app_path.stringByAppendingPathComponent_(file_name);
        if (file_name.hasSuffix_(".framework")) {
            var bundle = ObjC.classes.NSBundle.bundleWithPath_(file_path);
            if (bundle.isLoaded()) {
                console.log("[frida-ios-dump]: " + file_name + " has been loaded. ");
            } else {
                if (bundle.load()) {
                    console.log("[frida-ios-dump]: Load " + file_name + " success. ");
                } else {
                    console.log("[frida-ios-dump]: Load " + file_name + " failed. ");
                }
            }
        } else if (file_name.hasSuffix_(".bundle") ||
                   file_name.hasSuffix_(".momd") ||
                   file_name.hasSuffix_(".strings") ||
                   file_name.hasSuffix_(".appex") ||
                   file_name.hasSuffix_(".app") ||
                   file_name.hasSuffix_(".lproj") ||
                   file_name.hasSuffix_(".storyboardc")) {
            continue;
        } else {
            var isDirPtr = Memory.alloc(Process.pointerSize);
            Memory.writePointer(isDirPtr,NULL);
            defaultManager.fileExistsAtPath_isDirectory_(file_path, isDirPtr);
            if (isDirPtr.readU8() !== 0) {
                loadAllDynamicLibrary(file_path);
            } else {
                if (file_name.hasSuffix_(".dylib")) {
                    var is_loaded = 0;
                    for (var j = 0; j < modules.length; j++) {
                        if (modules[j].path.indexOf(file_name) != -1) {
                            is_loaded = 1;
                            console.log("[frida-ios-dump]: " + file_name + " has been dlopen.");
                            break;
                        }
                    }

                    if (!is_loaded) {
                        if (dlopen(allocStr(file_path.UTF8String()), 9)) {
                            console.log("[frida-ios-dump]: dlopen " + file_name + " success. ");
                        } else {
                            console.log("[frida-ios-dump]: dlopen " + file_name + " failed. ");
                        }
                    }
                }
            }
        }
    }
}

function sendForTransfer(payload, next) {
    // Only prepare the next file after the host has saved this one successfully.
    recv('transfer-result', result => {
        if (!result.ok) {
            send({cancelled: true});
            return;
        }
        setImmediate(next);
    });
    send(payload);
}

function dumpNextModule(index, appPath) {
    try {
        if (index === modules.length) {
            sendForTransfer({app: appPath}, () => send({done: 'ok', module_count: modules.length}));
            return;
        }
        const module = modules[index];
        console.log('start dump ' + module.path);
        const result = dumpModule(module.path);
        if (!result || !result.dump) throw new Error('Dump failed: ' + module.path);
        sendForTransfer({dump: result.dump, path: module.path, detail: result.detail},
                        () => dumpNextModule(index + 1, appPath));
    } catch (error) {
        send({dump_error: String(error), stack: error.stack});
    }
}

function handleMessage(message) {
    try {
        modules = getAllAppModules();
        const app_path = ObjC.classes.NSBundle.mainBundle().bundlePath();
        loadAllDynamicLibrary(app_path);
        modules = getAllAppModules();
        const root = app_path.toString().replace(/^\/private\/var\//, '/var/');
        modules = modules.filter(m => m.path.replace(/^\/private\/var\//, '/var/').startsWith(root + '/'));
        dumpNextModule(0, app_path.toString());
    } catch (error) {
        send({dump_error: String(error), stack: error.stack});
    }
}
rpc.exports.preflight = () => ({pid: Process.id, objc: ObjC.available,
    bundle: ObjC.classes.NSBundle.mainBundle().bundlePath().toString(),
    modules: getAllAppModules().map(m => ({name: m.name, path: m.path, base: m.base.toString()}))});
recv('dump', handleMessage);
