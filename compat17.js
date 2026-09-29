// Legacy API adapter for the unbundled Frida 17 runtime.
Module.ensureInitialized = name => Process.getModuleByName(name).ensureInitialized();
Module.findExportByName = (name, symbol) => name === null
    ? Module.findGlobalExportByName(symbol)
    : Process.getModuleByName(name).findExportByName(symbol);
Process.enumerateModulesSync = () => Process.enumerateModules();
for (const suffix of ['U8', 'U16', 'U32', 'U64', 'Pointer', 'ByteArray', 'Utf8String']) {
    Memory['read' + suffix] = (address, ...args) => ptr(address)['read' + suffix](...args);
    Memory['write' + suffix] = (address, ...args) => ptr(address)['write' + suffix](...args);
}
