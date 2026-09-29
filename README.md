# frida-ios-dump (Frida 17)

A Frida 17 compatible fork of [AloneMonkey/frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) for dumping decrypted iOS app binaries and packaging IPA files.

Adds an Objective-C bridge and legacy API adapter, checked file writes, sequential transfers with retries, and dump reports. Tested with Python 3.14, Frida 17.19.0, and iOS 15.8.8 / Dopamine.

## Setup

Requires a jailbroken iOS device with Frida 17 and SSH installed, a USB connection, and `iproxy` on the computer. Keep the host and device Frida versions aligned.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage

Start USB SSH forwarding in another terminal, unless it is already running:

```sh
iproxy 2222 22
```

Unlock the device, open the target app, then run:

```sh
python dump.py -l
python dump.py com.example.app -o app
```

The output is `app.ipa`. SSH defaults to `root@127.0.0.1:2222`; enter the device's SSH password when prompted. The first connection saves the device key in `.known_hosts` next to the script; later connections verify it. Use `python dump.py --help` for optional connection settings.

Validate an IPA:

```sh
python macho_check.py app.ipa validation.json
```

The validator checks ZIP CRC, Mach-O structure, and encryption flags. Exit code `2` means encrypted components remain; a zero `cryptid` alone does not prove the decrypted bytes are correct.

## Notes

- App extensions may remain encrypted. `decrypt_extensions.py/js` are unfinished experiments and are not part of the supported dump workflow.
- Interrupted files are retried up to three attempts while the SSH connection remains active. A closed SSH connection stops the run.
- `dump-report.json` and temporary files are retained for troubleshooting. The 20-minute message wait limit does not cover every attach or synchronous RPC call.

MIT licensed; the original license is preserved in [LICENSE](LICENSE).
