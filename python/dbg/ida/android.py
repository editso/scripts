import argparse
import subprocess
import shutil
import os
import sys
import hashlib
import re
import time
import threading


def ensure_program_exits(prog: str, path=None, help=None):
    if not shutil.which(prog, path=path):
        raise FileNotFoundError('`{}` not exists {}'.format(prog,
                                                            "" if not help else f"see: {help}"))


def adb_command(command: str, args=[], serial=None):
    ensure_program_exits(
        "adb", help="https://developer.android.com/tools/releases/platform-tools")

    if isinstance(args, str):
        args = [args]

    adb = 'adb {}'.format(
        "" if not serial else f'-s {serial}').strip().split(' ')
    adb = adb + [command] + args

    print('[+] execute: {}'.format(" ".join(adb)))

    prog = subprocess.Popen(adb,
                            stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    exit_code = prog.wait()

    if exit_code == 0:
        return prog.stdout.read().decode()

    raise ChildProcessError(prog.stderr.read().decode())


def get_devices():
    return list(map(lambda x: x.split('\t')[0], adb_command(
        'devices').strip().split('\n')[1:]))


def connect_to_jdwp(sdk: str, port):
    jdb = shutil.which('jdb', path=sdk)
    if not jdb:
        raise FileExistsError('jdb not found')
    jdwp = subprocess.Popen(
        [jdb, '-connect', f'com.sun.jdi.SocketAttach:hostname=localhost,port={port}'])
    jdwp.wait()


def upload_dbg(srv: str, name: str, serial: None):
    remote_path = f'/data/local/tmp/{name}'

    try:
        retval = adb_command('shell', f'stat {remote_path}')
    except ChildProcessError as e:
        retval = str(e)

    if 'No such file or directory' not in retval:
        return remote_path

    adb_command('push', [srv, remote_path], serial)
    return remote_path


def starting_ida(srv: str, port: str, serial: None):

    try:
        adb_command('shell', 'killall idasrv', serial)
    except Exception:
        pass

    ida_prog = upload_dbg(srv, 'idasrv', serial)

    def detach_ida():
        try:
            adb_command('shell', f'chmod +x {ida_prog}', serial)
            adb_command('shell', f'{ida_prog} -p {port} -K', serial)
        except Exception as e:
            print('Ida DebuggerServer launch fail {}'.format(e))

    adb_command('forward', [f'tcp:{port}', f'tcp:{port}'], serial)

    thread = threading.Thread(target=detach_ida)
    thread.start()
    thread.join(2)

    if not thread.is_alive():
        raise ChildProcessError('IDA DebuggerServer launch fail')

    print(f"[+] Ida DebuggerServer Listen on 127.0.0.1:{port}")


def run_dbg(apk: str, only_run=False, serial=None, idasrv=None, idaport=None, sdk=None, jdwp=5986, package=None, activity=None):
    debug_package = package
    main_activity = activity

    if apk != '--':

        bytes_apk = open(apk, 'rb').read()
        sha1_apk = hashlib.sha1(bytes_apk).hexdigest()

        remote_path = f"/data/local/tmp/apk/{sha1_apk}.apk"
        try:
            retval = adb_command('shell', f'stat {remote_path}', serial)
        except ChildProcessError as e:
            retval = str(e)
        if 'No such file or directory' in retval:
            adb_command('push', [apk, remote_path], serial)
        package = None

    if not package:
        adb_command('shell', f"pm install {remote_path}", serial)
        retval = adb_command(
            'shell', """pm list packages -3 -f | sed -r 's/package:(.*)=(.*)/\\1 \\2/' | awk '{system("sha1sum " $1 "|xargs echo " $2);}'""", serial).split('\n')

        for app in retval:
            if sha1_apk in app:
                debug_package = app.split(' ')[0].strip()
                break

        if not debug_package:
            raise FileExistsError(f'{apk} install fail')

    if not main_activity:
        retval = adb_command(
            'shell', f'dumpsys package {debug_package}', serial)
        lines = retval.split('\n')
        ranges = range(len(lines))
        for idx in ranges:
            line = lines[idx]
            if 'android.intent.action.MAIN' in line:
                main_activity = lines[idx + 1].strip().split(' ')[1]
                break
        if not main_activity:
            raise NameError("activity not found")

    if only_run:
        adb_command("shell", f'am start -n {main_activity}', serial)
    else:
        adb_command("shell", f'am start -D -n {main_activity}', serial)

    time.sleep(2)

    retval = adb_command(
        "shell", f'ps -ef | grep {debug_package}', serial).split('\n')

    debug_process = None

    for proc in retval:
        if proc.endswith(debug_package):
            proc = re.sub('[ ]+', " ", proc)
            debug_process = proc.split(' ')[1]
            break

    if not debug_process:
        raise FileExistsError(f'{debug_package} launch fail')

    print(f"[+] {debug_package} started. pid is {debug_process}")

    if only_run:
        return

    if idasrv:
        starting_ida(idasrv, idaport, serial)

    input('[+] Enter to start debugging (Make sure you have attached to IDA): ')

    adb_command('forward', [f'tcp:{jdwp}', f'jdwp:{debug_process}'], serial)

    connect_to_jdwp(sdk, jdwp)


def run_main(app: argparse.Namespace):
    if app.APK != '--' and not os.path.exists(app.APK):
        print('[-] apk file not exists')
        sys.exit(1)

    if app.APK == '--' and not app.package:
        print('[-] need package')
        sys.exit(1)

    retval = get_devices()

    if app.serial and app.serial not in retval:
        retval = adb_command('connect', app.serial)
        if 'failed' in retval:
            print(f"[-] device connect fail {app.serial}")
            sys.exit(1)
        retval = get_devices()

    if not retval:
        print('[-] no devices/emulators found')
        sys.exit(1)

    if not app.serial and len(retval) > 1:
        for idx in range(len(retval)):
            print(f"{idx + 1}) {retval[idx]}")
        while True:
            try:
                idx = int(
                    input(f'You want to debug on that device (1-{len(retval)}): ')) - 1
                if idx >= 0 and idx <= len(retval):
                    app.serial = retval[idx]
                    break
            except Exception:
                pass
            print('[-] bad input. retry')

    if not app.serial:
        app.serial = retval[0]

    whoami = adb_command(
        'shell', 'whoami', serial=app.serial).replace("\n", "")

    if whoami != 'root':
        adb_command('root', serial=app.serial)
        if app.serial and len(app.serial.split(':')) == 2:
            adb_command('connect', [app.serial])

    run_dbg(app.APK, app.run, app.serial, app.srv, app.ida,
            app.sdk, app.jdwp, app.package, app.activity)


if __name__ == '__main__':
    ap = argparse.ArgumentParser("IdaDbg")
    ap.add_argument('-i', '--srv', default=None,
                    help="IDA Debugger Server Program")
    ap.add_argument('-l', '--ida', default=5789,
                    help="IDA Debugger listen port")
    ap.add_argument('-j', '--sdk', default=None, help="Java JDK Home")
    ap.add_argument('-s', '--serial', default=None, help="ADB SERIAL")
    ap.add_argument('-p', '--package', default=None, help="APK package name")
    ap.add_argument('-a', '--activity', default=None,
                    help="APK lunch activity")
    ap.add_argument('-r', '--run', default=False,
                    action='store_true', help="Run but not debug")
    ap.add_argument('-d', "--jdwp", default=5986)
    ap.add_argument('APK', nargs='?', default="--")

    try:
        run_main(ap.parse_args())
        sys.exit(0)
    except Exception as e:
        print("[-] Err {}".format(e))
        sys.exit(1)
