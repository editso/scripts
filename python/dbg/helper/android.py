import argparse
import subprocess
import shutil
import os
import sys
import hashlib
import re
import time
import threading
import pathlib


class Helper:
    def __init__(
        self,
        skip_jdwp=False,
        apk_push_path="/data/local/tmp/apk",
        dbg_push_path="/data/local/tmp",
        dbg_port=5785,
    ) -> None:
        self.serial = None
        self.use_dbg = "ida"
        self.dbg_srv = None
        self.dbg_port = dbg_port
        self.dbg_push_path = dbg_push_path
        self.apk_push_path = apk_push_path
        self.skip_jdwp = skip_jdwp
        self._srv_name = None

    @property
    def srv_name(self):
        return self._srv_name if self._srv_name else f"{self.use_dbg}_srv"

    @srv_name.setter
    def srv_name(self, name):
        self._srv_name = name


helper = Helper()


def ensure_program_exits(prog: str, path=None, help=None):
    if not shutil.which(prog, path=path):
        raise FileNotFoundError("`{}` not exists {}".format(prog, "" if not help else f"see: {help}"))


def adb_command(command: str, args=[]):
    serial = helper.serial

    if command in ["connect", "devices"]:
        serial = None

    ensure_program_exits("adb", help="https://developer.android.com/tools/releases/platform-tools")

    if isinstance(args, str):
        args = [args]

    adb = "adb {}".format("" if not serial else f"-s {serial}").strip().split(" ")
    adb = adb + [command] + args

    print("[+] execute: {}".format(" ".join(adb)))

    prog = subprocess.Popen(
        adb,
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    exit_code = prog.wait()

    if exit_code == 0:
        return prog.stdout.read().decode()

    raise ChildProcessError(prog.stderr.read().decode())


def adb_shell(command: str):
    return adb_command("shell", command)


def get_devices():
    return list(
        map(
            lambda x: x.split("\t")[0],
            adb_command("devices").strip().split("\n")[1:],
        )
    )


def connect_to_jdwp(sdk: str, port):
    jdb = shutil.which("jdb", path=sdk)
    if not jdb:
        raise FileExistsError("jdb not found")
    jdwp = subprocess.Popen(
        [
            jdb,
            "-connect",
            f"com.sun.jdi.SocketAttach:hostname=localhost,port={port}",
        ]
    )
    jdwp.wait()


def adb_kill(prog: str, ignore_err=True):
    try:
        adb_shell(f"killall {prog}")
    except Exception as e:
        if not ignore_err:
            raise e


def adb_push(local_file: str, name: str, remote_path: str):
    remote_file = pathlib.Path(remote_path).joinpath(name)

    if not os.path.exists(local_file):
        raise FileNotFoundError(local_file)

    try:
        adb_shell(f"mkdir -p {remote_file.parent}")

        with open(local_file, "rb") as f:
            file_sha1 = hashlib.sha1(f.read()).hexdigest()
            retval = adb_shell(f"sha1sum {str(remote_file)}").split(" ")[0]
            if retval == file_sha1:
                return str(remote_file)

    except ChildProcessError:
        pass

    adb_command("push", [local_file, str(remote_file)])

    return str(remote_file)


def starting_ida(srv: str):
    srv_name = helper.srv_name
    srv_port = helper.dbg_port
    remote_path = helper.dbg_push_path

    adb_kill(srv_name)

    ida_prog = adb_push(srv, srv_name, remote_path)

    def detach_ida():
        try:
            adb_shell(f"chmod +x {ida_prog}")
            adb_shell(f"{ida_prog} -p {srv_port} -K")
        except Exception as e:
            print("Ida DebuggerServer error {}".format(e))

    adb_command("forward", [f"tcp:{srv_port}", f"tcp:{srv_port}"])

    thread = threading.Thread(target=detach_ida)
    thread.start()
    thread.join(2)

    if not thread.is_alive():
        raise ChildProcessError("IDA DebuggerServer launch fail")

    print(f"[+] Ida DebuggerServer Listen on 127.0.0.1:{srv_port}")


def starting_frida(srv: str):
    srv_name = helper.srv_name
    srv_port = helper.dbg_port
    remote_path = helper.dbg_push_path

    adb_kill(srv_name)

    frida_prog = adb_push(srv, srv_name, remote_path)

    def detach_frida():
        try:
            adb_shell(f"chmod +x {frida_prog}")
            adb_shell(f"{frida_prog} -l 0.0.0.0:{srv_port}")
        except Exception as e:
            print("FridaServer error {}".format(e))

    adb_command("forward", [f"tcp:{srv_port}", f"tcp:{srv_port}"])

    thread = threading.Thread(target=detach_frida)
    thread.start()
    thread.join(2)

    if not thread.is_alive():
        raise ChildProcessError("FridaServer launch fail")

    print(f"[+] FridaServer Listen on 127.0.0.1:{srv_port}")


def run_helper(apk: str, clean=False, push=True, only_run=False, sdk=None, jdwp=5986, package=None, activity=None):
    debugger = helper.use_dbg
    debug_package = package
    main_activity = activity

    if apk != "--":
        bytes_apk = open(apk, "rb").read()
        sha1_apk = hashlib.sha1(bytes_apk).hexdigest()
        remote_path = None if push else adb_push(apk, f"{sha1_apk}.apk", helper.apk_push_path)
        package = None

    if apk != "--" and not package:
        if push:
            adb_shell(f"pm install {remote_path}")
        else:
            adb_command("install", [apk])

        retval = adb_shell("""pm list packages -3 -f | sed -r 's/package:(.*)=(.*)/\\1 \\2/' | awk '{system("sha1sum " $1 "|xargs echo " $2);}'""").split("\n")

        for app in retval:
            if sha1_apk in app:
                debug_package = app.split(" ")[0].strip()
                break

        if not debug_package:
            raise FileExistsError(f"{apk} install fail")

    if clean:
        adb_shell(f"pm clear {debug_package}")

    if not main_activity:
        retval = adb_shell(f"dumpsys package {debug_package}")
        lines = retval.split("\n")
        ranges = range(len(lines))
        for idx in ranges:
            line = lines[idx]
            if "android.intent.action.MAIN" in line:
                main_activity = lines[idx + 1].strip().split(" ")[1]
                break
        if not main_activity:
            raise NameError("activity not found")

    adb_shell(" ".join(["am start", "" if only_run else "-D", "-n", main_activity]))

    time.sleep(2)

    retval = adb_shell(f"ps -ef | grep {debug_package}").split("\n")

    debug_process = None

    for proc in retval:
        if proc.endswith(debug_package):
            proc = re.sub("[ ]+", " ", proc)
            debug_process = proc.split(" ")[1]
            break

    if not debug_process:
        raise FileExistsError(f"{debug_package} launch fail")

    print(f"[+] {debug_package} started. pid is {debug_process}")

    if only_run:
        return

    if helper.dbg_srv:
        ({"ida": starting_ida, "frida": starting_frida})[debugger](helper.dbg_srv)

    if helper.skip_jdwp:
        return

    input("[+] Enter to start debugging (Make sure the debugger is attached): ")

    adb_command("forward", [f"tcp:{jdwp}", f"jdwp:{debug_process}"])

    connect_to_jdwp(sdk, jdwp)


def run_main(app: argparse.Namespace):
    if app.APK != "--" and not os.path.exists(app.APK):
        print("[-] apk file not exists")
        sys.exit(1)

    if app.APK == "--" and not app.package:
        print("[-] you need a package name, or an apk")
        sys.exit(1)

    retval = get_devices()

    if app.serial and app.serial not in retval and len(app.serial.split(":")) == 2:
        retval = adb_command("connect", app.serial)
        if "failed" in retval:
            print(f"[-] device connect fail {app.serial}")
            sys.exit(1)
        retval = get_devices()

    if not retval:
        print("[-] no devices/emulators found")
        sys.exit(1)

    if not app.serial and len(retval) > 1:
        for idx in range(len(retval)):
            print(f"{idx + 1}) {retval[idx]}")
        while True:
            try:
                idx = int(input(f"You want to debug on that device (1-{len(retval)}): ")) - 1
                if idx >= 0 and idx <= len(retval):
                    app.serial = retval[idx]
                    break
            except Exception:
                pass
            print("[-] bad input. retry")

    if not app.serial:
        app.serial = retval[0]

    helper.serial = app.serial

    whoami = adb_shell("whoami").replace("\n", "")

    if whoami != "root":
        adb_shell("root")
        if app.serial and len(app.serial.split(":")) == 2:
            adb_command("connect", [app.serial])

    helper.dbg_srv = app.srv
    helper.dbg_port = app.listen
    helper.use_dbg = app.dbg
    helper.skip_jdwp = app.skip_jdwp
    helper.srv_name = app.name
    helper.apk_push_path = app.apk_path
    helper.dbg_push_path = app.dbg_path

    run_helper(app.APK, app.clear, app.no_push, app.run, app.sdk, app.jdwp, app.package, app.activity)


if __name__ == "__main__":
    ap = argparse.ArgumentParser("DebuggerHelper")

    ap.add_argument("-e", "--srv", default=None, help="Debugger Server Program")
    ap.add_argument("-l", "--listen", default=5789, help="Debugger listen port", type=int)
    ap.add_argument("-j", "--sdk", default=None, help="Java JDK Home")
    ap.add_argument("-s", "--serial", default=None, help="ADB SERIAL")
    ap.add_argument("-p", "--package", default=None, help="APK package name")
    ap.add_argument("-a", "--activity", default=None, help="APK lunch activity")
    ap.add_argument("-d", "--jdwp", default=5986, type=int)
    ap.add_argument("-r", "--run", default=False, action="store_true", help="Run but not debug")
    ap.add_argument("-k", "--dbg", choices=["frida", "ida"], default="ida", help="Debugger kind")
    ap.add_argument("-n", "--name", help="Debugger Server name")
    ap.add_argument("-c", "--clear", default=False, action="store_true", help="clear app data")
    ap.add_argument("--skip-jdwp", default=False, action="store_true", help="Skip jdwp")
    ap.add_argument("--no-push", default=True, action="store_false", help="Do not upload apk")
    ap.add_argument("--dbg-path", default="/data/local/tmp", help="Debugger push path")
    ap.add_argument("--apk-path", default="/data/local/tmp/apk", help="APK push path")
    ap.add_argument("APK", nargs="?", default="--")

    try:
        run_main(ap.parse_args())
        sys.exit(0)
    except Exception as e:
        print("[-] Err {}".format(e))
        sys.exit(1)
