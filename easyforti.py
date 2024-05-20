import argparse
import time
from subprocess import PIPE, Popen, TimeoutExpired, call
from threading import Event, Thread
import re

try:
    import pyotp
    import requests
except ImportError:
    print("Some libraris are missing.")
    print("Try pip install pyotp requests")


probe_failure_event = Event()
exit_event = Event()
connected_event = Event()


def read_secret(path):
    with open(path) as f:
        return f.read()


def write_to_process(stdin, text):
    stdin.write(f"{text}\n")
    stdin.flush()  # Flush the buffer to ensure data is sent
    stdin.close()


def clear_route_table(server_name):
    print("try removing stalled routes.")
    call(["sudo", "route", "delete", server_name])


def wait_for_connection(stdout):
    for line in stdout:
        print(line, end="")
        if "getaddrinfo: nodename nor servname provided, or not known" in line:
            return False
        if "connect: Connection refused" in line:
            return False
        if "Connection terminated." in line:
            return False
        if "INFO:   Tunnel is up and running." in line:
            return True
    return False


def prob_http(probe_addr):
    try:
        requests.head(probe_addr, timeout=5)
    except requests.ConnectTimeout:
        return False
    except requests.ReadTimeout:
        return True
    except Exception as ex:
        print("unexpected event in probing")
        print(ex)
        return False
    return True


def prober(url):
    c = 0
    while not exit_event.is_set():
        if connected_event.is_set() and not probe_failure_event.is_set():
            success = prob_http(url)
            print("http probe success=", success)
            if not success:
                c += 1
            if c > 3:
                c = 0
                probe_failure_event.set()
        time.sleep(2)


def app_run(config_address, secret):
    while run_openfortivpn(config_address, secret) and not exit_event.is_set():
        connected_event.clear()
    print("Exiting...")


def run_openfortivpn(config_address, secret_key):
    # Start the program as a subprocess
    probe_failure_event.clear()
    print("Starting...")
    process = Popen(
        ["openfortivpn", "-c", config_address],
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
        bufsize=0,
        universal_newlines=True,
    )  # For handling text mode
    otp_code = generate_otp(secret_key)
    print("Providing OTP Code")
    write_to_process(process.stdin, otp_code)

    if not wait_for_connection(process.stdout):
        time.sleep(5)
        return True

    print("VPN is running")
    time.sleep(2)
    connected_event.set()

    while True:
        try:
            result = process.wait(2)
            print(f"Application Exited Unexpected. {result}")
            return True
        except TimeoutExpired:
            pass

        if exit_event.is_set():
            process.kill()
            process.wait()
            print("Exiting Gracefully.")
            return False
        if probe_failure_event.is_set():
            process.kill()
            process.wait()
            print("Probe failure occurred, restarting...")
            return True


def generate_otp(secret_key):
    # Create a TOTP object with the secret key
    totp = pyotp.TOTP(secret_key)

    # Generate the OTP code
    otp_code = totp.now()

    return otp_code


def get_args():
    parser = argparse.ArgumentParser(
        prog="easyforti",
        description="Parse config path, probe URL, and secret file path from arguments",
    )
    parser.add_argument(
        "--config-path", "-c", help="Path to the fortinetvpn config file", required=True
    )
    parser.add_argument(
        "--secret-file", "-s", help="Path to the secret file", required=True
    )
    parser.add_argument(
        "--probe-url",
        "-p",
        help="URL to probe the vpn liveness",
        default="http://gitlab.snapp.ir",
    )
    return parser.parse_args()


def get_server_name(file_path: str) -> str:
    with open(file_path) as f:
        for line in f.readlines():
            m = re.search(r"host\s*=\s*([\w\.]+)", line)
            if m:
                return m.groups()[0]


def main():
    args = get_args()
    config_path = args.config_path
    probe_url = args.probe_url
    secret_path = args.secret_file
    secret_key = read_secret(secret_path)

    server_name = get_server_name(config_path)
    clear_route_table(server_name)

    app_thread = Thread(target=app_run, args=(config_path, secret_key))
    app_thread.start()

    probe_thread = Thread(target=prober, args=(probe_url,))
    probe_thread.start()

    try:
        exit_event.wait()
    except KeyboardInterrupt:
        exit_event.set()

    app_thread.join()
    probe_thread.join()


if __name__ == "__main__":
    main()
