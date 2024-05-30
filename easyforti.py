import argparse
import re
import socket
import time
from itertools import chain
from subprocess import DEVNULL, PIPE, Popen, TimeoutExpired, call
from threading import Event, Thread
from typing import Iterable, List, TextIO, Tuple

try:
    import pyotp
    import requests
except ImportError:
    print("Some libraris are missing.")
    print("Try pip install pyotp requests")


probe_failure_event = Event()
exit_event = Event()
connected_event = Event()


def read_secret(path: str) -> str:
    """
    Reads TOTP secret from a text file

    Args:
        path (str): path to secret file

    Returns:
        str: TOTP secret in string
    """

    with open(path) as f:
        return f.read()


def write_to_process(stdin, text: str):
    stdin.write(f"{text}\n")
    stdin.flush()  # Flush the buffer to ensure data is sent
    stdin.close()


def resolve_hostname_to_ip(hostname: str) -> str:
    """
    Resolves dns name of a FQDN

    Args:
        hostname (str): a domain name

    Returns:
        str: IP Address
    """

    ip_address = socket.gethostbyname(hostname)
    return ip_address


def clear_route_table(server_name: str):
    """
    Clears routes added by OpenFortinet.
    This happens when OpenFortinet not exits gracefully
    or system got in to standby

    Args:
        server_name (str): FQDN of the VPN server
    """

    address = resolve_hostname_to_ip(server_name)
    address_history = get_routes_ips_history()

    print("try removing stalled routes.")
    for addr in chain(address_history, [server_name, address]):
        call(["sudo", "route", "delete", addr], stdout=DEVNULL, stderr=DEVNULL)


def wait_for_connection(stdout: TextIO) -> Tuple[bool, List[str]]:
    """
    Waits for a successful connection based on the output from a process.

    Args:
        stdout (TextIO): The subprocess stream representing the process output.

    Returns:
        Tuple[bool, List[str]]: A tuple containing:
            - A boolean indicating whether the connection was successful.
            - A list of routes added during the process.
    """
    routes = []
    CONNECTION_ERRORS_MSGS = [
        "getaddrinfo: nodename nor servname provided, or not known",
        "connect: Connection refused",
        "Connection terminated.",
    ]
    for line in stdout:
        print(line, end="")

        # adding routes
        match = re.match(r"add (host|net) ([\d\w\.]+): gateway", line)
        if match:
            routes.append(match.groups()[1])

        if "INFO:   Tunnel is up and running." in line:
            return True, routes
        for msg in CONNECTION_ERRORS_MSGS:
            if msg in line:
                break

    return False, None


def prob_http(probe_addr: str) -> bool:
    """
    Checks if an HTTP probe to the given address is successful.

    Args:
        probe_addr (str): The address to probe.

    Returns:
        bool: True if the probe is successful, False otherwise.
    """

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


def prober(url: str) -> None:
    """
    Continuously probes an HTTP URL for connectivity.

    Args:
        url (str): The URL to probe.
    """
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


def run_openfortivpn(config_address: str, secret_key: str) -> None:
    """
    Runs OpenFortinet process

    Args:
        config_address (str): configuration address for OpenFortinet
        secret_key (str): TOTP secret in string

    """
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

    connected, routes = wait_for_connection(process.stdout)
    if not connected:
        time.sleep(5)
        return True

    write_route_ips_to_file(routes)

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


def generate_otp(secret_key: str) -> str:
    """
    Generates TOTP based on given secret

    Args:
        secret_key (str): TOTP secret

    Returns:
        str: Time based OTP
    """
    totp = pyotp.TOTP(secret_key)
    otp_code = totp.now()

    return otp_code


def get_args() -> argparse.Namespace:
    """
    Parses commandline arguments and prints help

    Returns:
        argparse.Namespace: parsed arguments
    """
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
    """
    Retrieves the server name from the OpenFortinet configuration file.

    Args:
        file_path (str): The path to the configuration file.

    Returns:
        str: The server name extracted from the configuration file.
    """

    with open(file_path) as f:
        for line in f.readlines():
            m = re.search(r"host\s*=\s*([\w\.]+)", line)
            if m:
                return m.groups()[0]


def get_routes_ips_history() -> List[str]:
    """
    Retrieves a list of routes IP addresses from a file.
    It will be used to clear up route table.

    Returns:
        List[str]: A list of server IP addresses, or an empty list if the file is not found.
    """

    try:
        with open("/tmp/snapvpn-ips", mode="r") as tmp_file:
            return tmp_file.read().splitlines()
    except FileNotFoundError:
        return []


def write_route_ips_to_file(addresses: Iterable[str]) -> None:
    """
    Writes a list of IP addresses to a file.
    The file be used to clear route table.

    Args:
        addresses (Iterable[str]): An iterable containing IP addresses to be written.

    Returns:
        None
    """
    with open("/tmp/snapvpn-ips", mode="w") as tmp_file:
        for addr in addresses:
            tmp_file.write(f"{addr}\n")


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
    clear_route_table(server_name)
    probe_thread.join()


if __name__ == "__main__":
    main()
