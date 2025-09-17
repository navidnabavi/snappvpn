import argparse
import re
import socket
import time
from subprocess import DEVNULL, PIPE, Popen, TimeoutExpired, call
from threading import Event, Thread
from typing import Iterable, List, Optional, TextIO, Tuple

# Constants
ROUTE_IPS_FILE = "/tmp/snapvpn-ips"
DEFAULT_PROBE_URL = "http://gitlab.snapp.ir"
PROBE_TIMEOUT = 5
PROBE_INTERVAL = 2
MAX_PROBE_FAILURES = 3
CONNECTION_ERRORS_MSGS = [
    "getaddrinfo: nodename nor servname provided, or not known",
    "connect: Connection refused",
    "Connection terminated.",
]

try:
    import pyotp
    import requests
except ImportError:
    print("Some libraries are missing.")
    print("Try pip install pyotp requests")
    exit(1)


probe_failure_event = Event()
exit_event = Event()
connected_event = Event()


def read_secret(path: str) -> str:
    """
    Reads TOTP secret from a text file.

    Args:
        path (str): Path to secret file

    Returns:
        str: TOTP secret as string

    Raises:
        FileNotFoundError: If the secret file doesn't exist
        IOError: If there's an error reading the file
    """
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        raise FileNotFoundError(f"Secret file not found: {path}")
    except IOError as e:
        raise IOError(f"Error reading secret file {path}: {e}")


def write_to_process(stdin: TextIO, text: str) -> None:
    """
    Writes text to a process's stdin and closes it.

    Args:
        stdin: Process stdin stream
        text: Text to write to the process
    """
    stdin.write(f"{text}\n")
    stdin.flush()  # Flush the buffer to ensure data is sent
    stdin.close()


def resolve_hostname_to_ip(hostname: str) -> str:
    """
    Resolves DNS name of a FQDN to an IP address.

    Args:
        hostname (str): A domain name

    Returns:
        str: IP address

    Raises:
        socket.gaierror: If hostname resolution fails
    """
    return socket.gethostbyname(hostname)


def clear_route_table(server_name: str) -> None:
    """
    Clears routes added by OpenFortinet.
    This happens when OpenFortinet does not exit gracefully
    or system goes into standby.

    Args:
        server_name (str): FQDN of the VPN server
    """
    try:
        address = resolve_hostname_to_ip(server_name)
    except socket.gaierror:
        print(f"Warning: Could not resolve hostname {server_name}")
        address = None

    address_history = get_routes_ips_history()

    print("Trying to remove stalled routes...")
    addresses_to_clear = address_history + [server_name]
    if address:
        addresses_to_clear.append(address)

    for addr in addresses_to_clear:
        call(["sudo", "route", "delete", addr], stdout=DEVNULL, stderr=DEVNULL)


def wait_for_connection(stdout: TextIO) -> Tuple[bool, Optional[List[str]]]:
    """
    Waits for a successful connection based on the output from a process.

    Args:
        stdout (TextIO): The subprocess stream representing the process output.

    Returns:
        Tuple[bool, Optional[List[str]]]: A tuple containing:
            - A boolean indicating whether the connection was successful.
            - A list of routes added during the process, or None if failed.
    """
    routes = []

    for line in stdout:
        if "Connected to gateway" in line:
            print("Connected to gateway!")
        print(line, end="")

        # Parse route additions
        match = re.match(r"add (host|net) ([\d\w\.]+): gateway", line)
        if match:
            routes.append(match.groups()[1])

        if "INFO:   Tunnel is up and running." in line:
            return True, routes

        # Check for connection errors
        for msg in CONNECTION_ERRORS_MSGS:
            if msg in line:
                return False, None

    return False, None


def probe_http(probe_addr: str) -> bool:
    """
    Checks if an HTTP probe to the given address is successful.

    Args:
        probe_addr (str): The address to probe.

    Returns:
        bool: True if the probe is successful, False otherwise.
    """
    try:
        response = requests.head(probe_addr, timeout=PROBE_TIMEOUT)
        return response.status_code < 400
    except requests.ConnectTimeout:
        return False
    except requests.ReadTimeout:
        # ReadTimeout means connection was established but response was slow
        # This indicates connectivity, so we consider it successful
        return True
    except requests.RequestException:
        # Any other request-related error indicates failure
        return False
    except Exception as ex:
        print(f"Unexpected error during HTTP probe: {ex}")
        return False


def prober(url: str) -> None:
    """
    Continuously probes an HTTP URL for connectivity.

    Args:
        url (str): The URL to probe.
    """
    failure_count = 0

    while not exit_event.is_set():
        if connected_event.is_set() and not probe_failure_event.is_set():
            success = probe_http(url)
            if not success:
                print(f"HTTP probe failed for {url}")
                failure_count += 1
                if failure_count >= MAX_PROBE_FAILURES:
                    failure_count = 0
                    probe_failure_event.set()
                    print(
                        f"Probe failed {MAX_PROBE_FAILURES} consecutive "
                        "times, triggering reconnection"
                    )
            else:
                failure_count = 0  # Reset counter on successful probe

        time.sleep(PROBE_INTERVAL)


def app_run(config_address: str, secret: str) -> None:
    """
    Main application loop that manages VPN connection.

    Args:
        config_address (str): Path to OpenFortinet configuration file
        secret (str): TOTP secret key
    """
    while run_openfortivpn(config_address, secret) and not exit_event.is_set():
        connected_event.clear()

    print("Exiting...")


def run_openfortivpn(config_address: str, secret_key: str) -> bool:
    """
    Runs OpenFortinet process and manages its lifecycle.

    Args:
        config_address (str): Path to OpenFortinet configuration file
        secret_key (str): TOTP secret key

    Returns:
        bool: True if should retry connection, False if should exit
    """
    server_name = get_server_name(config_address)
    if not server_name:
        print("Error: Could not extract server name from config file")
        return True

    try:
        clear_route_table(server_name)
    except socket.gaierror:
        print(f"Warning: Could not resolve server name {server_name}")
        return True

    probe_failure_event.clear()
    print("Starting OpenFortinet VPN connection...")

    try:
        process = Popen(
            ["openfortivpn", "-c", config_address],
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE,
            bufsize=0,
            universal_newlines=True,
        )
    except FileNotFoundError:
        print("Error: openfortivpn not found. Please install it first.")
        return True

    try:
        otp_code = generate_otp(secret_key)
        print("Providing OTP code...")
        write_to_process(process.stdin, otp_code)

        connected, routes = wait_for_connection(process.stdout)
        if not connected:
            print("Failed to establish VPN connection, retrying in 5 seconds...")
            time.sleep(5)
            return True

        if routes:
            write_route_ips_to_file(routes)

        print("VPN connection established successfully")
        time.sleep(2)
        connected_event.set()

        # Monitor the VPN process
        while True:
            try:
                result = process.wait(2)
                print(f"VPN process exited unexpectedly with code: {result}")
                return True
            except TimeoutExpired:
                pass

            if exit_event.is_set():
                process.kill()
                process.wait()
                print("Exiting gracefully...")
                return False

            if probe_failure_event.is_set():
                process.kill()
                process.wait()
                print("Probe failure detected, restarting VPN connection...")
                return True

    except Exception as e:
        print(f"Error during VPN operation: {e}")
        if process.poll() is None:  # Process is still running
            process.kill()
            process.wait()
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
        description="EasyForti - Automated FortiClient VPN with TOTP authentication",
    )
    parser.add_argument(
        "--config-path",
        "-c",
        help="Path to the OpenFortinet VPN config file",
        required=True,
    )
    parser.add_argument(
        "--secret-file",
        "-s",
        help="Path to the TOTP secret file",
        required=True,
    )
    parser.add_argument(
        "--probe-url",
        "-p",
        help="URL to probe the VPN liveness",
        default=DEFAULT_PROBE_URL,
    )
    return parser.parse_args()


def get_server_name(file_path: str) -> Optional[str]:
    """
    Retrieves the server name from the OpenFortinet configuration file.

    Args:
        file_path (str): The path to the configuration file.

    Returns:
        Optional[str]: The server name extracted from the configuration file,
                      or None if not found or file cannot be read.
    """
    try:
        with open(file_path, "r") as f:
            for line in f:
                match = re.search(r"host\s*=\s*([\w\.]+)", line.strip())
                if match:
                    return match.group(1)
    except (FileNotFoundError, IOError) as e:
        print(f"Error reading config file {file_path}: {e}")

    return None


def get_routes_ips_history() -> List[str]:
    """
    Retrieves a list of route IP addresses from a temporary file.
    This will be used to clean up the route table.

    Returns:
        List[str]: A list of IP addresses, or an empty list if the file is
                  not found.
    """
    try:
        with open(ROUTE_IPS_FILE, "r") as tmp_file:
            return [line.strip() for line in tmp_file if line.strip()]
    except FileNotFoundError:
        return []
    except IOError as e:
        print(f"Warning: Could not read route history file: {e}")
        return []


def write_route_ips_to_file(addresses: Iterable[str]) -> None:
    """
    Writes a list of IP addresses to a temporary file.
    This file will be used to clean up the route table later.

    Args:
        addresses (Iterable[str]): An iterable containing IP addresses to be
                                  written.
    """
    try:
        with open(ROUTE_IPS_FILE, "w") as tmp_file:
            for addr in addresses:
                if addr.strip():  # Only write non-empty addresses
                    tmp_file.write(f"{addr.strip()}\n")
    except IOError as e:
        print(f"Warning: Could not write route history file: {e}")


def main() -> None:
    """
    Main entry point for the EasyForti VPN client.
    """
    try:
        args = get_args()
        config_path = args.config_path
        probe_url = args.probe_url
        secret_path = args.secret_file

        print(f"Reading TOTP secret from: {secret_path}")
        secret_key = read_secret(secret_path)

        print(f"Using config file: {config_path}")
        print(f"Probe URL: {probe_url}")

        # Start VPN connection thread
        app_thread = Thread(target=app_run, args=(config_path, secret_key), daemon=True)
        app_thread.start()

        # Start network probe thread
        probe_thread = Thread(target=prober, args=(probe_url,), daemon=True)
        probe_thread.start()

        print("VPN client started. Press Ctrl+C to exit.")

        try:
            exit_event.wait()
        except KeyboardInterrupt:
            print("\nReceived interrupt signal, shutting down...")
            exit_event.set()

        # Wait for threads to finish
        app_thread.join(timeout=10)
        probe_thread.join(timeout=5)

        print("EasyForti VPN client stopped.")

    except Exception as e:
        print(f"Fatal error: {e}")
        exit_event.set()


if __name__ == "__main__":
    main()
