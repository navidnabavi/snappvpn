# EasyForti

EasyForti is a Python helper project designed to facilitate the creation of OTP inputs for a VPN and automate the probing of connection stability. It leverages the Openfortinet VPN tool to ensure seamless and reliable VPN connections.

## Features

- **OTP Input Creation**: Generates One-Time Password (OTP) inputs for VPN authentication.
- **Automated Probing**: Periodically checks the stability of the VPN connection by probing a specified URL and reconnects.
- **Integration with Openfortinet**: Utilizes the Openfortinet VPN tool for establishing VPN connections.

## Prerequisites

- Python 3.x
- Openfortinet VPN tool installed and configured on your system

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/easyforti.git
    cd easyforti
    ```

2. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To use EasyForti, you need to provide the path to your Fortinet VPN configuration file, the path to your secret file, and optionally, a URL to probe for checking the VPN connection's liveness.

### Command-Line Arguments

- `--config-path` or `-c`: Path to the Fortinet VPN configuration file (required).
- `--secret-file` or `-s`: Path to the secret file containing authentication details (required) (read QR Code Script).
- `--probe-url` or `-p`: URL to probe for checking VPN liveness (optional, defaults to `http://gitlab.snapp.ir`).

### Example Command

```bash
python easyforti.py --config-path /path/to/config --secret-file /path/to/secret --probe-url http://example.com
```

This will start the VPN connection process, generate the OTP input, and periodically probe the specified URL to check the VPN's stability.

## Configuration

Ensure your Fortinet VPN configuration file is properly set up and accessible. The secret file should contain the necessary authentication details required by the Openfortinet tool. The secret is derived from a QR code provided by your VPN service.

### Extracting the Secret from the QR Code

A tool is provided to help you extract the secret from the QR code. Use the `qrcode.py` file included in the repository:

1. Save your QR code as an image file (e.g., `qrcode.png`).
2. Run the `qrcode.py` script to extract the secret:

    ```bash
    python qrcode.py /path/to/qrcode.png
    ```

#### QR Code Script (`qrcode.py`)

Below is a snippet of `qrcode.py` script, It will help you to extract the secret from the qrcode to provide the secret parameter of easyforti:

```bash
python qrcode.py qrcode_image.png
```

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss potential changes.

---

Thank you for using EasyForti! We hope it simplifies your VPN connectivity and stability checks.