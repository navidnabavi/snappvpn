from pyzbar.pyzbar import decode
import argparse
from PIL import Image
from urllib.parse import urlparse, parse_qs


def read_qr_code(image_path):
    with open(image_path, "rb") as image_file:
        image = Image.open(image_file)
        decoded_objects = decode(image)

        # Print results
        for obj in decoded_objects:
            data = obj.data.decode("utf-8")

            url = urlparse(data)
            if url.scheme == "otpauth" and url.netloc == "totp":
                query = parse_qs(url.query)
                print("QRCode Secret:", query["secret"][0])


def get_args():
    parser = argparse.ArgumentParser(
        prog="qrcode-scan",
        description="Parses QRcode",
    )
    parser.add_argument("qrcode_image", type=str)
    return parser.parse_args()


if __name__ == "__main__":
    parser = get_args()
    image_path = parser.qrcode_image
    read_qr_code(image_path)
