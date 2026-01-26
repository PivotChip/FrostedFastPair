# About

POC for **CVE-2025-36911** WhisperPair vulnerability, allowing you to connect to supported devices with no authentication info.

This firmware only performs discovery and vulnerability confirmation and does not implement complete audio listening.

Output on during tests:
* **Testing Mac:** will use the ESP's own Mac and the Mac of the device you are testing to attempt to pair.
* **See if device exposes key if you ask nicely:** Expose Key via Read; Broadcast Key in Ads.
* **Accept wrong key:** try to send a random security key. 

**Tested on Device:** Freenove ESP32-S3 ESP32 S3 Display CYD 2.8 Inch IPS Capacitive Touch Screen 240x320 Pixel

# Video

[![Watch the video](https://img.youtube.com/vi/pDZJA90SBy4/0.jpg)](https://youtu.be/pDZJA90SBy4)

# About the Device

You can use ESP32 device to track down devices that support Fast Pair and check vulneravility. 

![Image POC](/poc_marshal.jpg)

# Company 

Interested in penetration testing and security devices? Visit

https://pivotchip.ca

## Core Logic & Protocol

### 1. Discovery & Filtering
The scanner (`BleManager`) bypasses standard discovery to parse raw advertisement packets for GFPS payloads
* **Fast Pair:** Service UUID `0xFE2C`.
* **Nearby:** Service UUID `0xFEF3`.
* **Model ID Extraction:** Parses the 3-byte Model ID from Service Data to track devices across MAC address rotations.

### 2. State Management (Deduplication)
To handle privacy-enabled BLE devices that rotate MAC addresses, the system uses a tiered identity check
1.  **MAC Match:** Checks strict raw address equality.
2.  **Identity Match:** If MAC differs, correlates via `Model ID` or `Device Name`.
3.  **Hot-Swap:** Updates the stored MAC address in real-time when a known identity broadcasts from a new address, preventing connection failures during tests.

### 3. KBP Handshake Exploitation
The `testDevice` function executes a raw GFPS handshake to test for unauthorized pairing acceptance

1.  **Connection:** Establishes GATT connection with an 8-second timeout.
2.  **Service Resolution:** Locates Fast Pair Service (`0xFE2C`) and KBP Characteristic (`fe2c1234-8366-4814-8eb0-01de32100bea`).
3.  **Payload Construction:**
    * Generates a 16-byte block: `[Type: 0x00] [Flags: 0x11] [Provider Address] [Salt: 8 bytes]`.
    * **Encryption:** Encrypts the block using `mbedtls_aes_crypt_ecb` with the Salt as the key.
4.  **Verification:**
    * Writes the encrypted packet to the KBP characteristic.
    * Listens for a **Notification** response.
    * **Vulnerable:** Device sends a notification (accepting the handshake).
    * **Safe:** Device remains silent or disconnects.

## Hardware Configuration (`config.h`)

Designed for ESP32 with `FT6336U` touch and `TFT_eSPI` displays .

| Function | Pin |
| :--- | :--- |
| **Touch SDA** | `16` |
| **Touch SCL** | `15` |
| **Touch RST** | `18` |
| **Touch INT** | `17` |

## Build & Flash

1.  **Dependencies:**
    * `NimBLE-Arduino` (2.3.7)
    * `TFT_eSPI` (Display)
    * `FT6336U` (Input)
2.  **Partition Scheme:** Select **"Huge APP (3MB No OTA)"** to accommodate the BLE stack.
3.  **TFT Setup:** Configure `User_Setup.h` in the `TFT_eSPI` library to match the ILI9341/ST7789 driver for your specific board.

or download libraries from Freenove and place it into your Arduino Library folder

https://codeload.github.com/Freenove/Freenove_ESP32_S3_Display/zip/refs/heads/main


## Usage

* **Scanning:** Toggle `SCAN` to populate the list. 
* **Targeting:** Tap an entry to initiate the WhisperPair test. 





