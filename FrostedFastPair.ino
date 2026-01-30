#include "config.h"
#include "DisplayManager.h"
#include "BleManager.h"
#include "BleTester.h" 
#include <Wire.h>
#include <FT6336U.h> 
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"

#include <TFT_eSPI.h>

TFT_eSPI tft = TFT_eSPI();
FT6336U ts = FT6336U(TOUCH_SDA, TOUCH_SCL, TOUCH_RST, TOUCH_INT);

DisplayManager display;
BleManager ble;
BleTester tester; 

unsigned long lastDraw = 0;
bool isAggressiveMode = false; 

// Menu State
bool inMenuMode = false;
int selectedDeviceIndex = -1;
String selectedDeviceName = "";

void setup() {
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
    
    Serial.begin(115200);
    
    tft.init();
    tft.setRotation(1);
    
    ts.begin();

    display.begin(&tft, &ts);
    ble.init();
    tester.init(); 
    
    display.log("System Initialized.");
    display.log("Press SCAN to start.");
}

void loop() {
    // --- SERIAL COMMAND CHECK ---
    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        if (cmd.equalsIgnoreCase("clear")) {
            ble.clearPairings();
            display.log("! STORAGE CLEARED !");
        }
    }

    static bool inMenuMode = false;
    static int selectedDeviceIndex = -1;
    static String selectedDeviceName = "";

    // --- 1. MENU MODE HANDLING ---
    if (inMenuMode) {
        int menuAction = display.handleOverlayInput();

        if (menuAction == 1) { // BACK
            inMenuMode = false;
            display.clearMenuOverlay(); 
            
            ble.lockList();
            int vCount = ble.getVulnCount();
            bool isScan = ble.isScanning();
            ble.unlockList();
            display.drawHeader(isScan, vCount, isAggressiveMode);
            delay(200); 
        } 
        else if (menuAction == 2) { // PAIR
            // Get clean copy of device data
            ble.lockList();
            ScannedDevice target = ble.getDevicesUnsafe()[selectedDeviceIndex];
            ble.unlockList();

            // Perform Pairing via Tester
            // Pass Display for logging
            bool paired = tester.pairTarget(target, ble, &display);
            
            // Update List with result
            ble.lockList();
            if(selectedDeviceIndex < ble.getDevicesUnsafe().size()) {
                 ble.getDevicesUnsafe()[selectedDeviceIndex] = target;
            }
            ble.unlockList();

            inMenuMode = false;
            display.clearMenuOverlay(); 
            
            if (paired) display.log("Paired Successfully!");
            else display.log("Pairing Failed.");
            
            ble.lockList();
            int vCount = ble.getVulnCount();
            bool isScan = ble.isScanning();
            ble.unlockList();
            display.drawHeader(isScan, vCount, isAggressiveMode);
            
            delay(200); 
        }
        return; 
    }

    // --- 2. STANDARD SCANNING & INPUT ---
    ble.lockList();
    size_t deviceCount = ble.getDevicesUnsafe().size();
    ble.unlockList();
    
    int action = display.handleInput((int)deviceCount);

    if (action == 102) { // POWER OFF
        display.log("Powering Off...");
        delay(1000);
        
        // Shut down radios
        ble.stopScan();
        NimBLEDevice::deinit(true);
        
        // Turn off screen backlight (if applicable to your wiring, common on CYD)
        digitalWrite(21, LOW); 
        
        // Enter Deep Sleep with no wakeup sources
        // This requires a Reset button press to restart
        esp_deep_sleep_start();
    }
    else if (action == 100) {
        if (ble.isScanning()) {
            ble.stopScan();
            display.log("Scan Stopped.");
        } else {
            ble.startScan();
            display.log("Scan Started...");
        }
        delay(200); // Debounce
    }
    else if (action == 101) {
        isAggressiveMode = !isAggressiveMode;
        display.log(isAggressiveMode ? "Aggressive: ON" : "Aggressive: OFF");
        delay(200);
    }
    else if (action >= 0) {
        int realIndex = action + display.getScrollOffset();
        
        ble.lockList();
        std::vector<ScannedDevice>& rawDevs = ble.getDevicesUnsafe();
        
        if (realIndex < rawDevs.size()) {
            ScannedDevice target = rawDevs[realIndex];
            ble.unlockList(); 
            
            if (target.isPaired) {
                display.log("Already Paired.");
            }
            else if (target.isVulnerable) {
                selectedDeviceIndex = realIndex;
                selectedDeviceName = target.name;
                inMenuMode = true;
                display.drawPairingMenu(selectedDeviceName);
            }
            else {
                // RUN TEST
                if (ble.isScanning()) ble.stopScan();
                // Pass display to testDevice for detailed logging
                bool vuln = tester.testDevice(target, &ble, &display);
                
                if (vuln) {
                    // Update List
                    ble.lockList();
                    if(realIndex < ble.getDevicesUnsafe().size()) {
                        ble.getDevicesUnsafe()[realIndex].isVulnerable = true;
                        ble.incrementVuln();
                    }
                    ble.unlockList();

                    selectedDeviceIndex = realIndex;
                    selectedDeviceName = target.name;
                    inMenuMode = true;
                    display.drawPairingMenu(selectedDeviceName);
                } else {
                    // Logs handled inside testDevice now
                    ble.startScan(); // Resume scan
                }
            }
        } else {
            ble.unlockList();
        }
    }
    else if (action == -2) display.scroll(1, (int)deviceCount);
    else if (action == -3) display.scroll(-1, (int)deviceCount);

    // --- 3. UI REFRESH ---
    if (!inMenuMode && millis() - lastDraw > 200) {
        ble.lockList();
        
        std::vector<ScannedDevice>& rawDevs = ble.getDevicesUnsafe();
        std::vector<DeviceDisplayInfo> uiDevs;
        uiDevs.reserve(rawDevs.size());
        
        for(const auto& d : rawDevs) {
            DeviceDisplayInfo info;
            info.address = d.address;
            info.name = d.name;
            info.isVulnerable = d.isVulnerable;
            info.isFastPair = d.isFastPair;
            info.rssi = d.rssi;
            info.lastSeen = d.lastSeen;
            info.modelId = d.modelId; 
            info.isPaired = d.isPaired; 
            uiDevs.push_back(info);
        }
        
        int vCount = ble.getVulnCount();
        bool isScan = ble.isScanning();
        ble.unlockList(); 
        
        display.drawHeader(isScan, vCount, isAggressiveMode);
        display.drawList(uiDevs, isAggressiveMode);
        
        lastDraw = millis();
    }
}