#include "config.h"
#include "DisplayManager.h"
#include "BleManager.h"
#include <Wire.h>
#include <FT6336U.h> 
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"

// Ensure libraries are included if headers don't strictly enforce them
#include <TFT_eSPI.h>

TFT_eSPI tft = TFT_eSPI();
FT6336U ts = FT6336U(TOUCH_SDA, TOUCH_SCL, TOUCH_RST, TOUCH_INT);

DisplayManager display;
BleManager ble;

unsigned long lastDraw = 0;
bool isAggressiveMode = false; // New state for Aggressive Mode

void setup() {
    // Disable brownout detector
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
    
    Serial.begin(115200);
    
    tft.init();
    tft.setRotation(1);
    
    ts.begin();

    display.begin(&tft, &ts);
    ble.init();
    
    display.log("System Initialized.");
    display.log("Press SCAN to start.");
}

void loop() {
    // --- Safe Data Access for Input ---
    ble.lockList();
    size_t deviceCount = ble.getDevicesUnsafe().size();
    ble.unlockList();
    
    // --- Input Handling ---
    int action = display.handleInput((int)deviceCount);
    
    // ACTION 100: SCAN TOGGLE BUTTON
    if (action == 100) {
        if (ble.isScanning()) {
            ble.stopScan();
            display.log("Scan Stopped.");
        } else {
            ble.startScan();
            display.log("Scan Started...");
        }
        
        // Debounce touch release
        unsigned long startWait = millis();
        while(ts.read_touch_number() > 0 && (millis() - startWait < 500)) {
            delay(10);
        }
        delay(50);
    }
    // ACTION 101: AGGRESSIVE MODE TOGGLE
    else if (action == 101) {
        isAggressiveMode = !isAggressiveMode;
        if (isAggressiveMode) {
            display.log("Aggressive Mode: ON");
        } else {
            display.log("Aggressive Mode: OFF");
        }
        
        // Debounce touch release
        unsigned long startWait = millis();
        while(ts.read_touch_number() > 0 && (millis() - startWait < 500)) {
            delay(10);
        }
        delay(50);
    }
    // ACTION >= 0: DEVICE SELECTED
    else if (action >= 0) {
        int realIndex = action + display.getScrollOffset();
        
        ble.lockList();
        size_t safeSize = ble.getDevicesUnsafe().size();
        String targetName = ""; // Variable to hold name
        
        if (realIndex < (int)safeSize) {
            targetName = ble.getDevicesUnsafe()[realIndex].name; // Capture name
            ble.unlockList(); 
            
            display.log("Targeting: " + targetName); // Will now wrap if long
            display.log("Testing...");
            
            // Pass Name to verify identity and get fresh MAC
            bool vuln = ble.testDevice(realIndex, targetName);
            
            if (vuln) {
                display.log("!!! VULNERABLE !!!");
            } else {
                display.log("Test Failed / Safe");
            }
        } else {
            ble.unlockList();
        }
    }
    // SCROLL HANDLING
    else if (action == -2) { // Scroll Down (Swipe Up)
        display.scroll(1, (int)deviceCount);
    }
    else if (action == -3) { // Scroll Up (Swipe Down)
        display.scroll(-1, (int)deviceCount);
    }

    // --- UI Refresh (Every 200ms) ---
    if (millis() - lastDraw > 200) {
        ble.lockList(); // Lock while copying data to UI
        
        std::vector<ScannedDevice>& rawDevs = ble.getDevicesUnsafe();
        std::vector<DeviceDisplayInfo> uiDevs;
        uiDevs.reserve(rawDevs.size());
        
        for(const auto& d : rawDevs) {
            // Filter logic based on Aggressive Mode
            // Prompt said: "instead of adding fastpair devices to the right add the vulnerable to whisperpair in this case"
            // This implies a filter or sorting change. For now, we pass all,
            // relying on drawList to handle the "FP" tag visibility logic if desired,
            // or we could filter here.
            // Current drawList implementation handles the drawing based on the flag passed below.
            
            DeviceDisplayInfo info;
            info.address = d.address;
            info.name = d.name;
            info.isVulnerable = d.isVulnerable;
            info.isFastPair = d.isFastPair;
            info.rssi = d.rssi;
            info.lastSeen = d.lastSeen;
            info.modelId = d.modelId; 
            uiDevs.push_back(info);
        }
        
        int vCount = ble.getVulnCount();
        bool isScan = ble.isScanning();
        ble.unlockList(); // Unlock immediately after copy
        
        // Pass the new isAggressiveMode flag to fix compilation errors
        display.drawHeader(isScan, vCount, isAggressiveMode);
        display.drawList(uiDevs, isAggressiveMode);
        
        lastDraw = millis();
    }
}