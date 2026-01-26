#ifndef BLE_MANAGER_H
#define BLE_MANAGER_H

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <vector>
#include <algorithm> 
#include <Preferences.h>

#define MAX_SCANNED_DEVICES 50
#define SCAN_STACK_SIZE 8192 

struct ScannedDevice {
    NimBLEAddress rawAddr; // Fixed: Use default constructor
    String address;
    uint8_t addrType;     
    String name;
    bool isFastPair = false;      
    bool isVulnerable = false; 
    bool isPaired = false;   
    int rssi = 0;
    int lastLogRssi = 0;       
    uint32_t lastSeen = 0;     
    String modelId; 
    
    // Raw Service Data for upper-layer extraction (Model ID / Public Key)
    std::vector<uint8_t> fpServiceData; 
};

class BleManager {
private:
    NimBLEScan* pScan = nullptr;
    std::vector<ScannedDevice> discoveredDevices;
    SemaphoreHandle_t listLock;
    
    NimBLEUUID uuidFastPair; 
    NimBLEUUID uuidNearby;   
    
    Preferences prefs;
    
    volatile bool _isScanning = false;
    volatile int vulnerableCount = 0;

    String getStorageKey(String mac) {
        String key = mac;
        key.replace(":", ""); 
        key.trim();
        return key;
    }

    static void scanTask(void* param) {
        BleManager* ble = (BleManager*)param;
        if (ble->pScan->start(0, false)) {
             // Started
        } else {
             Serial.println(">> Scan start failed.");
        }
        
        while (ble->pScan != nullptr && ble->pScan->isScanning()) {
            vTaskDelay(100 / portTICK_PERIOD_MS);
        }
        ble->_isScanning = false;
        vTaskDelete(NULL);
    }

    class MyScanCallbacks : public NimBLEScanCallbacks {
        BleManager* parent;
    public:
        MyScanCallbacks(BleManager* p) : parent(p) {}
        
        String resolveManufacturer(const std::string& data) {
            if (data.length() < 2) return "";
            uint16_t id = ((uint8_t)data[1] << 8) | (uint8_t)data[0];
            switch(id) {
                case 0x004C: return "Apple Device";
                case 0x00E0: return "Google Device";
                case 0x0075: return "Samsung Device";
                case 0x0006: return "Microsoft Device";
                case 0x05AC: return "Sony Device";
                default:     return "Mfg: 0x" + String(id, HEX);
            }
        }

        String parseModelId(const std::string& data) {
            if (data.length() >= 3) {
                 uint32_t modelId = ((uint8_t)data[0] << 16) | ((uint8_t)data[1] << 8) | (uint8_t)data[2];
                 char buf[7];
                 sprintf(buf, "%06X", modelId);
                 return String(buf);
            }
            return "";
        }

        void onResult(const NimBLEAdvertisedDevice* dev) override {
            bool isFP = dev->isAdvertisingService(parent->uuidFastPair);
            bool isNearby = dev->isAdvertisingService(parent->uuidNearby);
            String fpModelId = "";
            std::vector<uint8_t> rawFPData;

            if (dev->haveServiceData()) {
                std::string fpData = dev->getServiceData(parent->uuidFastPair);
                if (fpData.length() > 0) {
                    isFP = true;
                    // Store Raw Data
                    rawFPData.assign(fpData.begin(), fpData.end());
                    fpModelId = parseModelId(fpData);
                }
                if (dev->getServiceData(parent->uuidNearby).length() > 0) isNearby = true;
            }

            if (isFP || isNearby) {
                String detectedName = String(dev->getName().c_str());
                String fallbackName = "";
                
                if (detectedName.isEmpty()) {
                    if (dev->haveManufacturerData()) {
                        fallbackName = resolveManufacturer(dev->getManufacturerData());
                    }
                    if (fallbackName.isEmpty()) {
                         if (!fpModelId.isEmpty()) fallbackName = "ID: " + fpModelId;
                         else if (isFP) fallbackName = "Fast Pair Device";
                         else if (isNearby) fallbackName = "Nearby Device";
                         else fallbackName = "Unknown";
                    }
                }

                if (xSemaphoreTake(parent->listLock, 5 / portTICK_PERIOD_MS) == pdTRUE) {
                    NimBLEAddress currentAddr = dev->getAddress();
                    bool found = false;

                    for(auto& d : parent->discoveredDevices) {
                        bool match = (d.rawAddr == currentAddr); 
                        
                        if (!match && !detectedName.isEmpty() && !d.name.isEmpty()) {
                            if (d.name == detectedName) match = true;
                        }
                        if (!match && !fpModelId.isEmpty() && !d.modelId.isEmpty()) {
                            if (d.modelId == fpModelId) match = true;
                        }

                        if(match) { 
                            d.rawAddr = currentAddr; 
                            d.address = String(currentAddr.toString().c_str());
                            d.rssi = dev->getRSSI();
                            d.lastSeen = millis();
                            d.addrType = dev->getAddressType(); 
                            
                            if (!fpModelId.isEmpty() && d.modelId.isEmpty()) d.modelId = fpModelId;
                            if (detectedName.length() > 0 && d.name != detectedName) d.name = detectedName;
                            // Update Raw Data
                            if (!rawFPData.empty()) d.fpServiceData = rawFPData;
                            
                            found = true;
                            break; 
                        }
                    }
                    
                    if (!found) {
                        if (parent->discoveredDevices.size() >= MAX_SCANNED_DEVICES) {
                             parent->discoveredDevices.erase(parent->discoveredDevices.begin());
                        }

                        ScannedDevice d;
                        d.rawAddr = currentAddr;
                        d.address = String(currentAddr.toString().c_str());
                        d.addrType = dev->getAddressType();
                        d.name = !detectedName.isEmpty() ? detectedName : fallbackName;
                        d.isFastPair = isFP;
                        d.isVulnerable = false;
                        d.isPaired = false; // CRITICAL FIX: Explicit initialization
                        d.rssi = dev->getRSSI();
                        d.lastLogRssi = d.rssi;
                        d.lastSeen = millis();
                        d.modelId = fpModelId; 
                        d.fpServiceData = rawFPData; // Save Data

                        String key = parent->getStorageKey(d.address);
                        if (parent->prefs.isKey(key.c_str())) { 
                            if (parent->prefs.getBool(key.c_str(), false)) {
                                d.isPaired = true;
                                d.isVulnerable = false; 
                            }
                        }
                        
                        parent->discoveredDevices.push_back(d);
                    }
                    xSemaphoreGive(parent->listLock);
                }
            }
        }
    };

public:
    BleManager() {
        uuidFastPair = NimBLEUUID((uint16_t)0xFE2C);
        uuidNearby = NimBLEUUID((uint16_t)0xFEF3);
    }

    void init() {
        listLock = xSemaphoreCreateMutex();
        prefs.begin("whisper", false);
        
        NimBLEDevice::init("ESP32-Whisper");
        
        pScan = NimBLEDevice::getScan();
        pScan->setScanCallbacks(new MyScanCallbacks(this), true); 
        pScan->setActiveScan(true); 
        pScan->setInterval(100); 
        pScan->setWindow(60); 
        pScan->setMaxResults(0); 
    }

    void startScan() {
        if (_isScanning) return;
        pScan->clearResults(); 
        _isScanning = true;
        xTaskCreate(scanTask, "scanTask", SCAN_STACK_SIZE, this, 1, NULL);
    }

    void stopScan() {
        if(pScan->isScanning()) {
            pScan->stop(); 
            Serial.println(">> Stop Requested.");
        }
    }

    // TARGETED SEARCH FUNCTION
    // actively searches for a specific ModelID or Name and UPDATES the passed device structure
    bool reacquireTarget(ScannedDevice* devToUpdate, int timeoutSecs) {
        if (devToUpdate == nullptr) return false;

        String modelId = devToUpdate->modelId;
        String name = devToUpdate->name;
        
        Serial.printf(">>> Targeting: ID=%s / Name=%s\n", modelId.c_str(), name.c_str());
        stopScan(); // Ensure clean slate
        delay(100);

        unsigned long startTime = millis();
        pScan->clearResults(); 
        
        // Start scanning manually (we manage the loop here)
        if(!pScan->start(0, false)) {
            Serial.println(">> Reacquire: Scan failed to start");
            return false;
        }

        bool found = false;
        
        while(millis() - startTime < (timeoutSecs * 1000)) {
            // Give the callback time to process
            delay(50); 
            
            xSemaphoreTake(listLock, portMAX_DELAY);
            for(const auto& d : discoveredDevices) {
                // Check if this device was seen SINCE we started this specific scan
                if(d.lastSeen > startTime) {
                    bool match = false;
                    
                    // Prioritize Model ID match (Unique)
                    if(!modelId.isEmpty() && !d.modelId.isEmpty()) {
                        if(d.modelId == modelId) match = true;
                    }
                    // Fallback to Name
                    else if(!name.isEmpty() && d.name == name) {
                        match = true;
                    }

                    if(match) {
                        // Directly update the object to preserve NimBLEAddress structure
                        devToUpdate->rawAddr = d.rawAddr; // Copy valid NimBLEAddress
                        devToUpdate->address = d.address;
                        devToUpdate->addrType = d.addrType;
                        devToUpdate->rssi = d.rssi;
                        devToUpdate->lastSeen = d.lastSeen;
                        found = true;
                        break;
                    }
                }
            }
            xSemaphoreGive(listLock);

            if(found) break;
        }

        pScan->stop();
        return found;
    }

    bool isScanning() { return pScan->isScanning() || _isScanning; }
    int getVulnCount() { return vulnerableCount; }
    void lockList() { xSemaphoreTake(listLock, portMAX_DELAY); }
    void unlockList() { xSemaphoreGive(listLock); }
    std::vector<ScannedDevice>& getDevicesUnsafe() { return discoveredDevices; }
    
    void incrementVuln() { vulnerableCount++; }

    void clearPairings() {
        lockList();
        
        prefs.clear(); // Wipes all keys in the 'whisper' namespace
        // Force a close and reopen to ensure the flash commit happens immediately
        prefs.end();
        delay(10);
        prefs.begin("whisper", false);

        for(auto& d : discoveredDevices) {
            d.isPaired = false;
        }
        unlockList();
        Serial.println(">>> SYSTEM: All saved pairings have been cleared from flash.");
    }
};

#endif