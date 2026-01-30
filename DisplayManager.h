#ifndef DISPLAY_MANAGER_H
#define DISPLAY_MANAGER_H

#include <TFT_eSPI.h> 
#include <FT6336U.h>
#include <vector>
#include "config.h"

// --- Styling ---
#define C_BG        TFT_BLACK
#define C_HEADER    0x18E3 // Dark Gray/Blue
#define C_DIVIDER   TFT_DARKGREY
#define C_LOG_TXT   TFT_GREEN
#define C_LIST_BG   0x10A2 // Dark Slate
#define C_LIST_TXT  TFT_WHITE
#define C_BTN       TFT_BLUE
#define C_BTN_ACT   TFT_ORANGE
#define C_VULN      TFT_RED
#define C_SAFE      TFT_GREEN

// --- Layout ---
#define HEAD_H      40  
#define SPLIT_X     160 
#define LIST_ITEM_H 60  
#define LOG_MAX     13

#define btnOffX   5
#define btnOffY   5
#define btnOffW   50
#define btnOffH   30


struct DeviceDisplayInfo {
    String address;
    String name;
    bool isVulnerable;
    bool isPaired;
    bool isFastPair;
    int rssi;
    uint32_t lastSeen; 
    String modelId; 
};

class DisplayManager {
private:
    TFT_eSPI* tft = nullptr;
    FT6336U* ts = nullptr;
    bool ready = false;
    
    std::vector<String> logs;
    std::vector<DeviceDisplayInfo> device_cache; 
    int scrollOffset = 0;
    
    // Button Coordinates (Scan)
    int btnScanX = 240;
    int btnScanY = 5;
    int btnScanW = 70;
    int btnScanH = 30;

    // Button Coordinates (Aggressive)
    int btnAggrX = 165; 
    int btnAggrY = 5;
    int btnAggrW = 70;
    int btnAggrH = 30;
    
    int lastTouchY = -1;
    unsigned long lastHeaderDraw = 0;
    bool lastScanState = false;

public:
    void begin(TFT_eSPI* _tft, FT6336U* _ts) {
        tft = _tft;
        ts = _ts;
        ready = true;
        
        tft->fillScreen(C_BG);
        drawStaticInterface();
    }

    void log(String msg) {
        // Enforce strict size limit
        if (logs.size() >= LOG_MAX) {
            logs.erase(logs.begin());
        }
        logs.push_back(msg);
        drawLogWindow();
    }

    void drawStaticInterface() {
        tft->fillRect(0, 0, SCREEN_WIDTH, HEAD_H, C_HEADER);
        tft->drawLine(0, HEAD_H, SCREEN_WIDTH, HEAD_H, C_DIVIDER);
        tft->drawLine(SPLIT_X, HEAD_H, SPLIT_X, SCREEN_HEIGHT, C_DIVIDER);
    }
    
    void drawHeader(bool isScanning, int vulnCount, bool isAggressive) {
        bool stateChanged = (isScanning != lastScanState);
        bool timeRefresh = (millis() - lastHeaderDraw > 1000);

        if (stateChanged || timeRefresh) {
            // --- NEW OFF BUTTON ---
            tft->fillRoundRect(btnOffX, btnOffY, btnOffW, btnOffH, 5, TFT_RED);
            tft->setTextColor(TFT_WHITE, TFT_RED);
            tft->setTextDatum(MC_DATUM);
            tft->drawString("OFF", btnOffX + btnOffW/2, btnOffY + btnOffH/2);

            // --- EXISTING SCAN BUTTON ---
            uint16_t btnColor = isScanning ? TFT_DARKGREEN : C_BTN_ACT;
            String btnText = isScanning ? "SCAN ON" : "SCAN OFF";
            
            
            tft->fillRoundRect(btnScanX, btnScanY, btnScanW, btnScanH, 5, btnColor);
            tft->setTextColor(TFT_WHITE, btnColor);
            tft->setTextDatum(MC_DATUM);
            tft->drawString(btnText, btnScanX + btnScanW/2, btnScanY + btnScanH/2);
            
            lastScanState = isScanning;
            lastHeaderDraw = millis();
        }

        // Draw Vuln Counter
        tft->setTextColor(TFT_WHITE, C_HEADER);
        tft->setTextDatum(TL_DATUM);
        tft->drawString("Vuln: " + String(vulnCount), 65, 12, 2);
    }

    void drawLogWindow() {
        tft->fillRect(0, HEAD_H + 1, SPLIT_X - 1, SCREEN_HEIGHT - HEAD_H, C_BG);
        tft->setTextDatum(TL_DATUM);
        tft->setTextColor(C_LOG_TXT, C_BG);
        
        int y = HEAD_H + 5;
        int maxW = SPLIT_X - 10; 
        
        for(const auto& line : logs) {
            if (tft->textWidth(line) <= maxW) {
                tft->drawString(line, 5, y);
                y += 15;
            } else {
                String currentLine = "";
                for (int i = 0; i < line.length(); i++) {
                    if (tft->textWidth(currentLine + line[i]) > maxW) {
                        tft->drawString(currentLine, 5, y);
                        y += 15;
                        currentLine = "";
                    }
                    currentLine += line[i];
                }
                if (currentLine.length() > 0) {
                    tft->drawString(currentLine, 5, y);
                    y += 15;
                }
            }
            if (y > SCREEN_HEIGHT) break;
        }
    }

    void drawList(const std::vector<DeviceDisplayInfo>& devices, bool isAggressive) {
        int x = SPLIT_X + 1;
        int y = HEAD_H + 1;
        int w = SCREEN_WIDTH - SPLIT_X;
        int h = SCREEN_HEIGHT - HEAD_H;
        
        int maxVisible = h / LIST_ITEM_H;
        
        if (device_cache.size() != maxVisible) {
            device_cache.resize(maxVisible);
            tft->fillRect(x, y, w, h, C_LIST_BG);
        }
        
        for (int i = 0; i < maxVisible; i++) {
            int entryY = y + (i * LIST_ITEM_H);
            int idx = i + scrollOffset;
            
            if (idx >= devices.size()) {
                if (!device_cache[i].address.isEmpty()) {
                    tft->fillRect(x, entryY, w, LIST_ITEM_H, C_LIST_BG);
                    device_cache[i].address = ""; 
                }
                continue;
            }

            const auto& dev = devices[idx];
            DeviceDisplayInfo& cached = device_cache[i];
            
            bool fullRedraw = false;
            bool barRedraw = false;
            
            if (cached.address != dev.address || 
                cached.name != dev.name ||
                cached.isVulnerable != dev.isVulnerable || 
                cached.isPaired != dev.isPaired || 
                cached.isFastPair != dev.isFastPair ||
                cached.modelId != dev.modelId) {
                fullRedraw = true;
            }
            else if (abs(cached.rssi - dev.rssi) >= 5) {
                barRedraw = true;
            }
            
            if (fullRedraw) {
                tft->fillRect(x, entryY, w, LIST_ITEM_H, C_LIST_BG);
                tft->drawRect(x, entryY, w, LIST_ITEM_H, C_DIVIDER);
                
                tft->setTextColor(C_LIST_TXT, C_LIST_BG);
                tft->setTextDatum(TL_DATUM);
                String displayName = String(idx + 1) + ". " + dev.name.substring(0, 15);
                tft->drawString(displayName, x + 5, entryY + 5, 2);
                
                tft->setTextColor(TFT_LIGHTGREY, C_LIST_BG);
                tft->drawString(dev.address, x + 5, entryY + 25, 1);
                
                int tagX = x + 5;
                if (dev.isPaired) {
                    tft->setTextColor(TFT_WHITE, TFT_DARKGREEN);
                    tft->drawString(" PAIRED ", tagX, entryY + 38);
                    tagX += 50;
                }
                else if (dev.isVulnerable) {
                    tft->setTextColor(TFT_WHITE, C_VULN);
                    tft->drawString(" VULN ", tagX, entryY + 38);
                    tagX += 40;
                }
                if (dev.isFastPair) { 
                    tft->setTextColor(TFT_BLACK, TFT_CYAN);
                    tft->drawString(" FP ", tagX, entryY + 38);
                    tagX += 25; 
                }
                if (!dev.modelId.isEmpty()) {
                    tft->setTextColor(TFT_ORANGE, C_LIST_BG);
                    tft->drawString(dev.modelId, tagX, entryY + 38);
                }
                
                barRedraw = true;
                cached = dev;
            }
            
            if (barRedraw) {
                tft->fillRect(x + w - 35, entryY + 5, 30, 6, C_LIST_BG);
                
                if (millis() - dev.lastSeen > 10000) {
                    tft->drawRect(x + w - 35, entryY + 5, 30, 6, TFT_DARKGREY);
                } else {
                    int barW = map(constrain(dev.rssi, -100, -40), -100, -40, 5, 30);
                    uint16_t barC = (dev.rssi > -70) ? TFT_GREEN : (dev.rssi > -85) ? TFT_YELLOW : TFT_RED;
                    tft->fillRect(x + w - 35, entryY + 5, barW, 5, barC);
                }
                
                cached.rssi = dev.rssi;
            }
        }
    }

    void drawPairingMenu(String deviceName) {
        tft->fillRect(40, 60, 240, 120, C_LIST_BG);
        tft->drawRect(40, 60, 240, 120, TFT_WHITE);
        
        tft->setTextDatum(MC_DATUM);
        tft->setTextColor(TFT_WHITE, C_LIST_BG);
        tft->drawString("Device Vulnerable:", 160, 80, 2);
        tft->setTextColor(TFT_YELLOW, C_LIST_BG);
        tft->drawString(deviceName.substring(0, 18), 160, 100, 2);

        // Draw BACK Button
        tft->fillRoundRect(60, 130, 90, 40, 5, TFT_RED);
        tft->setTextColor(TFT_WHITE, TFT_RED);
        tft->drawString("BACK", 105, 150, 2);

        // Draw PAIR Button
        tft->fillRoundRect(170, 130, 90, 40, 5, TFT_GREEN);
        tft->setTextColor(TFT_BLACK, TFT_GREEN);
        tft->drawString("PAIR", 215, 150, 2);
    }

    void clearMenuOverlay() {
        tft->fillRect(SPLIT_X, HEAD_H + 1, SCREEN_WIDTH - SPLIT_X, SCREEN_HEIGHT - HEAD_H, C_LIST_BG);
        drawLogWindow(); 
        for(auto& dev : device_cache) {
            dev.address = ""; 
        }
    }

    int handleOverlayInput() {
        if (ts->read_touch_number() == 0) return 0;
        int p_x = ts->read_touch1_x();
        int p_y = ts->read_touch1_y();
        int tx = p_y; int ty = 240 - p_x; 

        if (tx > 60 && tx < 150 && ty > 130 && ty < 170) return 1;
        if (tx > 170 && tx < 260 && ty > 130 && ty < 170) return 2;
        
        return 0;
    }

    // Return codes: -1 (None), 100 (Scan Toggle), 101 (Aggr Toggle), 0-N (List Index), -2 (Up), -3 (Down)
    int handleInput(int totalItems) {
        if (ts->read_touch_number() == 0) {
            lastTouchY = -1;
            return -1;
        }

        int p_x = ts->read_touch1_x();
        int p_y = ts->read_touch1_y();
        int tx = p_y; 
        int ty = 240 - p_x; 

        // OFF Button Detection (Return code 102)
        if (tx >= btnOffX - 10 && tx <= btnOffX + btnOffW + 10 && 
            ty >= btnOffY - 10 && ty <= btnOffY + btnOffH + 10) {
            return 102;
        }
        
        // Scan Button
        if (tx >= btnScanX - 10 && tx <= btnScanX + btnScanW + 10 && 
            ty >= btnScanY - 10 && ty <= btnScanY + btnScanH + 10) {
            return 100;
        }

        // Aggressive Button
        if (tx >= btnAggrX - 10 && tx <= btnAggrX + btnAggrW + 10 && 
            ty >= btnAggrY - 10 && ty <= btnAggrY + btnAggrH + 10) {
            return 101;
        }

        if (tx > SPLIT_X) {
            if (ty > HEAD_H) {
                int listY = ty - HEAD_H;
                int idx = listY / LIST_ITEM_H;
                if (idx >= 0) return idx;
            }
        }
        
        if (tx < SPLIT_X && ty > HEAD_H) {
             if (lastTouchY != -1) {
                int delta = ty - lastTouchY;
                if (abs(delta) > 20) {
                    lastTouchY = ty;
                    return (delta > 0) ? -3 : -2; 
                }
             } else {
                 lastTouchY = ty;
             }
        }
        return -1;
    }
    
    void scroll(int delta, int total) {
        scrollOffset += delta;
        if (scrollOffset < 0) scrollOffset = 0;
    }
    
    int getScrollOffset() { return scrollOffset; }
};

#endif