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
#define LOG_MAX     10

struct DeviceDisplayInfo {
    String address;
    String name;
    bool isVulnerable;
    bool isFastPair;
    int rssi;
    String modelId; 
};

class DisplayManager {
private:
    TFT_eSPI* tft = nullptr;
    FT6336U* ts = nullptr;
    bool ready = false;
    
    std::vector<String> logs;
    std::vector<DeviceDisplayInfo> device_cache; // Cache for smart redraw
    int scrollOffset = 0;
    
    // Button Coordinates (Scan)
    int btnScanX = 240;
    int btnScanY = 5;
    int btnScanW = 70;
    int btnScanH = 30;

    // Button Coordinates (Aggressive)
    int btnAggrX = 165; // Positioned to the left of Scan button
    int btnAggrY = 5;
    int btnAggrW = 70;
    int btnAggrH = 30;
    
    int lastTouchY = -1;
    unsigned long lastHeaderDraw = 0;
    bool lastScanState = false;
    bool lastAggrState = false; 

public:
    void begin(TFT_eSPI* _tft, FT6336U* _ts) {
        tft = _tft;
        ts = _ts;
        ready = true;
        
        tft->fillScreen(C_BG);
        drawStaticInterface();
    }

    void log(String msg) {
        if (logs.size() >= LOG_MAX) logs.erase(logs.begin());
        logs.push_back(msg);
        drawLogWindow();
    }

    void drawStaticInterface() {
        tft->fillRect(0, 0, SCREEN_WIDTH, HEAD_H, C_HEADER);
        tft->drawLine(0, HEAD_H, SCREEN_WIDTH, HEAD_H, C_DIVIDER);
        tft->drawLine(SPLIT_X, HEAD_H, SPLIT_X, SCREEN_HEIGHT, C_DIVIDER);
    }
    
    void drawHeader(bool isScanning, int vulnCount, bool isAggressive) {
        // Force button redraw logic to prevent UI de-sync
        bool stateChanged = (isScanning != lastScanState) || (isAggressive != lastAggrState);
        bool timeRefresh = (millis() - lastHeaderDraw > 1000);

        if (stateChanged || timeRefresh) {
            // Draw Scan Button
            uint16_t btnColor = isScanning ? TFT_DARKGREEN : C_BTN_ACT;
            String btnText = isScanning ? "SCAN ON" : "SCAN OFF";
            
            tft->fillRoundRect(btnScanX, btnScanY, btnScanW, btnScanH, 5, btnColor);
            tft->setTextColor(TFT_WHITE, btnColor);
            tft->setTextDatum(MC_DATUM);
            tft->drawString(btnText, btnScanX + btnScanW/2, btnScanY + btnScanH/2);

            // Draw Aggressive Button
            //uint16_t aggrColor = isAggressive ? TFT_RED : TFT_DARKGREY;
            //String aggrText = isAggressive ? "AGGR ON" : "AGGR OFF";

            //tft->fillRoundRect(btnAggrX, btnAggrY, btnAggrW, btnAggrH, 5, aggrColor);
            //tft->setTextColor(TFT_WHITE, aggrColor);
            //tft->setTextDatum(MC_DATUM);
            //tft->drawString(aggrText, btnAggrX + btnAggrW/2, btnAggrY + btnAggrH/2);
            
            // Only update these if we actually drew
            lastScanState = isScanning;
            //lastAggrState = isAggressive;
            lastHeaderDraw = millis();
        }

        // Draw Vuln Counter
        tft->setTextColor(TFT_WHITE, C_HEADER);
        tft->setTextDatum(TL_DATUM);
        tft->drawString("Vuln Found: " + String(vulnCount), 10, 12, 2);
    }

    void drawLogWindow() {
        // Clear log area
        tft->fillRect(0, HEAD_H + 1, SPLIT_X - 1, SCREEN_HEIGHT - HEAD_H, C_BG);
        tft->setTextDatum(TL_DATUM);
        tft->setTextColor(C_LOG_TXT, C_BG);
        
        int y = HEAD_H + 5;
        int maxW = SPLIT_X - 10; // Margin
        
        for(const auto& line : logs) {
            if (tft->textWidth(line) <= maxW) {
                // Fits on one line
                tft->drawString(line, 5, y);
                y += 15;
            } else {
                // Needs wrapping
                String currentLine = "";
                for (int i = 0; i < line.length(); i++) {
                    if (tft->textWidth(currentLine + line[i]) > maxW) {
                        tft->drawString(currentLine, 5, y);
                        y += 15;
                        currentLine = "";
                    }
                    currentLine += line[i];
                }
                // Draw remaining text
                if (currentLine.length() > 0) {
                    tft->drawString(currentLine, 5, y);
                    y += 15;
                }
            }
            // Stop drawing if we run off screen
            if (y > SCREEN_HEIGHT) break;
        }
    }

    void drawList(const std::vector<DeviceDisplayInfo>& devices, bool isAggressive) {
        int x = SPLIT_X + 1;
        int y = HEAD_H + 1;
        int w = SCREEN_WIDTH - SPLIT_X;
        int h = SCREEN_HEIGHT - HEAD_H;
        
        int maxVisible = h / LIST_ITEM_H;
        
        // Resize cache if needed (e.g. first run)
        if (device_cache.size() != maxVisible) {
            device_cache.resize(maxVisible);
            // Force full clear on resize
            tft->fillRect(x, y, w, h, C_LIST_BG);
        }
        
        for (int i = 0; i < maxVisible; i++) {
            int entryY = y + (i * LIST_ITEM_H);
            int idx = i + scrollOffset;
            
            // --- EMPTY SLOT HANDLING ---
            if (idx >= devices.size()) {
                // If this slot was previously occupied, clear it
                if (!device_cache[i].address.isEmpty()) {
                    tft->fillRect(x, entryY, w, LIST_ITEM_H, C_LIST_BG);
                    device_cache[i].address = ""; // Mark empty
                }
                continue;
            }

            const auto& dev = devices[idx];
            DeviceDisplayInfo& cached = device_cache[i];
            
            bool fullRedraw = false;
            bool barRedraw = false;
            
            // 1. Check for Identity Change (Different device or scrolled)
            if (cached.address != dev.address || 
                cached.name != dev.name ||
                cached.isVulnerable != dev.isVulnerable || 
                cached.isFastPair != dev.isFastPair ||
                cached.modelId != dev.modelId) {
                fullRedraw = true;
            }
            // 2. Check for RSSI Change Threshold (5dB)
            else if (abs(cached.rssi - dev.rssi) >= 5) {
                barRedraw = true;
            }
            
            // --- DRAWING ---
            
            if (fullRedraw) {
                // Clear the specific row background
                tft->fillRect(x, entryY, w, LIST_ITEM_H, C_LIST_BG);
                tft->drawRect(x, entryY, w, LIST_ITEM_H, C_DIVIDER);
                
                // Name
                tft->setTextColor(C_LIST_TXT, C_LIST_BG);
                tft->setTextDatum(TL_DATUM);
                // Add order number to the name: "1. DeviceName"
                String displayName = String(idx + 1) + ". " + dev.name.substring(0, 15);
                tft->drawString(displayName, x + 5, entryY + 5, 2);
                
                // Address
                tft->setTextColor(TFT_LIGHTGREY, C_LIST_BG);
                tft->drawString(dev.address, x + 5, entryY + 25, 1);
                
                // Tags
                int tagX = x + 5;
                if (dev.isVulnerable) {
                    tft->setTextColor(TFT_WHITE, C_VULN);
                    tft->drawString(" VULN ", tagX, entryY + 38);
                    tagX += 40;
                }
                // Only show FP tag if NOT aggressive mode (to save space/confusion)
                // Or modify logic as requested: "instead of adding fastpair devices to the right add the vulnerable to whisperpair in this case"
                // The VULN tag above handles the vulnerability display. 
                // The prompt implies filtering list logic which should happen in the main loop, 
                // but here we just draw what is passed.
                if (dev.isFastPair) { 
                    tft->setTextColor(TFT_BLACK, TFT_CYAN);
                    tft->drawString(" FP ", tagX, entryY + 38);
                    tagX += 25; // Bump X for next item
                }

                // Show Model ID if available
                if (!dev.modelId.isEmpty()) {
                    tft->setTextColor(TFT_ORANGE, C_LIST_BG);
                    tft->drawString(dev.modelId, tagX, entryY + 38);
                }
                
                // If we redrew the background, we MUST redraw the bar
                barRedraw = true;
                
                // Update cache (RSSI updated in next block)
                cached = dev;
            }
            
            if (barRedraw) {
                // Clear bar background area only
                tft->fillRect(x + w - 35, entryY + 5, 30, 6, C_LIST_BG);
                
                int barW = map(constrain(dev.rssi, -100, -40), -100, -40, 5, 30);
                uint16_t barC = (dev.rssi > -70) ? TFT_GREEN : (dev.rssi > -85) ? TFT_YELLOW : TFT_RED;
                tft->fillRect(x + w - 35, entryY + 5, barW, 5, barC);
                
                // Update RSSI in cache
                cached.rssi = dev.rssi;
            }
        }
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