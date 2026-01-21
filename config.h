#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>

// ==========================================
// PINS VERIFIED BY YOUR WORKING EXAMPLES
// ==========================================
#define TOUCH_SDA  16
#define TOUCH_SCL  15
#define TOUCH_RST  18
#define TOUCH_INT  17

#define SCREEN_WIDTH  320
#define SCREEN_HEIGHT 240

#define FP_SERVICE_UUID "0000fe2c-0000-1000-8000-00805f9b34fb"
#define FP_KBP_UUID     "fe2c1234-8366-4814-8eb0-01de32100bea"
#define SCAN_TIME_MS    10000 

#endif