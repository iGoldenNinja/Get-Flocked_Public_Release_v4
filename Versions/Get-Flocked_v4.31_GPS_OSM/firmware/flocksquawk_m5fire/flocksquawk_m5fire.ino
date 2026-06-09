#include <Arduino.h>
#include <WiFi.h>
#include <NimBLEDevice.h>
#include <NimBLEScan.h>
#include <NimBLEAdvertisedDevice.h>
#include <ArduinoJson.h>
#include <FS.h>
#include <SD.h>
#include <SPI.h>
#include <math.h>
#include <M5Unified.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"

#include "EventBus.h"
#include "DeviceSignatures.h"
#include "src/RadioScanner.h"
#include "ThreatAnalyzer.h"
#include "src/SoundEngine.h"
#include "TelemetryReporter.h"

// Global system components
RadioScannerManager rfScanner;
ThreatAnalyzer threatEngine;
SoundEngine audioSystem;
TelemetryReporter reporter;
HardwareSerial gpsSerial(1);

// UI toggle (easy to remove if you don't like it)
#define ENABLE_HOME_UI 1

// UI state (home screen)
static bool homeScreenActive = false;
static bool homeScreenPending = false;
static unsigned long homeReadyTimestamp = 0;
static unsigned long lastUiUpdate = 0;
static unsigned long lastRadarUpdate = 0;
static unsigned long lastScanBannerUpdate = 0;
static uint32_t alertCount = 0;
static char lastMacAddress[18] = "--";
static int8_t lastRssi = -100;
static const size_t RSSI_GRAPH_POINTS = 60;
static int8_t rssiHistory[RSSI_GRAPH_POINTS] = {0};
static size_t rssiIndex = 0;
static bool rssiFilled = false;
static const size_t CERTAINTY_GRAPH_POINTS = 60;
static uint8_t certaintyHistory[CERTAINTY_GRAPH_POINTS] = {0};
static size_t certaintyIndex = 0;
static bool certaintyFilled = false;
static uint16_t accentColor = TFT_GREEN;
static uint8_t displayBrightness = 160;
static const char* configPath = "/flocksquawk.json";
static const char* fieldLogPath = "/field_log.csv";
static const char* wifiSightingsPath = "/wifi_sightings.csv";
static const char* bleSightingsPath = "/ble_sightings.csv";
static uint32_t bootSessionId = 0;

static const int radarBoxX = 4;
static const int radarBoxW = 312;
static const int radarBoxH = 72;
static const int radarBoxBottomMargin = 4;
static const int radarBoxY = 240 - radarBoxH - radarBoxBottomMargin;
static const int radarLineInsetX = 2;
static const int radarLineInsetY = 2;

static const int rssiBoxX = 200;
static const int rssiBoxY = 62;
static const int rssiBoxW = 116;
static const int rssiBoxH = 44;
static const int certaintyBoxX = 200;
static const int certaintyBoxY = 124;
static const int certaintyBoxW = 116;
static const int certaintyBoxH = 32;

static const int scanTextX = 4;
static const int scanTextY = 24;
static const int infoTextBaseY = scanTextY + 18;

enum class MenuMode {
    None,
    Main,
    GPSSettings,
    DebugSettings,
    AdjustBacklight,
    AdjustAccent,
    AdjustGeoRadius,
    AdjustTheme,
    AdjustScreenSaver,
    ResetMenu
};

static MenuMode menuMode = MenuMode::None;
static int menuIndex = 0;
static const char* menuItems[] = {
    "Backlight",
    "Accent Color",
    "Theme",
    "Night Mode",
    "1/6/11 Hop",
    "GPS Settings",
    "Car Mode",
    "Screen Saver",
    "Battery Saver",
    "Logging",
    "Debug Settings",
    "Save Settings",
    "Reset",
    "Back"
};
static const size_t menuItemCount = sizeof(menuItems) / sizeof(menuItems[0]);
static const int menuVisibleCount = 5;
static int gpsMenuIndex = 0;
static const char* gpsMenuItems[] = {
    "GPS",
    "Geo Alert",
    "GPS Port",
    "Geo Radius",
    "Back"
};
static const size_t gpsMenuItemCount = sizeof(gpsMenuItems) / sizeof(gpsMenuItems[0]);
static int debugMenuIndex = 0;
static const char* debugMenuItems[] = {
    "Test RF Alert",
    "Test GEO Alert",
    "Screen Test",
    "Startup Sound",
    "Back"
};
static const size_t debugMenuItemCount = sizeof(debugMenuItems) / sizeof(debugMenuItems[0]);
static int resetMenuIndex = 0;
static const char* resetMenuItems[] = {
    "Reset Alerts",
    "Factory Reset",
    "Back"
};
static const size_t resetMenuItemCount = sizeof(resetMenuItems) / sizeof(resetMenuItems[0]);

struct AccentOption {
    const char* name;
    uint16_t color;
};

static const AccentOption accentOptions[] = {
    {"Green", TFT_GREEN},
    {"Cyan", TFT_CYAN},
    {"Blue", TFT_BLUE},
    {"Sky", TFT_SKYBLUE},
    {"Navy", TFT_NAVY},
    {"Purple", TFT_MAGENTA},
    {"Pink", TFT_PINK},
    {"Amber", TFT_ORANGE},
    {"Yellow", TFT_YELLOW},
    {"White", TFT_WHITE},
    {"Grey", TFT_LIGHTGREY},
    {"Red", TFT_RED}
};
static const size_t accentOptionCount = sizeof(accentOptions) / sizeof(accentOptions[0]);
static size_t accentIndex = 0;
static bool menuJustOpened = false;
static bool alertActive = false;
static bool alertPopupGeo = false;
static unsigned long alertStart = 0;
static unsigned long lastAlertDraw = 0;
static bool batterySaverEnabled = false;
static bool commonChannelHopEnabled = true;
static bool gpsEnabled = true;
static bool geoAlertEnabled = true;
static bool loggingEnabled = false;
static uint16_t geoRadiusMeters = 300;
static uint8_t gpsPortMode = 1; // 0 = Port C RX16/TX17, 1 = Port B RX36/TX26
enum CarModeMode : uint8_t {
    CAR_MODE_OFF = 0,
    CAR_MODE_ON = 1,
    CAR_MODE_AUTO = 2
};
static CarModeMode carModeMode = CAR_MODE_OFF;
static bool nightModeEnabled = false;
static bool screenSaverEnabled = true;
static uint8_t screenSaverTimeoutSec = 60;
static bool displayIsOff = false;
static bool carModePromptActive = false;
static bool carModeSawExternalPower = false;
static bool externalPowerStableState = false;
static uint8_t externalPowerScore = 0;
static uint32_t lastExternalPowerSampleMs = 0;
static uint32_t carModeExternalPowerSinceMs = 0;
static uint32_t carModeUnplugStartMs = 0;
static uint32_t lastCarModePromptUpdate = 0;
static const uint32_t CAR_MODE_UNPLUG_TIMEOUT_MS = 30000;
static const uint32_t CAR_MODE_ARM_DELAY_MS = 8000;
static const uint32_t EXTERNAL_POWER_SAMPLE_MS = 250;
static const uint8_t EXTERNAL_POWER_SCORE_MAX = 4;
static const uint8_t EXTERNAL_POWER_ON_SCORE = 2;
static bool infoPopupActive = false;
static unsigned long infoPopupStart = 0;
static const char* infoPopupText = "";
static AlertLevel lastAlertLevel = ALERT_NONE;
static uint8_t lastCertainty = 0;
static char lastRadioType[16] = "--";
static char lastDetectionLabel[18] = "idle";
static const size_t RADAR_BLIP_COUNT = 6;
static const size_t ACTIVE_THREAT_COUNT = 8;
static const uint32_t ACTIVE_THREAT_TIMEOUT_MS = 15000;
static const uint32_t ALERT_POPUP_MS = 3000;
static const uint32_t FIELD_LOG_STATUS_INTERVAL_MS = 30000;
static const uint32_t ALERT_REPEAT_SUPPRESS_MS = 10000;
static const uint32_t SIGHTING_REFRESH_MS = 12000;
static const int8_t WIFI_SIGHTING_MIN_RSSI = -82;
static const int8_t BLE_SIGHTING_MIN_RSSI = -88;
static const int8_t SIGHTING_RSSI_IMPROVE_DB = 8;
static const uint16_t BLE_EMPTY_HEALTH_LOG_EVERY = 120;
static const size_t WIFI_SIGHTING_TRACK_COUNT = 128;
static const size_t BLE_SIGHTING_TRACK_COUNT = 64;
static const size_t ALERT_COOLDOWN_TRACK_COUNT = 16;

struct RadarBlip {
    int16_t x;
    int16_t y;
    uint8_t ttl;
    AlertLevel level;
};

static RadarBlip radarBlips[RADAR_BLIP_COUNT];
static size_t nextRadarBlip = 0;
static uint32_t lastThreatSeenMs = 0;

struct ActiveThreat {
    uint8_t mac[6];
    uint32_t lastSeenMs;
    AlertLevel level;
};

static ActiveThreat activeThreats[ACTIVE_THREAT_COUNT];
static bool fieldLogReady = false;
static bool wifiSightingsReady = false;
static bool bleSightingsReady = false;
static uint32_t loggingTimerStartMs = 0;
static uint32_t wifiFramesSeen = 0;
static uint32_t bleDevicesSeen = 0;
static uint32_t threatEventsSeen = 0;
static uint32_t wifiSightingsLogged = 0;
static uint32_t bleSightingsLogged = 0;
static uint32_t bleScanStarts = 0;
static uint32_t bleScanEnds = 0;
static uint32_t bleScanResults = 0;
static uint32_t bleScanFailures = 0;
static uint32_t bleScanResultsAtStart = 0;
static uint32_t lastFieldStatusLogMs = 0;

struct MacThrottleSlot {
    uint8_t mac[6];
    uint32_t lastLogMs;
    int8_t lastLoggedRssi;
};

static MacThrottleSlot wifiSightingSlots[WIFI_SIGHTING_TRACK_COUNT];
static MacThrottleSlot bleSightingSlots[BLE_SIGHTING_TRACK_COUNT];
static MacThrottleSlot alertCooldownSlots[ALERT_COOLDOWN_TRACK_COUNT];

static const char* geoTargetsPath = "/geo_targets.csv";
static const char* geoIndexPath = "/geo_index.csv";
static const uint32_t GPS_BAUD = 115200;
static const uint32_t GEO_SCAN_INTERVAL_MS = 3000;
static const uint32_t GPS_FIX_STALE_MS = 10000;
static const float GEO_NEAR_EXTRA_M = 200.0f;
static const float GEO_GROUP_MARGIN_M = 2500.0f;
static const float GEO_MAP_RANGE_M = 2500.0f;
static const size_t GEO_ACTIVE_GROUP_COUNT = 4;
static const size_t GEO_MAP_TARGET_COUNT = 12;
static bool gpsSerialStarted = false;
static bool gpsHasFix = false;
static bool gpsEverHadFix = false;
static double gpsLat = 0.0;
static double gpsLon = 0.0;
static float gpsCourseDeg = 0.0f;
static bool gpsHasCourse = false;
static uint8_t gpsSatellites = 0;
static float gpsHdop = 99.9f;
static uint32_t lastGpsFixMs = 0;
static uint32_t lastGeoScanMs = 0;
static float nearestGeoDistanceM = -1.0f;
static char nearestGeoLabel[24] = "--";
static bool geoInsideFence = false;
static bool geoNearFence = false;
static bool geoAlertLatched = false;
static char nmeaLine[96];
static uint8_t nmeaLineIndex = 0;

struct GeoActiveGroup {
    char path[40];
    char label[18];
    float centerDistanceM;
    uint16_t radiusM;
    uint16_t count;
};

struct GeoMapTarget {
    double lat;
    double lon;
    float distanceM;
    uint16_t radiusM;
    char label[18];
};

static GeoActiveGroup geoActiveGroups[GEO_ACTIVE_GROUP_COUNT];
static size_t geoActiveGroupCount = 0;
static bool geoIndexAvailable = false;
static char nearestGeoGroupLabel[18] = "--";
static float nearestGeoGroupDistanceM = -1.0f;
static GeoMapTarget geoMapTargets[GEO_MAP_TARGET_COUNT];
static size_t geoMapTargetCount = 0;
static uint32_t lastUserInputMs = 0;
static uint32_t lastSaverUpdate = 0;
static bool screenSaverActive = false;

struct ThemePreset {
    const char* name;
    uint16_t accent;
    uint16_t label;
    uint16_t dim;
};

static const ThemePreset themePresets[] = {
    {"Custom", TFT_GREEN, TFT_CYAN, TFT_DARKGREY},
    {"Matrix", TFT_GREEN, TFT_GREEN, TFT_DARKGREEN},
    {"Amber", TFT_ORANGE, TFT_YELLOW, TFT_DARKGREY},
    {"Ice", TFT_CYAN, TFT_SKYBLUE, TFT_DARKGREY},
    {"Emergency", TFT_RED, TFT_ORANGE, TFT_DARKGREY},
    {"Ghost", TFT_WHITE, TFT_LIGHTGREY, TFT_DARKGREY}
};
static const size_t themePresetCount = sizeof(themePresets) / sizeof(themePresets[0]);
static size_t themeIndex = 0;

static bool loadSettingsFromSd();
static bool saveSettingsToSd();
static void setDisplayPower(bool on);
static void resetHomeUi();
static void restartGpsSerial();
static void updateGpsGeo();
static void triggerAlert(bool incrementCount, uint8_t certainty = 100);
static void triggerGeoAlert(bool incrementCount = true);
static void showInfoPopup(const char* text);
static void updateAccentAnimation();
static void markUserInput();
static void handleScreenSaver();
static void handleCarModePower(uint32_t now);
static void applyThemePreset();
static void setLoggingEnabled(bool enabled);
static uint16_t themeLabelColor();
static uint16_t themeDimColor();
static bool rawExternalPowerPresent();
static bool externalPowerPresent(uint32_t now, bool forceSample = false);
static void seedExternalPowerState(bool present);
static bool isCarModeEnabled();
static bool carModeBlocksPowerSaving();
static const char* carModeModeName();
static void initFieldLog();
static void logFieldEvent(const char* event, const ThreatEvent* threat = nullptr);
static void clearDisplayedThreat(const char* eventName);
static void initSightingLogs();
static void logWifiSighting(const WiFiFrameEvent& frame);
static void logBleSighting(const BluetoothDeviceEvent& device);
static bool shouldEmitAlertForMac(const uint8_t* mac, uint32_t now);

// Event bus handler implementations
EventBus::WiFiFrameHandler EventBus::wifiHandler = nullptr;
EventBus::BluetoothHandler EventBus::bluetoothHandler = nullptr;
EventBus::ThreatHandler EventBus::threatHandler = nullptr;
EventBus::SystemEventHandler EventBus::systemReadyHandler = nullptr;
EventBus::AudioHandler EventBus::audioHandler = nullptr;

void EventBus::publishWifiFrame(const WiFiFrameEvent& event) {
    if (wifiHandler) wifiHandler(event);
}

void EventBus::publishBluetoothDevice(const BluetoothDeviceEvent& event) {
    if (bluetoothHandler) bluetoothHandler(event);
}

void EventBus::publishThreat(const ThreatEvent& event) {
    if (threatHandler) threatHandler(event);
}

void EventBus::publishSystemReady() {
    if (systemReadyHandler) systemReadyHandler();
}

void EventBus::publishAudioRequest(const AudioEvent& event) {
    if (audioHandler) audioHandler(event);
}

void EventBus::subscribeWifiFrame(WiFiFrameHandler handler) {
    wifiHandler = handler;
}

void EventBus::subscribeBluetoothDevice(BluetoothHandler handler) {
    bluetoothHandler = handler;
}

void EventBus::subscribeThreat(ThreatHandler handler) {
    threatHandler = handler;
}

void EventBus::subscribeSystemReady(SystemEventHandler handler) {
    systemReadyHandler = handler;
}

void EventBus::subscribeAudioRequest(AudioHandler handler) {
    audioHandler = handler;
}

// Thread-safe deferred event processing
static portMUX_TYPE wifiMux = portMUX_INITIALIZER_UNLOCKED;
static portMUX_TYPE bleMux = portMUX_INITIALIZER_UNLOCKED;
static portMUX_TYPE threatMux = portMUX_INITIALIZER_UNLOCKED;
static const uint8_t WIFI_EVENT_QUEUE_SIZE = 32;
static const uint8_t BLE_EVENT_QUEUE_SIZE = 16;
static const uint8_t THREAT_EVENT_QUEUE_SIZE = 16;
static const uint8_t WIFI_EVENTS_PER_LOOP = 12;
static const uint8_t BLE_EVENTS_PER_LOOP = 4;
static const uint8_t THREAT_EVENTS_PER_LOOP = 12;
static WiFiFrameEvent wifiFrameQueue[WIFI_EVENT_QUEUE_SIZE];
static BluetoothDeviceEvent bleDeviceQueue[BLE_EVENT_QUEUE_SIZE];
static ThreatEvent threatQueue[THREAT_EVENT_QUEUE_SIZE];
static volatile uint8_t wifiQueueHead = 0;
static volatile uint8_t wifiQueueTail = 0;
static volatile uint8_t bleQueueHead = 0;
static volatile uint8_t bleQueueTail = 0;
static volatile uint8_t threatQueueHead = 0;
static volatile uint8_t threatQueueTail = 0;
static volatile uint16_t wifiQueueDrops = 0;
static volatile uint16_t bleQueueDrops = 0;
static volatile uint16_t threatQueueDrops = 0;

static bool enqueueWiFiFrame(const WiFiFrameEvent& event) {
    bool queued = false;
    portENTER_CRITICAL(&wifiMux);
    uint8_t nextHead = (wifiQueueHead + 1) % WIFI_EVENT_QUEUE_SIZE;
    if (nextHead != wifiQueueTail) {
        wifiFrameQueue[wifiQueueHead] = event;
        wifiQueueHead = nextHead;
        queued = true;
    } else if (wifiQueueDrops < UINT16_MAX) {
        wifiQueueDrops++;
    }
    portEXIT_CRITICAL(&wifiMux);
    return queued;
}

static bool dequeueWiFiFrame(WiFiFrameEvent* event) {
    bool hasEvent = false;
    portENTER_CRITICAL(&wifiMux);
    if (wifiQueueTail != wifiQueueHead) {
        *event = wifiFrameQueue[wifiQueueTail];
        wifiQueueTail = (wifiQueueTail + 1) % WIFI_EVENT_QUEUE_SIZE;
        hasEvent = true;
    }
    portEXIT_CRITICAL(&wifiMux);
    return hasEvent;
}

static bool enqueueBleDevice(const BluetoothDeviceEvent& event) {
    bool queued = false;
    portENTER_CRITICAL(&bleMux);
    uint8_t nextHead = (bleQueueHead + 1) % BLE_EVENT_QUEUE_SIZE;
    if (nextHead != bleQueueTail) {
        bleDeviceQueue[bleQueueHead] = event;
        bleQueueHead = nextHead;
        queued = true;
    } else if (bleQueueDrops < UINT16_MAX) {
        bleQueueDrops++;
    }
    portEXIT_CRITICAL(&bleMux);
    return queued;
}

static bool dequeueBleDevice(BluetoothDeviceEvent* event) {
    bool hasEvent = false;
    portENTER_CRITICAL(&bleMux);
    if (bleQueueTail != bleQueueHead) {
        *event = bleDeviceQueue[bleQueueTail];
        bleQueueTail = (bleQueueTail + 1) % BLE_EVENT_QUEUE_SIZE;
        hasEvent = true;
    }
    portEXIT_CRITICAL(&bleMux);
    return hasEvent;
}

static bool enqueueThreat(const ThreatEvent& event) {
    bool queued = false;
    portENTER_CRITICAL(&threatMux);
    uint8_t nextHead = (threatQueueHead + 1) % THREAT_EVENT_QUEUE_SIZE;
    if (nextHead != threatQueueTail) {
        threatQueue[threatQueueHead] = event;
        threatQueueHead = nextHead;
        queued = true;
    } else if (threatQueueDrops < UINT16_MAX) {
        threatQueueDrops++;
    }
    portEXIT_CRITICAL(&threatMux);
    return queued;
}

static bool dequeueThreat(ThreatEvent* event) {
    bool hasEvent = false;
    portENTER_CRITICAL(&threatMux);
    if (threatQueueTail != threatQueueHead) {
        *event = threatQueue[threatQueueTail];
        threatQueueTail = (threatQueueTail + 1) % THREAT_EVENT_QUEUE_SIZE;
        hasEvent = true;
    }
    portEXIT_CRITICAL(&threatMux);
    return hasEvent;
}

// RadioScannerManager implementation
void RadioScannerManager::initialize() {
    configureWiFiSniffer();
    configureBluetoothScanner();
}

void RadioScannerManager::configureWiFiSniffer() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    wifi_promiscuous_filter_t filter;
    memset(&filter, 0, sizeof(filter));
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(wifiPacketHandler);
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_channel(currentWifiChannel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    
    Serial.println("[RF] WiFi sniffer activated");
}

void RadioScannerManager::configureBluetoothScanner() {
    NimBLEDevice::init("");
    bleScanner = NimBLEDevice::getScan();
    bleScanner->setActiveScan(true);
    bleScanner->setInterval(80);
    bleScanner->setWindow(80);
    
    class BLEDeviceObserver : public NimBLEScanCallbacks {
        void onResult(const NimBLEAdvertisedDevice* device) override {
            bleScanResults++;
            BluetoothDeviceEvent event;
            memset(&event, 0, sizeof(event));
            
            NimBLEAddress addr = device->getAddress();
            std::string addrStr = addr.toString();
            sscanf(addrStr.c_str(), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                   &event.mac[0], &event.mac[1], &event.mac[2],
                   &event.mac[3], &event.mac[4], &event.mac[5]);
            
            event.rssi = device->getRSSI();
            
            if (device->haveName()) {
                strncpy(event.name, device->getName().c_str(), sizeof(event.name) - 1);
            }
            
            event.hasServiceUUID = device->haveServiceUUID();
            if (event.hasServiceUUID && device->getServiceUUIDCount() > 0) {
                NimBLEUUID uuid = device->getServiceUUID(0);
                strncpy(event.serviceUUID, uuid.toString().c_str(), sizeof(event.serviceUUID) - 1);
            }

            if (device->haveManufacturerData()) {
                std::string mfg = device->getManufacturerData();
                if (mfg.length() >= 2) {
                    event.hasManufacturerId = true;
                    event.manufacturerId =
                        static_cast<uint8_t>(mfg[0]) |
                        (static_cast<uint16_t>(static_cast<uint8_t>(mfg[1])) << 8);
                }
            }
            
            EventBus::publishBluetoothDevice(event);
        }
        
        void onScanEnd(const NimBLEScanResults& results, int reason) override {
            (void)results;
            (void)reason;
        }
    };
    
    bleScanner->setScanCallbacks(new BLEDeviceObserver());
    Serial.println("[RF] Bluetooth scanner initialized");
    logFieldEvent("ble_scan_config");
}

uint8_t RadioScannerManager::getCurrentWifiChannel() {
    return currentWifiChannel;
}

bool RadioScannerManager::isBluetoothScanning() {
    return isScanningBLE;
}

void RadioScannerManager::setCommonChannelMode(bool enabled) {
    commonChannelMode = enabled;
    currentWifiChannel = enabled ? 1 : currentWifiChannel;
    esp_wifi_set_channel(currentWifiChannel, WIFI_SECOND_CHAN_NONE);
}

bool RadioScannerManager::isCommonChannelMode() {
    return commonChannelMode;
}

void RadioScannerManager::update() {
    switchWifiChannel();
    performBLEScan();
}

void RadioScannerManager::switchWifiChannel() {
    unsigned long now = millis();
    if (now - lastChannelSwitch >= CHANNEL_SWITCH_MS) {
        if (commonChannelMode) {
            if (currentWifiChannel == 1) {
                currentWifiChannel = 6;
            } else if (currentWifiChannel == 6) {
                currentWifiChannel = 11;
            } else {
                currentWifiChannel = 1;
            }
        } else {
            currentWifiChannel++;
            if (currentWifiChannel > MAX_WIFI_CHANNEL) {
                currentWifiChannel = 1;
            }
        }
        esp_wifi_set_channel(currentWifiChannel, WIFI_SECOND_CHAN_NONE);
        lastChannelSwitch = now;
    }
}

void RadioScannerManager::performBLEScan() {
    unsigned long now = millis();
    if (now - lastBLEScan >= BLE_SCAN_INTERVAL_MS && !isScanningBLE) {
        if (bleScanner && !bleScanner->isScanning()) {
            bleScanner->start(BLE_SCAN_SECONDS, false);
            isScanningBLE = true;
            lastBLEScan = now;
            bleScanStarts++;
            bleScanResultsAtStart = bleScanResults;
        } else if (!bleScanner) {
            bleScanFailures++;
            lastBLEScan = now;
            logFieldEvent("ble_scan_no_scanner");
        }
    }
    
    if (isScanningBLE && bleScanner && !bleScanner->isScanning()) {
        if (now - lastBLEScan > BLE_SCAN_SECONDS * 1000) {
            bleScanner->clearResults();
            isScanningBLE = false;
            bleScanEnds++;
            if (bleScanResults != bleScanResultsAtStart) {
                logFieldEvent("ble_scan_end");
            } else if (BLE_EMPTY_HEALTH_LOG_EVERY > 0 &&
                       (bleScanEnds % BLE_EMPTY_HEALTH_LOG_EVERY) == 0) {
                logFieldEvent("ble_scan_empty");
            }
        }
    }
}

struct WiFi80211Header {
    uint16_t frameControl;
    uint16_t duration;
    uint8_t destination[6];
    uint8_t source[6];
    uint8_t bssid[6];
    uint16_t sequence;
};

void RadioScannerManager::wifiPacketHandler(void* buffer, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t* packet = (wifi_promiscuous_pkt_t*)buffer;
    const uint8_t* rawData = packet->payload;
    
    if (packet->rx_ctrl.sig_len < 24) return;
    
    const WiFi80211Header* header = (const WiFi80211Header*)rawData;
    uint8_t frameType = (header->frameControl & 0x000C) >> 2;
    uint8_t frameSubtype = (header->frameControl & 0x00F0) >> 4;
    
    bool isManagementFrame = (frameType == 0x00);
    bool isDataFrame = (frameType == 0x02);
    bool isProbeRequest = (frameSubtype == 0x04);
    bool isProbeResponse = (frameSubtype == 0x05);
    bool isBeacon = (frameSubtype == 0x08);

    if (!isDataFrame && !(isManagementFrame &&
        (isProbeRequest || isProbeResponse || isBeacon))) {
        return;
    }

    WiFiFrameEvent event;
    memset(&event, 0, sizeof(event));

    memcpy(event.mac, header->source, 6);
    memcpy(event.receiverMac, header->destination, 6);
    memcpy(event.bssid, header->bssid, 6);
    event.rssi = packet->rx_ctrl.rssi;
    event.frameType = frameType;
    event.frameSubtype = frameSubtype;
    event.channel = RadioScannerManager::currentWifiChannel;
    event.hasReceiverMac = true;
    event.hasBssid = isManagementFrame;

    const uint8_t* payload = rawData + sizeof(WiFi80211Header);

    if (isManagementFrame && (isBeacon || isProbeResponse)) {
        payload += 12;
    }
    
    size_t payloadOffset = payload - rawData;
    if (isManagementFrame && packet->rx_ctrl.sig_len >= payloadOffset + 2) {
        if (payload[0] == 0 && payload[1] <= 32) {
            size_t ssidLen = payload[1];
            size_t ssidEnd = payloadOffset + 2 + ssidLen;
            if (packet->rx_ctrl.sig_len >= ssidEnd) {
                event.wildcardSsid = (isProbeRequest && ssidLen == 0);
            }
            if (ssidLen > 0 && packet->rx_ctrl.sig_len >= ssidEnd) {
                memcpy(event.ssid, payload + 2, ssidLen);
                event.ssid[ssidLen] = '\0';
            }
        }
    }
    
    EventBus::publishWifiFrame(event);
}

uint8_t RadioScannerManager::currentWifiChannel = 1;
unsigned long RadioScannerManager::lastChannelSwitch = 0;
unsigned long RadioScannerManager::lastBLEScan = 0;
NimBLEScan* RadioScannerManager::bleScanner = nullptr;
bool RadioScannerManager::isScanningBLE = false;
bool RadioScannerManager::commonChannelMode = true;
uint16_t RadioScannerManager::CHANNEL_SWITCH_MS = 300;
uint8_t RadioScannerManager::BLE_SCAN_SECONDS = 3;
uint32_t RadioScannerManager::BLE_SCAN_INTERVAL_MS = 3000;

// SoundEngine implementation
void SoundEngine::initialize() {
    volumeLevel = DEFAULT_VOLUME;
    tempVolumeActive = false;
    tempVolumeRestoreMs = 0;
    
    SPI.begin(SoundEngine::SD_SCK, SoundEngine::SD_MISO, SoundEngine::SD_MOSI, SoundEngine::SD_CS);
    if (!SD.begin(SoundEngine::SD_CS, SPI)) {
        Serial.println("[Audio] Failed to mount SD card");
        return;
    }
    
    M5.Speaker.begin();
    setVolume(volumeLevel);
    Serial.println("[Audio] Sound system initialized");
}

void SoundEngine::applySpeakerVolume(float level) {
    if (level < 0.0f) level = 0.0f;
    if (level > 1.0f) level = 1.0f;
    uint8_t scaled = static_cast<uint8_t>(
        roundf(level * SoundEngine::MAX_SPEAKER_GAIN * 255.0f));
    M5.Speaker.setVolume(scaled);
}

void SoundEngine::setVolume(float level) {
    if (level >= 0.0f && level <= 1.0f) {
        volumeLevel = level;
        if (!tempVolumeActive) {
            applySpeakerVolume(volumeLevel);
        }
    }
}

float SoundEngine::getVolumeLevel() const {
    return volumeLevel;
}

float SoundEngine::confidenceVolumeScale(uint8_t certainty) const {
    if (certainty < 20) return 0.25f;
    if (certainty < 50) return 0.55f;
    if (certainty < 80) return 0.78f;
    return 1.0f;
}

void SoundEngine::applyTemporaryConfidenceVolume(uint8_t certainty,
                                                 uint16_t holdMs) {
    restoreTemporaryVolumeIfNeeded();
    if (volumeLevel <= 0.0f) return;
    uint8_t boundedCertainty = certainty > 100 ? 100 : certainty;
    applySpeakerVolume(volumeLevel * confidenceVolumeScale(boundedCertainty));
    tempVolumeActive = true;
    tempVolumeRestoreMs = millis() + holdMs;
}

void SoundEngine::restoreTemporaryVolumeIfNeeded() {
    if (!tempVolumeActive) return;
    if ((int32_t)(millis() - tempVolumeRestoreMs) < 0) return;
    applySpeakerVolume(volumeLevel);
    tempVolumeActive = false;
}

void SoundEngine::playConfidenceBeep(uint8_t certainty, AlertLevel level) {
    uint8_t boundedCertainty = certainty > 100 ? 100 : certainty;
    uint16_t frequency = 1350;
    uint16_t durationMs = 35;

    if (boundedCertainty >= 80) {
        frequency = 2300;
        durationMs = 95;
    } else if (boundedCertainty >= 50) {
        frequency = 2050;
        durationMs = 75;
    } else if (boundedCertainty >= 20) {
        frequency = 1750;
        durationMs = 55;
    }

    if (level >= ALERT_CONFIRMED && boundedCertainty < 50) {
        frequency = 1900;
        durationMs = 70;
    }

    applyTemporaryConfidenceVolume(boundedCertainty, durationMs + 25);
    M5.Speaker.tone(frequency, durationMs);
}

bool SoundEngine::playToneFallback(const char* filename, bool asyncMode) {
    if (!filename) return false;

    const char* soundName = soundNameFromFilename(filename);
    if (!soundName) return false;

    if (playCustomToneSequence(soundName)) {
        return true;
    }

    return playDefaultToneSequence(soundName, asyncMode);
}

const char* SoundEngine::soundNameFromFilename(const char* filename) const {
    if (!filename) return nullptr;
    if (strstr(filename, "geo")) return "geo";
    if (strstr(filename, "alert")) return "alert";
    if (strstr(filename, "ready")) return "ready";
    if (strstr(filename, "startup")) return "startup";
    return nullptr;
}

bool SoundEngine::playCustomToneSequence(const char* soundName) {
    if (!soundName || !SD.exists(SoundEngine::TONE_PROFILE_PATH)) {
        return false;
    }

    File profile = SD.open(SoundEngine::TONE_PROFILE_PATH, FILE_READ);
    if (!profile) return false;

    bool played = false;
    uint8_t noteCount = 0;
    while (profile.available() && noteCount < 16) {
        String line = profile.readStringUntil('\n');
        line.trim();
        if (line.length() == 0 || line[0] == '#') continue;

        int c1 = line.indexOf(',');
        int c2 = line.indexOf(',', c1 + 1);
        int c3 = line.indexOf(',', c2 + 1);
        if (c1 <= 0 || c2 <= c1 || c3 <= c2) continue;

        String name = line.substring(0, c1);
        name.trim();
        if (!name.equalsIgnoreCase(soundName)) continue;

        uint16_t frequency = static_cast<uint16_t>(
            line.substring(c1 + 1, c2).toInt());
        uint16_t durationMs = static_cast<uint16_t>(
            line.substring(c2 + 1, c3).toInt());
        uint16_t gapMs = static_cast<uint16_t>(
            line.substring(c3 + 1).toInt());

        if (frequency > 0 && durationMs > 0) {
            M5.Speaker.tone(frequency, durationMs);
            delay(durationMs);
            played = true;
            noteCount++;
        }
        if (gapMs > 0) {
            delay(gapMs);
        }
        M5.update();
    }

    profile.close();
    return played;
}

bool SoundEngine::playDefaultToneSequence(const char* soundName, bool asyncMode) {
    if (!soundName) return false;

    if (strcmp(soundName, "alert") == 0) {
        M5.Speaker.tone(2400, 700);
        return true;
    }

    if (strcmp(soundName, "geo") == 0) {
        M5.Speaker.tone(1250, 120);
        delay(150);
        M5.Speaker.tone(1650, 120);
        delay(150);
        M5.Speaker.tone(2050, 180);
        return true;
    }

    if (strcmp(soundName, "ready") == 0) {
        if (asyncMode) {
            M5.Speaker.tone(1800, 180);
            return true;
        }
        M5.Speaker.tone(1300, 90);
        delay(120);
        M5.Speaker.tone(1750, 100);
        delay(130);
        M5.Speaker.tone(2200, 140);
        delay(170);
        return true;
    }

    if (strcmp(soundName, "startup") == 0) {
        if (asyncMode) {
            M5.Speaker.tone(1568, 160);
            return true;
        }
        M5.Speaker.tone(784, 90);
        delay(115);
        M5.Speaker.tone(988, 70);
        delay(90);
        M5.Speaker.tone(1175, 90);
        delay(115);
        M5.Speaker.tone(1568, 130);
        delay(165);
        M5.Speaker.tone(1319, 70);
        delay(90);
        M5.Speaker.tone(1760, 160);
        delay(190);
        return true;
    }

    return false;
}

static uint16_t readLe16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) |
           (static_cast<uint16_t>(p[1]) << 8);
}

static uint32_t readLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

bool SoundEngine::inspectWavBuffer(const uint8_t* data, size_t length,
                                   WavInfo* info) const {
    if (!data || length < 44 || !info) return false;
    if (memcmp(data, "RIFF", 4) != 0 || memcmp(data + 8, "WAVE", 4) != 0) {
        return false;
    }

    memset(info, 0, sizeof(WavInfo));
    size_t pos = 12;
    bool haveFmt = false;
    bool haveData = false;

    while (pos + 8 <= length) {
        const uint8_t* chunk = data + pos;
        uint32_t chunkSize = readLe32(chunk + 4);
        size_t next = pos + 8 + chunkSize + (chunkSize & 1);
        if (next > length + 1) return false;

        if (memcmp(chunk, "fmt ", 4) == 0) {
            if (chunkSize < 16 || pos + 24 > length) return false;
            uint16_t format = readLe16(chunk + 8);
            info->pcm = (format == 1);
            info->channels = readLe16(chunk + 10);
            info->sampleRate = readLe32(chunk + 12);
            info->bitsPerSample = readLe16(chunk + 22);
            haveFmt = true;
        } else if (memcmp(chunk, "data", 4) == 0) {
            haveData = chunkSize > 0;
        }

        pos = next;
    }

    return haveFmt && haveData;
}

bool SoundEngine::isSupportedWav(const WavInfo& info) const {
    return info.pcm &&
           info.channels == 1 &&
           info.bitsPerSample == 16 &&
           info.sampleRate == 16000;
}

bool SoundEngine::loadWavFromSd(const char* filename, uint8_t** outData, size_t* outLength) {
    if (!SD.exists(filename)) {
        Serial.printf("[Audio] Cannot open: %s\n", filename);
        return false;
    }
    
    File audioFile = SD.open(filename, FILE_READ);
    if (!audioFile) {
        Serial.printf("[Audio] Failed to open: %s\n", filename);
        return false;
    }
    
    size_t dataSize = audioFile.size();
    if (dataSize == 0) {
        Serial.printf("[Audio] Empty file: %s\n", filename);
        audioFile.close();
        return false;
    }
    
#if defined(ps_malloc)
    uint8_t* wavData = static_cast<uint8_t*>(ps_malloc(dataSize));
#else
    uint8_t* wavData = static_cast<uint8_t*>(malloc(dataSize));
#endif
    if (!wavData) {
        Serial.printf("[Audio] Out of memory loading: %s\n", filename);
        audioFile.close();
        return false;
    }
    
    size_t bytesRead = audioFile.read(wavData, dataSize);
    audioFile.close();
    if (bytesRead != dataSize) {
        Serial.printf("[Audio] Read error: %s\n", filename);
        free(wavData);
        return false;
    }

    WavInfo info;
    if (!inspectWavBuffer(wavData, dataSize, &info)) {
        Serial.printf("[Audio] Invalid WAV: %s\n", filename);
        free(wavData);
        return false;
    }
    if (!isSupportedWav(info)) {
        Serial.printf("[Audio] Unsupported WAV: %s pcm=%d ch=%u bits=%u rate=%lu\n",
                      filename, info.pcm ? 1 : 0, info.channels,
                      info.bitsPerSample,
                      static_cast<unsigned long>(info.sampleRate));
        Serial.println("[Audio] Use mono 16-bit PCM WAV at 16000 Hz");
        free(wavData);
        return false;
    }
    
    *outData = wavData;
    *outLength = dataSize;
    return true;
}

void SoundEngine::playSound(const char* filename) {
    if (!SoundEngine::USE_WAV_FILES && playToneFallback(filename, false)) {
        return;
    }

    uint8_t* wavData = nullptr;
    size_t dataSize = 0;
    if (!loadWavFromSd(filename, &wavData, &dataSize)) {
        playToneFallback(filename, false);
        return;
    }
    
    M5.Speaker.playWav(wavData, dataSize);
    while (M5.Speaker.isPlaying()) {
        M5.update();
        delay(5);
    }
    free(wavData);
}

void SoundEngine::playSoundAsync(const char* filename) {
    if (!SoundEngine::USE_WAV_FILES && playToneFallback(filename, true)) {
        return;
    }

    if (asyncActive && M5.Speaker.isPlaying()) {
        return;
    }
    if (asyncActive && asyncBuffer) {
        free(asyncBuffer);
        asyncBuffer = nullptr;
        asyncLength = 0;
        asyncActive = false;
    }
    
    if (!loadWavFromSd(filename, &asyncBuffer, &asyncLength)) {
        playToneFallback(filename, true);
        return;
    }
    
    asyncActive = true;
    M5.Speaker.playWav(asyncBuffer, asyncLength);
}

void SoundEngine::playSoundAsyncAtConfidence(const char* filename,
                                             uint8_t certainty) {
    applyTemporaryConfidenceVolume(certainty, 900);
    playSoundAsync(filename);
}

void SoundEngine::update() {
    restoreTemporaryVolumeIfNeeded();
    if (asyncActive && !M5.Speaker.isPlaying()) {
        if (asyncBuffer) {
            free(asyncBuffer);
            asyncBuffer = nullptr;
        }
        asyncLength = 0;
        asyncActive = false;
    }
}

void SoundEngine::handleAudioRequest(const AudioEvent& event) {
    playSound(event.soundFile);
}

static void drawBootTextCentered(const char* text, int y,
                                 uint8_t size, uint16_t color) {
    M5.Display.setTextSize(size);
    M5.Display.setTextColor(color, TFT_BLACK);
    int16_t x = (320 - M5.Display.textWidth(text)) / 2;
    if (x < 0) x = 0;
    M5.Display.drawString(text, x, y);
}

static void drawBootScreen(uint8_t progress, const char* status) {
    if (progress > 100) progress = 100;
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.drawRect(8, 8, 304, 224, TFT_DARKGREY);
    M5.Display.drawRect(12, 12, 296, 216, TFT_NAVY);

    M5.Display.setTextSize(1);
    M5.Display.setTextColor(TFT_DARKGREY, TFT_BLACK);
    M5.Display.drawString("M5 FIRE / GPS", 18, 20);
    M5.Display.drawString("PASSIVE RF", 244, 20);

    drawBootTextCentered("GET", 48, 2, TFT_ORANGE);
    drawBootTextCentered("FLOCKED", 74, 3, TFT_RED);
    drawBootTextCentered("SIGNAL DECK v4.31", 114, 1, TFT_CYAN);

    int barX = 34;
    int barY = 168;
    int barW = 252;
    int barH = 18;
    M5.Display.drawRect(barX, barY, barW, barH, TFT_DARKGREY);
    int fillW = ((barW - 2) * progress) / 100;
    if (fillW > 0) {
        M5.Display.fillRect(barX + 1, barY + 1, fillW, barH - 2, TFT_GREEN);
    }
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.drawString(status, 34, 196);
    M5.Display.setTextColor(TFT_DARKGREY, TFT_BLACK);
    M5.Display.drawString(String(progress) + "%", 258, 196);
}

// Main system initialization
void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("Initializing Threat Detection System...");
    Serial.println();

    M5.begin();
    bootSessionId = esp_random();
    if (bootSessionId == 0) {
        bootSessionId = millis();
    }
    M5.Display.clear();
    M5.Display.setTextSize(2);
    M5.Display.setCursor(0, 0);
    drawBootScreen(5, "lighting up the signal deck");
    
    audioSystem.initialize();
    drawBootScreen(18, "audio checks passed");
    loadSettingsFromSd();
    setDisplayPower(true);
    drawBootScreen(30, "settings loaded");
    seedExternalPowerState(rawExternalPowerPresent());
    carModeSawExternalPower = externalPowerStableState;
    carModeExternalPowerSinceMs = externalPowerStableState ? millis() : 0;
    if (loggingEnabled && loggingTimerStartMs == 0) {
        loggingTimerStartMs = millis();
    }
    initFieldLog();
    initSightingLogs();
    logFieldEvent("boot");
    drawBootScreen(42, loggingEnabled ? "field logging armed" : "field logging paused");
    audioSystem.playSound("startup");
    
    EventBus::subscribeWifiFrame([](const WiFiFrameEvent& event) {
        enqueueWiFiFrame(event);
    });

    EventBus::subscribeBluetoothDevice([](const BluetoothDeviceEvent& event) {
        enqueueBleDevice(event);
    });

    EventBus::subscribeThreat([](const ThreatEvent& event) {
        enqueueThreat(event);
    });
    
    EventBus::subscribeAudioRequest([](const AudioEvent& event) {
        audioSystem.handleAudioRequest(event);
    });
    
    EventBus::subscribeSystemReady([]() {
        drawBootScreen(100, "scan ready - go get flocked");
        homeReadyTimestamp = millis();
        homeScreenPending = true;
        audioSystem.playSound("ready");
    });
    
    threatEngine.initialize();
    drawBootScreen(58, "detectors loaded");
    reporter.initialize();
    drawBootScreen(68, "telemetry online");
    rfScanner.initialize();
    drawBootScreen(82, "radios tuned");
    RadioScannerManager::setCommonChannelMode(commonChannelHopEnabled);
    restartGpsSerial();
    drawBootScreen(94, gpsEnabled ? "gps listener ready" : "gps listener paused");
    
    Serial.println("System operational - scanning for targets");
    Serial.println();
    
    EventBus::publishSystemReady();
}

#if ENABLE_HOME_UI
static void drawHomeFrame() {
    M5.Display.clear(TFT_BLACK);
    M5.Display.setTextSize(1);
    M5.Display.setCursor(0, 0);
    
    // Top bar
    M5.Display.drawFastHLine(0, 20, 320, TFT_DARKGREY);
    M5.Display.setTextColor(themeLabelColor(), TFT_BLACK);
    M5.Display.drawString("VOL", 4, 4);
    M5.Display.drawString("RAM", 110, 4);
    M5.Display.drawString("UP", 184, 4);
    M5.Display.drawString("BAT", 250, 4);
    
    // Info labels
    M5.Display.setTextColor(themeLabelColor(), TFT_BLACK);
    int textBaseY = infoTextBaseY;
    M5.Display.drawString("WiFi CH:", 4, textBaseY);
    M5.Display.drawString("Last MAC:", 4, textBaseY + 18);
    M5.Display.drawString("Alerts:", 4, textBaseY + 36);
    M5.Display.drawString("Threat:", 4, textBaseY + 54);
    M5.Display.drawString("Range:", 4, textBaseY + 72);
    M5.Display.drawString("InRng:", 4, textBaseY + 90);
    M5.Display.drawString("GPS:", 4, 144);
    M5.Display.drawString("Geo:", 4, 154);
    M5.Display.drawString("RSSI", rssiBoxX, rssiBoxY - 12);
    M5.Display.drawString("CONF", certaintyBoxX, certaintyBoxY - 12);
    M5.Display.drawString("BT", 292, scanTextY);
    
    // RSSI graph frame
    M5.Display.drawRect(rssiBoxX, rssiBoxY, rssiBoxW, rssiBoxH, TFT_DARKGREY);
    M5.Display.drawRect(certaintyBoxX, certaintyBoxY, certaintyBoxW, certaintyBoxH, TFT_DARKGREY);
    
    // Radar frame (empty box)
    M5.Display.drawRect(radarBoxX, radarBoxY, radarBoxW, radarBoxH, TFT_DARKGREY);
}

static uint16_t alertLevelColor(AlertLevel level) {
    switch (level) {
        case ALERT_CONFIRMED:  return TFT_RED;
        case ALERT_SUSPICIOUS: return TFT_ORANGE;
        case ALERT_INFO:       return TFT_CYAN;
        default:               return TFT_DARKGREEN;
    }
}

static const char* alertLevelName(AlertLevel level) {
    switch (level) {
        case ALERT_CONFIRMED:  return "CONF";
        case ALERT_SUSPICIOUS: return "SUSP";
        case ALERT_INFO:       return "INFO";
        default:               return "CLEAR";
    }
}

static const char* rangeNameFromRssi(int8_t rssi) {
    if (rssi > -55) return "HOT";
    if (rssi > -72) return "NEAR";
    return "FAR";
}

static uint16_t rangeColorFromRssi(int8_t rssi) {
    if (rssi > -55) return TFT_RED;
    if (rssi > -72) return TFT_ORANGE;
    return TFT_CYAN;
}

static void recordActiveThreat(const ThreatEvent& threat) {
    if (threat.alertLevel < ALERT_SUSPICIOUS) return;

    uint32_t now = millis();
    uint8_t slot = ACTIVE_THREAT_COUNT;
    uint32_t oldest = UINT32_MAX;
    uint8_t oldestSlot = 0;

    for (uint8_t i = 0; i < ACTIVE_THREAT_COUNT; i++) {
        if (activeThreats[i].lastSeenMs != 0 &&
            memcmp(activeThreats[i].mac, threat.mac, 6) == 0) {
            slot = i;
            break;
        }
        if (activeThreats[i].lastSeenMs == 0) {
            slot = i;
            break;
        }
        if (activeThreats[i].lastSeenMs < oldest) {
            oldest = activeThreats[i].lastSeenMs;
            oldestSlot = i;
        }
    }

    if (slot == ACTIVE_THREAT_COUNT) slot = oldestSlot;
    memcpy(activeThreats[slot].mac, threat.mac, 6);
    activeThreats[slot].lastSeenMs = now;
    activeThreats[slot].level = threat.alertLevel;
}

static uint8_t activeThreatInRangeCount() {
    uint32_t now = millis();
    uint8_t count = 0;
    for (uint8_t i = 0; i < ACTIVE_THREAT_COUNT; i++) {
        if (activeThreats[i].lastSeenMs == 0) continue;
        if (now - activeThreats[i].lastSeenMs > ACTIVE_THREAT_TIMEOUT_MS) {
            activeThreats[i].lastSeenMs = 0;
            activeThreats[i].level = ALERT_NONE;
            continue;
        }
        if (activeThreats[i].level >= ALERT_SUSPICIOUS) {
            count++;
        }
    }
    return count;
}

static int gpsRxPin() {
    return gpsPortMode == 0 ? 16 : 36;
}

static int gpsTxPin() {
    return gpsPortMode == 0 ? 17 : 26;
}

static const char* gpsPortName() {
    return gpsPortMode == 0 ? "C" : "B";
}

static void restartGpsSerial() {
    gpsSerial.end();
    gpsSerialStarted = false;
    if (!gpsEnabled) return;
    gpsSerial.begin(GPS_BAUD, SERIAL_8N1, gpsRxPin(), gpsTxPin());
    gpsSerialStarted = true;
    Serial.printf("[GPS] Enabled on Port %s RX=%d TX=%d @ %lu\n",
                  gpsPortName(), gpsRxPin(), gpsTxPin(),
                  static_cast<unsigned long>(GPS_BAUD));
}

static double nmeaToDecimal(const char* raw, const char* hemi) {
    if (!raw || !hemi || raw[0] == '\0' || hemi[0] == '\0') return 0.0;
    double v = atof(raw);
    int degrees = static_cast<int>(v / 100.0);
    double minutes = v - (degrees * 100.0);
    double decimal = degrees + (minutes / 60.0);
    if (hemi[0] == 'S' || hemi[0] == 'W') decimal = -decimal;
    return decimal;
}

static bool nextCsvField(char** cursor, char* out, size_t outLen) {
    if (!cursor || !*cursor || !out || outLen == 0) return false;
    char* start = *cursor;
    char* comma = strchr(start, ',');
    if (comma) {
        *comma = '\0';
        *cursor = comma + 1;
    } else {
        *cursor = start + strlen(start);
    }
    strncpy(out, start, outLen - 1);
    out[outLen - 1] = '\0';
    return true;
}

static void parseGgaSentence(char* line) {
    char* cursor = line;
    char field[18];
    char latRaw[16] = "";
    char latHemi[3] = "";
    char lonRaw[16] = "";
    char lonHemi[3] = "";
    char fixQuality[4] = "";
    char sats[4] = "";
    char hdop[8] = "";

    nextCsvField(&cursor, field, sizeof(field)); // $GPGGA / $GNGGA
    nextCsvField(&cursor, field, sizeof(field)); // time
    nextCsvField(&cursor, latRaw, sizeof(latRaw));
    nextCsvField(&cursor, latHemi, sizeof(latHemi));
    nextCsvField(&cursor, lonRaw, sizeof(lonRaw));
    nextCsvField(&cursor, lonHemi, sizeof(lonHemi));
    nextCsvField(&cursor, fixQuality, sizeof(fixQuality));
    nextCsvField(&cursor, sats, sizeof(sats));
    nextCsvField(&cursor, hdop, sizeof(hdop));

    bool fixed = atoi(fixQuality) > 0;
    gpsSatellites = static_cast<uint8_t>(atoi(sats));
    gpsHdop = atof(hdop);
    if (fixed && latRaw[0] != '\0' && lonRaw[0] != '\0') {
        gpsLat = nmeaToDecimal(latRaw, latHemi);
        gpsLon = nmeaToDecimal(lonRaw, lonHemi);
        gpsHasFix = true;
        gpsEverHadFix = true;
        lastGpsFixMs = millis();
    }
}

static void parseRmcSentence(char* line) {
    char* cursor = line;
    char field[18];
    char status[3] = "";
    char latRaw[16] = "";
    char latHemi[3] = "";
    char lonRaw[16] = "";
    char lonHemi[3] = "";
    char speedKnotsField[10] = "";
    char courseField[10] = "";

    nextCsvField(&cursor, field, sizeof(field)); // $GPRMC / $GNRMC
    nextCsvField(&cursor, field, sizeof(field)); // time
    nextCsvField(&cursor, status, sizeof(status));
    nextCsvField(&cursor, latRaw, sizeof(latRaw));
    nextCsvField(&cursor, latHemi, sizeof(latHemi));
    nextCsvField(&cursor, lonRaw, sizeof(lonRaw));
    nextCsvField(&cursor, lonHemi, sizeof(lonHemi));
    nextCsvField(&cursor, speedKnotsField, sizeof(speedKnotsField));
    nextCsvField(&cursor, courseField, sizeof(courseField));

    if (status[0] == 'A' && latRaw[0] != '\0' && lonRaw[0] != '\0') {
        gpsLat = nmeaToDecimal(latRaw, latHemi);
        gpsLon = nmeaToDecimal(lonRaw, lonHemi);
        gpsHasFix = true;
        gpsEverHadFix = true;
        lastGpsFixMs = millis();
        float speedKnots = atof(speedKnotsField);
        if (courseField[0] != '\0' && speedKnots >= 0.8f) {
            gpsCourseDeg = atof(courseField);
            if (gpsCourseDeg < 0.0f) gpsCourseDeg = 0.0f;
            while (gpsCourseDeg >= 360.0f) gpsCourseDeg -= 360.0f;
            gpsHasCourse = true;
        } else if (speedKnots < 0.8f) {
            gpsHasCourse = false;
        }
    }
}

static int8_t hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static bool nmeaChecksumValid(char* line) {
    if (!line || line[0] != '$') return false;
    char* star = strchr(line, '*');
    if (!star || !star[1] || !star[2]) return false;

    uint8_t checksum = 0;
    for (char* p = line + 1; p < star; p++) {
        checksum ^= static_cast<uint8_t>(*p);
    }

    int8_t high = hexNibble(star[1]);
    int8_t low = hexNibble(star[2]);
    if (high < 0 || low < 0) return false;
    if (checksum != static_cast<uint8_t>((high << 4) | low)) return false;

    *star = '\0';
    return true;
}

static void parseNmeaLine(char* line) {
    if (!nmeaChecksumValid(line)) return;
    if (strncmp(line, "$GPGGA", 6) == 0 || strncmp(line, "$GNGGA", 6) == 0) {
        parseGgaSentence(line);
    } else if (strncmp(line, "$GPRMC", 6) == 0 || strncmp(line, "$GNRMC", 6) == 0) {
        parseRmcSentence(line);
    }
}

static float distanceMeters(double lat1, double lon1, double lat2, double lon2) {
    const double earthRadiusM = 6371000.0;
    double p1 = lat1 * DEG_TO_RAD;
    double p2 = lat2 * DEG_TO_RAD;
    double dp = (lat2 - lat1) * DEG_TO_RAD;
    double dl = (lon2 - lon1) * DEG_TO_RAD;
    double a = sin(dp / 2.0) * sin(dp / 2.0) +
               cos(p1) * cos(p2) * sin(dl / 2.0) * sin(dl / 2.0);
    double c = 2.0 * atan2(sqrt(a), sqrt(1.0 - a));
    return static_cast<float>(earthRadiusM * c);
}

static bool parseGeoTargetLine(char* line, double* lat, double* lon,
                               uint16_t* radiusM, char* label, size_t labelLen) {
    if (!line || line[0] == '\0' || line[0] == '#') return false;
    if (strstr(line, "lat") && strstr(line, "lon")) return false;

    char* cursor = line;
    char id[24] = "";
    char latField[18] = "";
    char lonField[18] = "";
    char radiusField[10] = "";
    char labelField[24] = "";

    if (!nextCsvField(&cursor, id, sizeof(id))) return false;
    if (!nextCsvField(&cursor, latField, sizeof(latField))) return false;
    if (!nextCsvField(&cursor, lonField, sizeof(lonField))) return false;
    nextCsvField(&cursor, radiusField, sizeof(radiusField));
    nextCsvField(&cursor, labelField, sizeof(labelField));

    *lat = atof(latField);
    *lon = atof(lonField);
    *radiusM = geoRadiusMeters;
    const char* src = labelField[0] != '\0' ? labelField : id;
    strncpy(label, src, labelLen - 1);
    label[labelLen - 1] = '\0';
    return (*lat != 0.0 || *lon != 0.0);
}

static void clearGeoMapTargets() {
    geoMapTargetCount = 0;
}

static void addGeoMapTarget(double lat, double lon, float distanceM,
                            uint16_t radiusM, const char* label) {
    if (distanceM > GEO_MAP_RANGE_M) return;

    size_t slot = geoMapTargetCount;
    if (slot >= GEO_MAP_TARGET_COUNT) {
        float farthest = -1.0f;
        slot = 0;
        for (size_t i = 0; i < GEO_MAP_TARGET_COUNT; i++) {
            if (geoMapTargets[i].distanceM > farthest) {
                farthest = geoMapTargets[i].distanceM;
                slot = i;
            }
        }
        if (distanceM >= farthest) return;
    } else {
        geoMapTargetCount++;
    }

    geoMapTargets[slot].lat = lat;
    geoMapTargets[slot].lon = lon;
    geoMapTargets[slot].distanceM = distanceM;
    geoMapTargets[slot].radiusM = radiusM;
    strncpy(geoMapTargets[slot].label, label ? label : "", sizeof(geoMapTargets[slot].label) - 1);
    geoMapTargets[slot].label[sizeof(geoMapTargets[slot].label) - 1] = '\0';
}

static bool parseGeoIndexLine(char* line, double* centerLat, double* centerLon,
                              uint16_t* radiusM, uint16_t* count,
                              char* path, size_t pathLen,
                              char* label, size_t labelLen) {
    if (!line || line[0] == '\0' || line[0] == '#') return false;
    if (strstr(line, "center_lat") && strstr(line, "center_lon")) return false;

    char* cursor = line;
    char state[8] = "";
    char groupId[18] = "";
    char latField[18] = "";
    char lonField[18] = "";
    char radiusField[10] = "";
    char countField[8] = "";
    char pathField[40] = "";
    char labelField[18] = "";

    if (!nextCsvField(&cursor, state, sizeof(state))) return false;
    if (!nextCsvField(&cursor, groupId, sizeof(groupId))) return false;
    if (!nextCsvField(&cursor, latField, sizeof(latField))) return false;
    if (!nextCsvField(&cursor, lonField, sizeof(lonField))) return false;
    if (!nextCsvField(&cursor, radiusField, sizeof(radiusField))) return false;
    nextCsvField(&cursor, countField, sizeof(countField));
    nextCsvField(&cursor, pathField, sizeof(pathField));
    nextCsvField(&cursor, labelField, sizeof(labelField));

    *centerLat = atof(latField);
    *centerLon = atof(lonField);
    *radiusM = static_cast<uint16_t>(atoi(radiusField));
    *count = static_cast<uint16_t>(atoi(countField));
    if (*radiusM == 0 || pathField[0] == '\0') return false;

    strncpy(path, pathField, pathLen - 1);
    path[pathLen - 1] = '\0';
    const char* labelSrc = labelField[0] != '\0' ? labelField : groupId;
    strncpy(label, labelSrc, labelLen - 1);
    label[labelLen - 1] = '\0';
    return (*centerLat != 0.0 || *centerLon != 0.0);
}

static void sortActiveGeoGroups() {
    for (size_t i = 0; i < geoActiveGroupCount; i++) {
        for (size_t j = i + 1; j < geoActiveGroupCount; j++) {
            if (geoActiveGroups[j].centerDistanceM < geoActiveGroups[i].centerDistanceM) {
                GeoActiveGroup tmp = geoActiveGroups[i];
                geoActiveGroups[i] = geoActiveGroups[j];
                geoActiveGroups[j] = tmp;
            }
        }
    }
}

static void addActiveGeoGroup(const char* path, const char* label,
                              float distanceM, uint16_t radiusM,
                              uint16_t count) {
    size_t slot = geoActiveGroupCount;
    if (slot >= GEO_ACTIVE_GROUP_COUNT) {
        float farthest = -1.0f;
        slot = 0;
        for (size_t i = 0; i < GEO_ACTIVE_GROUP_COUNT; i++) {
            if (geoActiveGroups[i].centerDistanceM > farthest) {
                farthest = geoActiveGroups[i].centerDistanceM;
                slot = i;
            }
        }
        if (distanceM >= farthest) return;
    } else {
        geoActiveGroupCount++;
    }

    strncpy(geoActiveGroups[slot].path, path, sizeof(geoActiveGroups[slot].path) - 1);
    geoActiveGroups[slot].path[sizeof(geoActiveGroups[slot].path) - 1] = '\0';
    strncpy(geoActiveGroups[slot].label, label, sizeof(geoActiveGroups[slot].label) - 1);
    geoActiveGroups[slot].label[sizeof(geoActiveGroups[slot].label) - 1] = '\0';
    geoActiveGroups[slot].centerDistanceM = distanceM;
    geoActiveGroups[slot].radiusM = radiusM;
    geoActiveGroups[slot].count = count;
    sortActiveGeoGroups();
}

static bool selectGeoGroupsFromIndex() {
    geoActiveGroupCount = 0;
    geoIndexAvailable = false;
    nearestGeoGroupDistanceM = -1.0f;
    strncpy(nearestGeoGroupLabel, "--", sizeof(nearestGeoGroupLabel) - 1);
    nearestGeoGroupLabel[sizeof(nearestGeoGroupLabel) - 1] = '\0';

    File file = SD.open(geoIndexPath, FILE_READ);
    if (!file) {
        return false;
    }
    geoIndexAvailable = true;

    char line[144];
    while (file.available()) {
        size_t len = file.readBytesUntil('\n', line, sizeof(line) - 1);
        line[len] = '\0';
        char* cr = strchr(line, '\r');
        if (cr) *cr = '\0';

        double centerLat = 0.0;
        double centerLon = 0.0;
        uint16_t radiusM = 0;
        uint16_t count = 0;
        char path[40] = "";
        char label[18] = "";
        if (!parseGeoIndexLine(line, &centerLat, &centerLon,
                               &radiusM, &count, path, sizeof(path),
                               label, sizeof(label))) {
            continue;
        }

        float d = distanceMeters(gpsLat, gpsLon, centerLat, centerLon);
        if (nearestGeoGroupDistanceM < 0.0f || d < nearestGeoGroupDistanceM) {
            nearestGeoGroupDistanceM = d;
            strncpy(nearestGeoGroupLabel, label, sizeof(nearestGeoGroupLabel) - 1);
            nearestGeoGroupLabel[sizeof(nearestGeoGroupLabel) - 1] = '\0';
        }
        if (d <= static_cast<float>(radiusM) + GEO_GROUP_MARGIN_M) {
            addActiveGeoGroup(path, label, d, radiusM, count);
        }
    }

    file.close();
    return true;
}

static bool scanGeoTargetFile(const char* path, float* bestDistance,
                              uint16_t* bestRadius, char* bestLabel,
                              size_t bestLabelLen) {
    File file = SD.open(path, FILE_READ);
    if (!file) return false;

    bool found = false;
    char line[112];
    while (file.available()) {
        size_t len = file.readBytesUntil('\n', line, sizeof(line) - 1);
        line[len] = '\0';
        char* cr = strchr(line, '\r');
        if (cr) *cr = '\0';

        double targetLat = 0.0;
        double targetLon = 0.0;
        uint16_t targetRadius = geoRadiusMeters;
        char targetLabel[24] = "";
        if (!parseGeoTargetLine(line, &targetLat, &targetLon,
                                &targetRadius, targetLabel,
                                sizeof(targetLabel))) {
            continue;
        }

        found = true;
        float d = distanceMeters(gpsLat, gpsLon, targetLat, targetLon);
        addGeoMapTarget(targetLat, targetLon, d, targetRadius, targetLabel);
        if (d < *bestDistance) {
            *bestDistance = d;
            *bestRadius = targetRadius;
            strncpy(bestLabel, targetLabel, bestLabelLen - 1);
            bestLabel[bestLabelLen - 1] = '\0';
        }
    }

    file.close();
    return found;
}

static void scanGeoTargets() {
    if (!geoAlertEnabled || !gpsHasFix) {
        geoInsideFence = false;
        geoNearFence = false;
        nearestGeoDistanceM = -1.0f;
        clearGeoMapTargets();
        return;
    }

    clearGeoMapTargets();
    float bestDistance = 99999999.0f;
    uint16_t bestRadius = geoRadiusMeters;
    char bestLabel[24] = "--";
    bool foundAny = false;
    bool usedIndex = selectGeoGroupsFromIndex();

    if (usedIndex) {
        for (size_t i = 0; i < geoActiveGroupCount; i++) {
            if (scanGeoTargetFile(geoActiveGroups[i].path, &bestDistance,
                                  &bestRadius, bestLabel,
                                  sizeof(bestLabel))) {
                foundAny = true;
            }
        }
    } else {
        foundAny = scanGeoTargetFile(geoTargetsPath, &bestDistance,
                                     &bestRadius, bestLabel,
                                     sizeof(bestLabel));
    }

    if (!foundAny) {
        nearestGeoDistanceM = -1.0f;
        if (usedIndex) {
            if (nearestGeoGroupDistanceM >= 0.0f) {
                strncpy(nearestGeoLabel, nearestGeoGroupLabel, sizeof(nearestGeoLabel) - 1);
            } else {
                strncpy(nearestGeoLabel, "no group", sizeof(nearestGeoLabel) - 1);
            }
        } else {
            strncpy(nearestGeoLabel, "no file", sizeof(nearestGeoLabel) - 1);
        }
        nearestGeoLabel[sizeof(nearestGeoLabel) - 1] = '\0';
        geoInsideFence = false;
        geoNearFence = false;
        return;
    }

    nearestGeoDistanceM = bestDistance;
    strncpy(nearestGeoLabel, bestLabel, sizeof(nearestGeoLabel) - 1);
    nearestGeoLabel[sizeof(nearestGeoLabel) - 1] = '\0';
    geoInsideFence = bestDistance <= bestRadius;
    geoNearFence = !geoInsideFence && bestDistance <= (bestRadius + GEO_NEAR_EXTRA_M);
}

static void updateGpsGeo() {
    if (!gpsEnabled) {
        gpsHasFix = false;
        gpsHasCourse = false;
        geoInsideFence = false;
        geoNearFence = false;
        clearGeoMapTargets();
        return;
    }
    if (!gpsSerialStarted) {
        restartGpsSerial();
    }

    while (gpsSerial.available()) {
        char c = static_cast<char>(gpsSerial.read());
        if (c == '\n') {
            nmeaLine[nmeaLineIndex] = '\0';
            if (nmeaLineIndex > 6) {
                parseNmeaLine(nmeaLine);
            }
            nmeaLineIndex = 0;
        } else if (c != '\r') {
            if (nmeaLineIndex < sizeof(nmeaLine) - 1) {
                nmeaLine[nmeaLineIndex++] = c;
            } else {
                nmeaLineIndex = 0;
            }
        }
    }

    uint32_t now = millis();
    if (gpsHasFix && now - lastGpsFixMs > GPS_FIX_STALE_MS) {
        gpsHasFix = false;
        gpsHasCourse = false;
        clearGeoMapTargets();
    }

    if (now - lastGeoScanMs >= GEO_SCAN_INTERVAL_MS) {
        lastGeoScanMs = now;
        scanGeoTargets();
        if (geoAlertEnabled && geoInsideFence && !geoAlertLatched) {
            geoAlertLatched = true;
            logFieldEvent("geo_alert");
            triggerGeoAlert(true);
        } else if (!geoInsideFence) {
            geoAlertLatched = false;
        }
    }
}

static const char* geoStatusName() {
    if (!geoAlertEnabled) return "OFF";
    if (!gpsEnabled) return "GPSOFF";
    if (!gpsHasFix) return gpsEverHadFix ? "STALE" : "NOFIX";
    if (geoInsideFence) return "HOT";
    if (geoNearFence) return "NEAR";
    return "CLEAR";
}

static uint16_t geoStatusColor() {
    if (geoInsideFence) return TFT_BLUE;
    if (geoNearFence) return TFT_CYAN;
    if (gpsHasFix) return TFT_GREEN;
    return TFT_DARKGREY;
}

static void printCsvText(File& file, const char* value) {
    file.print('"');
    if (value) {
        for (const char* p = value; *p; p++) {
            uint8_t c = static_cast<uint8_t>(*p);
            if (c == '"') {
                file.print("\"\"");
            } else if (c == '\r' || c == '\n') {
                file.print(' ');
            } else if (c < 0x20 || c > 0x7E) {
                file.print('?');
            } else {
                file.print(static_cast<char>(c));
            }
        }
    }
    file.print('"');
}

static void printMacCsv(File& file, const uint8_t* mac) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printCsvText(file, macStr);
}

static void formatUptimeHms(uint32_t ms, char* out, size_t outSize) {
    uint32_t totalSeconds = ms / 1000;
    uint32_t hours = totalSeconds / 3600;
    uint32_t minutes = (totalSeconds / 60) % 60;
    uint32_t seconds = totalSeconds % 60;
    snprintf(out, outSize, "%lu:%02lu:%02lu",
             static_cast<unsigned long>(hours),
             static_cast<unsigned long>(minutes),
             static_cast<unsigned long>(seconds));
}

static String uptimeShortString(uint32_t ms) {
    uint32_t totalSeconds = ms / 1000;
    uint32_t hours = totalSeconds / 3600;
    uint32_t minutes = (totalSeconds / 60) % 60;
    uint32_t seconds = totalSeconds % 60;
    char buffer[10];
    if (hours > 0) {
        snprintf(buffer, sizeof(buffer), "%lu:%02lu",
                 static_cast<unsigned long>(hours),
                 static_cast<unsigned long>(minutes));
    } else {
        snprintf(buffer, sizeof(buffer), "%02lu:%02lu",
                 static_cast<unsigned long>(minutes),
                 static_cast<unsigned long>(seconds));
    }
    return String(buffer);
}

static void printUptimeHmsCsv(File& file, uint32_t ms) {
    char uptime[12];
    formatUptimeHms(ms, uptime, sizeof(uptime));
    printCsvText(file, uptime);
}

static uint32_t activeTimerMs(uint32_t nowMs) {
    if (loggingEnabled && loggingTimerStartMs != 0) {
        return nowMs >= loggingTimerStartMs ? nowMs - loggingTimerStartMs : 0;
    }
    return nowMs;
}

static const char* activeTimerModeName() {
    return loggingEnabled ? "log" : "boot";
}

static void printTimerColumnsCsv(File& file, uint32_t nowMs) {
    uint32_t timerMs = activeTimerMs(nowMs);
    file.print(timerMs / 1000); file.print(',');
    printUptimeHmsCsv(file, timerMs); file.print(',');
    file.print(nowMs / 1000); file.print(',');
    printUptimeHmsCsv(file, nowMs); file.print(',');
    printCsvText(file, activeTimerModeName()); file.print(',');
}

static bool macEquals(const uint8_t* a, const uint8_t* b) {
    return memcmp(a, b, 6) == 0;
}

static bool isZeroMac(const uint8_t* mac) {
    for (uint8_t i = 0; i < 6; i++) {
        if (mac[i] != 0) return false;
    }
    return true;
}

static bool shouldSkipLoggedMac(const uint8_t* mac) {
    return isZeroMac(mac) || isMulticastOrBroadcastMac(mac);
}

static bool logHeaderHasToken(const char* path, const char* token) {
    File file = SD.open(path, FILE_READ);
    if (!file) return true;
    if (file.size() == 0) {
        file.close();
        return true;
    }
    String header = file.readStringUntil('\n');
    file.close();
    return header.indexOf(token) >= 0;
}

static void rotateLogIfSchemaChanged(const char* path, const char* requiredToken) {
    if (!SD.exists(path) || logHeaderHasToken(path, requiredToken)) return;

    char backupPath[64];
    for (uint8_t i = 1; i < 100; i++) {
        snprintf(backupPath, sizeof(backupPath), "%s.old%02u", path, i);
        if (!SD.exists(backupPath)) {
            if (SD.rename(path, backupPath)) {
                Serial.printf("[Log] Rotated old log schema %s to %s\n", path, backupPath);
            } else {
                Serial.printf("[Log] Could not rotate old log schema for %s\n", path);
            }
            return;
        }
    }
}

static int findMacThrottleSlot(MacThrottleSlot* slots, size_t count,
                               const uint8_t* mac, bool* matched) {
    int firstEmpty = -1;
    int oldestSlot = 0;
    uint32_t oldestMs = UINT32_MAX;

    if (matched) *matched = false;
    for (size_t i = 0; i < count; i++) {
        if (slots[i].lastLogMs != 0 && macEquals(slots[i].mac, mac)) {
            if (matched) *matched = true;
            return static_cast<int>(i);
        }
        if (slots[i].lastLogMs == 0 && firstEmpty < 0) {
            firstEmpty = static_cast<int>(i);
        }
        if (slots[i].lastLogMs < oldestMs) {
            oldestMs = slots[i].lastLogMs;
            oldestSlot = static_cast<int>(i);
        }
    }

    return firstEmpty >= 0 ? firstEmpty : oldestSlot;
}

static bool shouldLogMacSighting(MacThrottleSlot* slots, size_t count,
                                 const uint8_t* mac, int8_t rssi,
                                 uint32_t now) {
    bool matched = false;
    int slot = findMacThrottleSlot(slots, count, mac, &matched);
    if (slot < 0) return false;

    bool logIt = !matched ||
        now - slots[slot].lastLogMs >= SIGHTING_REFRESH_MS ||
        rssi >= slots[slot].lastLoggedRssi + SIGHTING_RSSI_IMPROVE_DB;

    if (logIt) {
        memcpy(slots[slot].mac, mac, 6);
        slots[slot].lastLogMs = now;
        slots[slot].lastLoggedRssi = rssi;
    }
    return logIt;
}

static void writeWifiSightingsHeader(File& file) {
    file.println(
        "ms,uptime_s,uptime_hms,device_uptime_s,device_uptime_hms,timer_mode,"
        "session_id,role,mac,src_mac,dst_mac,bssid,channel,rssi,frame_type,"
        "frame_subtype,wildcard_ssid,ssid,gps_fix,lat,lon,geo_status,"
        "car_mode,external_power,battery,wifi_frames,threat_events");
}

static void writeBleSightingsHeader(File& file) {
    file.println(
        "ms,uptime_s,uptime_hms,device_uptime_s,device_uptime_hms,timer_mode,"
        "session_id,mac,name,rssi,manufacturer_id,service_uuid,gps_fix,lat,lon,"
        "geo_status,car_mode,external_power,battery,ble_devices,threat_events");
}

static void writeFieldLogHeader(File& file) {
    file.println(
        "ms,uptime_s,uptime_hms,device_uptime_s,device_uptime_hms,timer_mode,"
        "session_id,event,radio,channel,rssi,certainty,alert_level,should_alert,"
        "first_detection,match_flags,rssi_modifier,mac,identifier,category,"
        "gps_fix,lat,lon,sats,hdop,geo_status,geo_distance_m,geo_label,"
        "car_mode,external_power,battery,wifi_frames,ble_devices,threat_events,"
        "wifi_sightings,ble_sightings,ble_scan_starts,ble_scan_ends,"
        "ble_scan_results,ble_scan_failures,alert_count");
}

static void initFieldLog() {
    if (!loggingEnabled) {
        fieldLogReady = false;
        return;
    }
    if (loggingTimerStartMs == 0) {
        loggingTimerStartMs = millis();
    }
    rotateLogIfSchemaChanged(fieldLogPath, "device_uptime_s");
    bool needsHeader = !SD.exists(fieldLogPath);
    File file = SD.open(fieldLogPath, FILE_APPEND);
    if (!file) {
        fieldLogReady = false;
        Serial.println("[Log] Failed to open field log");
        return;
    }
    if (needsHeader || file.size() == 0) {
        writeFieldLogHeader(file);
    }
    file.close();
    fieldLogReady = true;
}

static void initOneSightingsLog(const char* path, bool* ready,
                                void (*writeHeader)(File&)) {
    rotateLogIfSchemaChanged(path, "device_uptime_s");
    bool needsHeader = !SD.exists(path);
    File file = SD.open(path, FILE_APPEND);
    if (!file) {
        *ready = false;
        Serial.printf("[Log] Failed to open %s\n", path);
        return;
    }
    if (needsHeader || file.size() == 0) {
        writeHeader(file);
    }
    file.close();
    *ready = true;
}

static void initSightingLogs() {
    if (!loggingEnabled) {
        wifiSightingsReady = false;
        bleSightingsReady = false;
        return;
    }
    initOneSightingsLog(wifiSightingsPath, &wifiSightingsReady, writeWifiSightingsHeader);
    initOneSightingsLog(bleSightingsPath, &bleSightingsReady, writeBleSightingsHeader);
}

static void logFieldEvent(const char* event, const ThreatEvent* threat) {
    if (!loggingEnabled || !fieldLogReady) return;
    File file = SD.open(fieldLogPath, FILE_APPEND);
    if (!file) {
        fieldLogReady = false;
        return;
    }

    uint32_t nowMs = millis();
    file.print(nowMs); file.print(',');
    printTimerColumnsCsv(file, nowMs);
    file.print(bootSessionId, HEX); file.print(',');
    printCsvText(file, event); file.print(',');

    if (threat) {
        printCsvText(file, threat->radioType); file.print(',');
        file.print(threat->channel); file.print(',');
        file.print(threat->rssi); file.print(',');
        file.print(threat->certainty); file.print(',');
        file.print(static_cast<int>(threat->alertLevel)); file.print(',');
        file.print(threat->shouldAlert ? 1 : 0); file.print(',');
        file.print(threat->firstDetection ? 1 : 0); file.print(',');
        file.print(threat->matchFlags, HEX); file.print(',');
        file.print(threat->rssiModifier); file.print(',');
        printMacCsv(file, threat->mac); file.print(',');
        printCsvText(file, threat->identifier); file.print(',');
        printCsvText(file, threat->category); file.print(',');
    } else {
        file.print(",,,,,,,,,,,,");
    }

    file.print(gpsHasFix ? 1 : 0); file.print(',');
    if (gpsHasFix) file.print(gpsLat, 7);
    file.print(',');
    if (gpsHasFix) file.print(gpsLon, 7);
    file.print(',');
    file.print(gpsSatellites); file.print(',');
    file.print(gpsHdop, 1); file.print(',');
    printCsvText(file, geoStatusName()); file.print(',');
    if (nearestGeoDistanceM >= 0.0f) file.print(nearestGeoDistanceM, 1);
    file.print(',');
    printCsvText(file, nearestGeoLabel); file.print(',');
    printCsvText(file, carModeModeName()); file.print(',');
    file.print(externalPowerStableState ? 1 : 0); file.print(',');
    file.print(M5.Power.getBatteryLevel()); file.print(',');
    file.print(wifiFramesSeen); file.print(',');
    file.print(bleDevicesSeen); file.print(',');
    file.print(threatEventsSeen); file.print(',');
    file.print(wifiSightingsLogged); file.print(',');
    file.print(bleSightingsLogged); file.print(',');
    file.print(bleScanStarts); file.print(',');
    file.print(bleScanEnds); file.print(',');
    file.print(bleScanResults); file.print(',');
    file.print(bleScanFailures); file.print(',');
    file.println(alertCount);
    file.close();
}

static void printWifiSightingRow(const WiFiFrameEvent& frame, const char* role,
                                 const uint8_t* mac, uint32_t now) {
    if (!loggingEnabled || !wifiSightingsReady) return;
    File file = SD.open(wifiSightingsPath, FILE_APPEND);
    if (!file) {
        wifiSightingsReady = false;
        return;
    }

    file.print(now); file.print(',');
    printTimerColumnsCsv(file, now);
    file.print(bootSessionId, HEX); file.print(',');
    printCsvText(file, role); file.print(',');
    printMacCsv(file, mac); file.print(',');
    printMacCsv(file, frame.mac); file.print(',');
    printMacCsv(file, frame.receiverMac); file.print(',');
    if (frame.hasBssid) {
        printMacCsv(file, frame.bssid);
    } else {
        printCsvText(file, "");
    }
    file.print(',');
    file.print(frame.channel); file.print(',');
    file.print(frame.rssi); file.print(',');
    file.print(frame.frameType); file.print(',');
    file.print(frame.frameSubtype); file.print(',');
    file.print(frame.wildcardSsid ? 1 : 0); file.print(',');
    printCsvText(file, frame.ssid); file.print(',');
    file.print(gpsHasFix ? 1 : 0); file.print(',');
    if (gpsHasFix) file.print(gpsLat, 7);
    file.print(',');
    if (gpsHasFix) file.print(gpsLon, 7);
    file.print(',');
    printCsvText(file, geoStatusName()); file.print(',');
    printCsvText(file, carModeModeName()); file.print(',');
    file.print(externalPowerStableState ? 1 : 0); file.print(',');
    file.print(M5.Power.getBatteryLevel()); file.print(',');
    file.print(wifiFramesSeen); file.print(',');
    file.println(threatEventsSeen);
    file.close();
    wifiSightingsLogged++;
}

static void maybeLogWifiSightingRole(const WiFiFrameEvent& frame,
                                      const char* role,
                                      const uint8_t* mac,
                                      bool force) {
    if (!wifiSightingsReady || shouldSkipLoggedMac(mac)) return;
    if (!force && frame.rssi < WIFI_SIGHTING_MIN_RSSI) return;
    uint32_t now = millis();
    if (shouldLogMacSighting(wifiSightingSlots, WIFI_SIGHTING_TRACK_COUNT,
                             mac, frame.rssi, now)) {
        printWifiSightingRow(frame, role, mac, now);
    }
}

static void logWifiSighting(const WiFiFrameEvent& frame) {
    bool force = frame.wildcardSsid || frame.ssid[0] != '\0';
    maybeLogWifiSightingRole(frame, "src", frame.mac, force);
    if (frame.hasReceiverMac) {
        maybeLogWifiSightingRole(frame, "dst", frame.receiverMac, force);
    }
    if (frame.hasBssid) {
        maybeLogWifiSightingRole(frame, "bssid", frame.bssid, force);
    }
}

static void logBleSighting(const BluetoothDeviceEvent& device) {
    if (!loggingEnabled || !bleSightingsReady || shouldSkipLoggedMac(device.mac)) return;
    bool force = device.name[0] != '\0' || device.hasManufacturerId || device.hasServiceUUID;
    if (!force && device.rssi < BLE_SIGHTING_MIN_RSSI) return;
    uint32_t now = millis();
    if (!shouldLogMacSighting(bleSightingSlots, BLE_SIGHTING_TRACK_COUNT,
                              device.mac, device.rssi, now)) {
        return;
    }

    File file = SD.open(bleSightingsPath, FILE_APPEND);
    if (!file) {
        bleSightingsReady = false;
        return;
    }
    file.print(now); file.print(',');
    printTimerColumnsCsv(file, now);
    file.print(bootSessionId, HEX); file.print(',');
    printMacCsv(file, device.mac); file.print(',');
    printCsvText(file, device.name); file.print(',');
    file.print(device.rssi); file.print(',');
    if (device.hasManufacturerId) file.print(device.manufacturerId, HEX);
    file.print(',');
    printCsvText(file, device.hasServiceUUID ? device.serviceUUID : ""); file.print(',');
    file.print(gpsHasFix ? 1 : 0); file.print(',');
    if (gpsHasFix) file.print(gpsLat, 7);
    file.print(',');
    if (gpsHasFix) file.print(gpsLon, 7);
    file.print(',');
    printCsvText(file, geoStatusName()); file.print(',');
    printCsvText(file, carModeModeName()); file.print(',');
    file.print(externalPowerStableState ? 1 : 0); file.print(',');
    file.print(M5.Power.getBatteryLevel()); file.print(',');
    file.print(bleDevicesSeen); file.print(',');
    file.println(threatEventsSeen);
    file.close();
    bleSightingsLogged++;
}

static void setLoggingEnabled(bool enabled) {
    if (enabled == loggingEnabled) {
        if (enabled && (!fieldLogReady || !wifiSightingsReady || !bleSightingsReady)) {
            if (loggingTimerStartMs == 0) {
                loggingTimerStartMs = millis();
            }
            initFieldLog();
            initSightingLogs();
        }
        return;
    }

    if (!enabled) {
        logFieldEvent("logging_off");
        loggingEnabled = false;
        loggingTimerStartMs = 0;
        fieldLogReady = false;
        wifiSightingsReady = false;
        bleSightingsReady = false;
        return;
    }

    loggingTimerStartMs = millis();
    lastFieldStatusLogMs = loggingTimerStartMs;
    loggingEnabled = true;
    initFieldLog();
    initSightingLogs();
    logFieldEvent("logging_on");
}

static bool shouldEmitAlertForMac(const uint8_t* mac, uint32_t now) {
    bool matched = false;
    int slot = findMacThrottleSlot(alertCooldownSlots, ALERT_COOLDOWN_TRACK_COUNT,
                                   mac, &matched);
    if (slot < 0) return true;
    if (matched && now - alertCooldownSlots[slot].lastLogMs < ALERT_REPEAT_SUPPRESS_MS) {
        return false;
    }
    memcpy(alertCooldownSlots[slot].mac, mac, 6);
    alertCooldownSlots[slot].lastLogMs = now;
    alertCooldownSlots[slot].lastLoggedRssi = 0;
    return true;
}

static void clearDisplayedThreat(const char* eventName) {
    lastAlertLevel = ALERT_NONE;
    lastCertainty = 0;
    lastRssi = -100;
    lastThreatSeenMs = 0;
    strncpy(lastRadioType, "--", sizeof(lastRadioType) - 1);
    lastRadioType[sizeof(lastRadioType) - 1] = '\0';
    strncpy(lastDetectionLabel, "idle", sizeof(lastDetectionLabel) - 1);
    lastDetectionLabel[sizeof(lastDetectionLabel) - 1] = '\0';
    certaintyHistory[certaintyIndex] = 0;
    certaintyIndex = (certaintyIndex + 1) % CERTAINTY_GRAPH_POINTS;
    if (certaintyIndex == 0) certaintyFilled = true;
    logFieldEvent(eventName);
}

static uint16_t themeLabelColor() {
    if (nightModeEnabled) return TFT_DARKGREY;
    return themePresets[themeIndex].label;
}

static uint16_t themeDimColor() {
    return themePresets[themeIndex].dim;
}

static void applyThemePreset() {
    if (themeIndex == 0) {
        accentColor = accentOptions[accentIndex].color;
        return;
    }
    accentColor = themePresets[themeIndex].accent;
}

static bool isCarModeEnabled() {
    return carModeMode != CAR_MODE_OFF;
}

static bool carModeBlocksPowerSaving() {
    if (carModeMode == CAR_MODE_ON) return true;
    return carModeMode == CAR_MODE_AUTO && (externalPowerStableState || carModeSawExternalPower);
}

static const char* carModeModeName() {
    switch (carModeMode) {
        case CAR_MODE_ON:   return "On";
        case CAR_MODE_AUTO: return "Auto";
        default:            return "Off";
    }
}

static void updateAccentAnimation() {
    applyThemePreset();
}

static bool rawExternalPowerPresent() {
    return M5.Power.isCharging();
}

static void seedExternalPowerState(bool present) {
    externalPowerScore = present ? EXTERNAL_POWER_SCORE_MAX : 0;
    externalPowerStableState = present;
    carModeExternalPowerSinceMs = present ? millis() : 0;
    lastExternalPowerSampleMs = millis();
}

static bool externalPowerPresent(uint32_t now, bool forceSample) {
    if (!forceSample && lastExternalPowerSampleMs != 0 &&
        now - lastExternalPowerSampleMs < EXTERNAL_POWER_SAMPLE_MS) {
        return externalPowerStableState;
    }

    bool rawPower = rawExternalPowerPresent();
    if (rawPower) {
        if (externalPowerScore < EXTERNAL_POWER_SCORE_MAX) externalPowerScore++;
    } else if (externalPowerScore > 0) {
        externalPowerScore--;
    }

    if (externalPowerScore >= EXTERNAL_POWER_ON_SCORE) {
        externalPowerStableState = true;
    } else if (externalPowerScore == 0) {
        externalPowerStableState = false;
    }

    lastExternalPowerSampleMs = now;
    return externalPowerStableState;
}

static void markUserInput() {
    lastUserInputMs = millis();
    if (screenSaverActive) {
        screenSaverActive = false;
        resetHomeUi();
    }
}

static void drawCarModePrompt(uint32_t now) {
    uint32_t elapsed = now - carModeUnplugStartMs;
    int32_t remaining =
        (int32_t)((CAR_MODE_UNPLUG_TIMEOUT_MS - min(elapsed, CAR_MODE_UNPLUG_TIMEOUT_MS)) / 1000UL);

    M5.Display.fillRect(12, 38, 296, 166, TFT_BLACK);
    M5.Display.drawRect(12, 38, 296, 166, TFT_ORANGE);
    M5.Display.drawRect(14, 40, 292, 162, TFT_DARKGREY);
    M5.Display.setTextSize(2);
    M5.Display.setTextColor(TFT_ORANGE, TFT_BLACK);
    M5.Display.drawString("Car Mode", 92, 52);
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.drawString("External power disconnected.", 36, 86);
    M5.Display.drawString("Disable car mode and stay on?", 36, 106);
    M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
    M5.Display.drawString("Auto off in " + String(remaining) + "s", 96, 130);
    M5.Display.setTextColor(TFT_DARKGREY, TFT_BLACK);
    M5.Display.drawString("A: Sleep   B/C: Disable", 64, 166);
}

static void enterCarModeStandby() {
    setDisplayPower(true);
    M5.Display.clear(TFT_BLACK);
    M5.Display.setTextSize(2);
    M5.Display.setTextColor(TFT_ORANGE, TFT_BLACK);
    M5.Display.drawString("Car Mode", 92, 76);
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.drawString("Entering standby", 102, 116);
    delay(500);
    M5.Display.clear(TFT_BLACK);
    setDisplayPower(false);
    M5.Power.deepSleep(0, false);
    while (true) {
        delay(1000);
    }
}

static void disableCarModeAfterPowerLoss(const char* logEventName) {
    carModeMode = CAR_MODE_OFF;
    carModePromptActive = false;
    carModeSawExternalPower = false;
    carModeExternalPowerSinceMs = 0;
    batterySaverEnabled = false;
    screenSaverActive = false;
    RadioScannerManager::setPerformanceMode(false);
    saveSettingsToSd();
    resetHomeUi();
    logFieldEvent(logEventName);
    showInfoPopup("Car Mode Off");
}

static void handleCarModePower(uint32_t now) {
    bool onExternalPower = externalPowerPresent(now);

    if (!isCarModeEnabled()) {
        carModePromptActive = false;
        carModeSawExternalPower = onExternalPower;
        carModeExternalPowerSinceMs = onExternalPower ? now : 0;
        return;
    }

    if (onExternalPower || (carModeMode == CAR_MODE_ON && !carModeSawExternalPower)) {
        if (onExternalPower) {
            if (!carModeSawExternalPower || carModeExternalPowerSinceMs == 0) {
                carModeExternalPowerSinceMs = now;
            }
            carModeSawExternalPower = true;
        }
        if (carModePromptActive) {
            carModePromptActive = false;
            logFieldEvent("car_power_restored");
            resetHomeUi();
        }
        batterySaverEnabled = false;
        screenSaverActive = false;
        setDisplayPower(true);
        RadioScannerManager::setPerformanceMode(true);
        return;
    }

    RadioScannerManager::setPerformanceMode(false);

    if (carModeMode == CAR_MODE_AUTO && !carModeSawExternalPower) {
        return;
    }

    if (carModeSawExternalPower &&
        (carModeExternalPowerSinceMs == 0 ||
         now - carModeExternalPowerSinceMs < CAR_MODE_ARM_DELAY_MS)) {
        return;
    }

    if (carModeSawExternalPower && !carModePromptActive) {
        carModePromptActive = true;
        carModeUnplugStartMs = now;
        lastCarModePromptUpdate = 0;
        menuMode = MenuMode::None;
        infoPopupActive = false;
        setDisplayPower(true);
        logFieldEvent("car_power_lost");
        drawCarModePrompt(now);
    }

    if (!carModePromptActive) return;

    if (M5.BtnA.wasPressed()) {
        logFieldEvent("car_mode_manual_standby");
        enterCarModeStandby();
    }

    if (M5.BtnB.wasPressed() || M5.BtnC.wasPressed()) {
        disableCarModeAfterPowerLoss("car_mode_user_off");
        return;
    }

    if (now - carModeUnplugStartMs >= CAR_MODE_UNPLUG_TIMEOUT_MS) {
        disableCarModeAfterPowerLoss("car_mode_auto_off");
        return;
    }

    if (now - lastCarModePromptUpdate >= 1000 || lastCarModePromptUpdate == 0) {
        drawCarModePrompt(now);
        lastCarModePromptUpdate = now;
    }
}

static void drawScreenSaver() {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.drawRect(8, 8, 304, 224, TFT_DARKGREY);
    M5.Display.drawRect(12, 12, 296, 216, TFT_NAVY);

    M5.Display.setTextSize(1);
    M5.Display.setTextColor(TFT_DARKGREY, TFT_BLACK);
    M5.Display.drawString("IDLE SCAN", 18, 20);
    M5.Display.drawString("PASSIVE RF", 244, 20);

    drawBootTextCentered("GET", 46, 2, TFT_ORANGE);
    drawBootTextCentered("FLOCKED", 72, 3, TFT_RED);
    drawBootTextCentered("SIGNAL DECK v4.31", 112, 1, TFT_CYAN);

    M5.Display.drawRect(34, 148, 252, 48, TFT_DARKGREY);
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(themeLabelColor(), TFT_BLACK);
    M5.Display.drawString("THREAT", 46, 158);
    M5.Display.drawString("GPS", 46, 174);
    M5.Display.drawString("LOG", 190, 174);
    M5.Display.drawString("GEO", 46, 190);

    M5.Display.setTextColor(alertLevelColor(lastAlertLevel), TFT_BLACK);
    M5.Display.drawString(String(alertLevelName(lastAlertLevel)) + " " + String(lastCertainty) + "%", 110, 158);
    M5.Display.setTextColor(gpsHasFix ? TFT_GREEN : TFT_ORANGE, TFT_BLACK);
    M5.Display.drawString(gpsHasFix ? "FIX" : "NOFIX", 110, 174);
    M5.Display.setTextColor(loggingEnabled ? TFT_GREEN : TFT_DARKGREY, TFT_BLACK);
    M5.Display.drawString(loggingEnabled ? "ON" : "OFF", 228, 174);
    M5.Display.setTextColor(geoStatusColor(), TFT_BLACK);
    M5.Display.drawString(geoStatusName(), 110, 190);

    M5.Display.setTextColor(themeDimColor(), TFT_BLACK);
    M5.Display.drawString("Btn wakes", 132, 212);
}

static void handleScreenSaver() {
    if (carModeBlocksPowerSaving() || !screenSaverEnabled || menuMode != MenuMode::None || alertActive ||
        batterySaverEnabled) {
        screenSaverActive = false;
        return;
    }
    uint32_t now = millis();
    if (!screenSaverActive &&
        now - lastUserInputMs >= static_cast<uint32_t>(screenSaverTimeoutSec) * 1000UL) {
        screenSaverActive = true;
        drawScreenSaver();
        lastSaverUpdate = now;
    }
    if (screenSaverActive && now - lastSaverUpdate >= 1000) {
        drawScreenSaver();
        lastSaverUpdate = now;
    }
}

static void addRadarBlip(const ThreatEvent& threat) {
    uint32_t seed = 0;
    for (uint8_t i = 0; i < 6; i++) {
        seed = (seed * 33u) ^ threat.mac[i];
    }
    int radarW = radarBoxW - (radarLineInsetX * 2) - 8;
    int radarH = radarBoxH - (radarLineInsetY * 2) - 8;
    radarBlips[nextRadarBlip].x = radarBoxX + radarLineInsetX + 4 + (seed % radarW);
    radarBlips[nextRadarBlip].y = radarBoxY + radarLineInsetY + 4 + ((seed >> 8) % radarH);
    radarBlips[nextRadarBlip].ttl = 18;
    radarBlips[nextRadarBlip].level = threat.alertLevel;
    nextRadarBlip = (nextRadarBlip + 1) % RADAR_BLIP_COUNT;
}

static void updateScanningBanner() {
    M5.Display.fillRect(scanTextX, scanTextY, 260, 16, TFT_BLACK);
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.setCursor(scanTextX, scanTextY);
    M5.Display.print("Scanning for Flock signatures");
}

static void updateRssiGraph() {
    M5.Display.fillRect(rssiBoxX + 1, rssiBoxY + 1, rssiBoxW - 2, rssiBoxH - 2, TFT_BLACK);
    
    size_t points = rssiFilled ? RSSI_GRAPH_POINTS : rssiIndex;
    if (points < 2) return;
    
    int graphW = rssiBoxW - 2;
    int graphH = rssiBoxH - 2;
    int x0 = rssiBoxX + 1;
    int y0 = rssiBoxY + 1;
    
    auto mapRssi = [graphH](int8_t rssi) {
        if (rssi < -100) rssi = -100;
        if (rssi > -30) rssi = -30;
        int norm = rssi + 100; // 0..70
        return graphH - 1 - (norm * (graphH - 1) / 70);
    };
    
    for (size_t i = 1; i < points; i++) {
        size_t idx0 = (rssiIndex + RSSI_GRAPH_POINTS - points + i - 1) % RSSI_GRAPH_POINTS;
        size_t idx1 = (rssiIndex + RSSI_GRAPH_POINTS - points + i) % RSSI_GRAPH_POINTS;
        
        int xA = x0 + static_cast<int>((i - 1) * (graphW - 1) / (points - 1));
        int xB = x0 + static_cast<int>(i * (graphW - 1) / (points - 1));
        int yA = y0 + mapRssi(rssiHistory[idx0]);
        int yB = y0 + mapRssi(rssiHistory[idx1]);
        
        M5.Display.drawLine(xA, yA, xB, yB, accentColor);
    }
}

static void updateCertaintyGraph() {
    M5.Display.fillRect(certaintyBoxX + 1, certaintyBoxY + 1,
                        certaintyBoxW - 2, certaintyBoxH - 2, TFT_BLACK);

    size_t points = certaintyFilled ? CERTAINTY_GRAPH_POINTS : certaintyIndex;
    if (points < 2) return;

    int graphW = certaintyBoxW - 2;
    int graphH = certaintyBoxH - 2;
    int x0 = certaintyBoxX + 1;
    int y0 = certaintyBoxY + 1;

    for (size_t i = 1; i < points; i++) {
        size_t idx0 = (certaintyIndex + CERTAINTY_GRAPH_POINTS - points + i - 1) % CERTAINTY_GRAPH_POINTS;
        size_t idx1 = (certaintyIndex + CERTAINTY_GRAPH_POINTS - points + i) % CERTAINTY_GRAPH_POINTS;

        int xA = x0 + static_cast<int>((i - 1) * (graphW - 1) / (points - 1));
        int xB = x0 + static_cast<int>(i * (graphW - 1) / (points - 1));
        int yA = y0 + graphH - 1 - (certaintyHistory[idx0] * (graphH - 1) / 100);
        int yB = y0 + graphH - 1 - (certaintyHistory[idx1] * (graphH - 1) / 100);

        M5.Display.drawLine(xA, yA, xB, yB, alertLevelColor(lastAlertLevel));
    }
}

static void updateTopBarStats() {
    // Volume
    uint8_t volPercent = static_cast<uint8_t>(roundf(audioSystem.getVolumeLevel() * 100.0f));
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.fillRect(40, 2, 60, 16, TFT_BLACK);
    M5.Display.drawString(String(volPercent) + "%", 40, 4);
    
    // RAM utilization
    uint32_t heapSize = ESP.getHeapSize();
    uint32_t freeHeap = ESP.getFreeHeap();
    uint8_t ramPercent = heapSize > 0 ? static_cast<uint8_t>(((heapSize - freeHeap) * 100) / heapSize) : 0;
    M5.Display.fillRect(140, 2, 60, 16, TFT_BLACK);
    M5.Display.drawString(String(ramPercent) + "%", 140, 4);

    // Uptime stopwatch for syncing notes with field logs
    M5.Display.fillRect(204, 2, 42, 16, TFT_BLACK);
    uint32_t nowMs = millis();
    M5.Display.setTextColor(loggingEnabled ? TFT_GREEN : TFT_WHITE, TFT_BLACK);
    M5.Display.drawString(uptimeShortString(activeTimerMs(nowMs)), 204, 4);
    
    // Battery
    int battery = M5.Power.getBatteryLevel();
    bool charging = externalPowerPresent(nowMs);
    int barX = 270;
    int barY = 2;
    int barW = 36;
    int barH = 14;
    M5.Display.drawRect(barX, barY, barW, barH, TFT_WHITE);
    int fillW = (battery * (barW - 2)) / 100;
    M5.Display.fillRect(barX + 1, barY + 1, barW - 2, barH - 2, TFT_BLACK);
    M5.Display.fillRect(barX + 1, barY + 1, fillW, barH - 2, TFT_GREEN);
    M5.Display.fillRect(barX + barW, barY + 4, 3, 6, TFT_WHITE);
    M5.Display.fillRect(310, 2, 10, 16, TFT_BLACK);
    if (charging) {
        M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
        M5.Display.drawString("+", 310, 3);
    }
}

static void updateHomeStats() {
    updateTopBarStats();

    // WiFi channel
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.fillRect(70, infoTextBaseY - 2, 50, 16, TFT_BLACK);
    M5.Display.drawString(String(RadioScannerManager::getCurrentWifiChannel()), 70, infoTextBaseY);
    
    // Bluetooth indicator
    bool btActive = RadioScannerManager::isBluetoothScanning();
    uint16_t btColor = btActive ? TFT_BLUE : TFT_DARKGREY;
    M5.Display.fillCircle(312, scanTextY + 6, 5, btColor);
    
    // Last MAC
    M5.Display.fillRect(70, infoTextBaseY + 16, 120, 16, TFT_BLACK);
    M5.Display.drawString(String(lastMacAddress), 70, infoTextBaseY + 18);
    
    // Alerts count
    M5.Display.fillRect(60, infoTextBaseY + 34, 80, 16, TFT_BLACK);
    M5.Display.drawString(String(alertCount), 60, infoTextBaseY + 36);

    // Threat status strip
    uint16_t levelColor = alertLevelColor(lastAlertLevel);
    M5.Display.fillRect(60, infoTextBaseY + 52, 128, 16, TFT_BLACK);
    M5.Display.setTextColor(levelColor, TFT_BLACK);
    M5.Display.drawString(alertLevelName(lastAlertLevel), 60, infoTextBaseY + 54);
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.drawString(String(lastCertainty) + "%", 96, infoTextBaseY + 54);

    // Proximity and active target count
    M5.Display.fillRect(60, infoTextBaseY + 70, 128, 16, TFT_BLACK);
    const char* rangeName = rangeNameFromRssi(lastRssi);
    M5.Display.setTextColor(strcmp(rangeName, "FAR") == 0 ? rangeColorFromRssi(lastRssi) : TFT_DARKGREY, TFT_BLACK);
    M5.Display.drawString("FAR", 60, infoTextBaseY + 72);
    M5.Display.setTextColor(strcmp(rangeName, "NEAR") == 0 ? rangeColorFromRssi(lastRssi) : TFT_DARKGREY, TFT_BLACK);
    M5.Display.drawString("NEAR", 86, infoTextBaseY + 72);
    M5.Display.setTextColor(strcmp(rangeName, "HOT") == 0 ? rangeColorFromRssi(lastRssi) : TFT_DARKGREY, TFT_BLACK);
    M5.Display.drawString("HOT", 122, infoTextBaseY + 72);
    M5.Display.setTextColor(TFT_DARKGREY, TFT_BLACK);
    M5.Display.drawString(String(lastRssi), 152, infoTextBaseY + 72);

    M5.Display.fillRect(60, infoTextBaseY + 88, 128, 16, TFT_BLACK);
    uint8_t activeCount = activeThreatInRangeCount();
    M5.Display.setTextColor(activeCount > 0 ? TFT_ORANGE : TFT_DARKGREY, TFT_BLACK);
    M5.Display.drawString(String(activeCount), 60, infoTextBaseY + 90);
    M5.Display.setTextColor(TFT_DARKGREY, TFT_BLACK);
    M5.Display.drawString("targets", 80, infoTextBaseY + 90);

    M5.Display.fillRect(34, 142, 162, 22, TFT_BLACK);
    M5.Display.setTextColor(TFT_DARKGREY, TFT_BLACK);
    if (!gpsEnabled) {
        M5.Display.drawString(String(gpsPortName()) + " OFF", 34, 144);
    } else if (gpsHasFix) {
        M5.Display.setTextColor(TFT_GREEN, TFT_BLACK);
        M5.Display.drawString(String(gpsPortName()) + " FIX " + String(gpsSatellites), 34, 144);
        M5.Display.setTextColor(TFT_DARKGREY, TFT_BLACK);
        M5.Display.drawString("HD" + String(gpsHdop, 1), 112, 144);
    } else {
        M5.Display.setTextColor(TFT_ORANGE, TFT_BLACK);
        M5.Display.drawString(String(gpsPortName()) + " NOFIX", 34, 144);
    }

    M5.Display.setTextColor(geoStatusColor(), TFT_BLACK);
    M5.Display.drawString(geoStatusName(), 34, 154);
    M5.Display.setTextColor(TFT_DARKGREY, TFT_BLACK);
    if (nearestGeoDistanceM >= 0.0f) {
        M5.Display.drawString(String((int)nearestGeoDistanceM) + "m " + String(nearestGeoLabel), 78, 154);
    } else {
        M5.Display.drawString(String(lastRadioType) + "/" + String(lastDetectionLabel), 78, 154);
    }
}

static void updateRadarSweep() {
    int radarX0 = radarBoxX + radarLineInsetX;
    int radarY0 = radarBoxY + radarLineInsetY;
    int radarW = radarBoxW - (radarLineInsetX * 2);
    int radarH = radarBoxH - (radarLineInsetY * 2);
    
    M5.Display.fillRect(radarX0, radarY0, radarW, radarH, TFT_BLACK);
    M5.Display.drawRect(radarBoxX, radarBoxY, radarBoxW, radarBoxH, TFT_DARKGREY);
    M5.Display.drawFastVLine(radarX0 + (radarW / 2), radarY0, radarH, themeDimColor());
    M5.Display.drawFastHLine(radarX0, radarY0 + (radarH / 2), radarW, themeDimColor());

    for (size_t i = 0; i < RADAR_BLIP_COUNT; i++) {
        if (radarBlips[i].ttl == 0) continue;
        uint16_t color = alertLevelColor(radarBlips[i].level);
        M5.Display.fillCircle(radarBlips[i].x, radarBlips[i].y, 2, color);
        if (radarBlips[i].ttl > 0) radarBlips[i].ttl--;
    }
}

static void updateGeoMap() {
    int mapX0 = radarBoxX + radarLineInsetX;
    int mapY0 = radarBoxY + radarLineInsetY;
    int mapW = radarBoxW - (radarLineInsetX * 2);
    int mapH = radarBoxH - (radarLineInsetY * 2);
    int cx = mapX0 + mapW / 2;
    int cy = mapY0 + mapH / 2;
    float scaleX = static_cast<float>(mapW - 12) / (GEO_MAP_RANGE_M * 2.0f);
    float scaleY = static_cast<float>(mapH - 12) / (GEO_MAP_RANGE_M * 2.0f);
    float pixelsPerM = scaleX < scaleY ? scaleX : scaleY;

    M5.Display.fillRect(mapX0, mapY0, mapW, mapH, TFT_BLACK);
    M5.Display.drawRect(radarBoxX, radarBoxY, radarBoxW, radarBoxH,
                        geoInsideFence ? TFT_BLUE : TFT_DARKGREY);
    M5.Display.drawFastVLine(cx, mapY0, mapH, themeDimColor());
    M5.Display.drawFastHLine(mapX0, cy, mapW, themeDimColor());

    bool trackUp = gpsHasCourse;
    float headingRad = trackUp ? gpsCourseDeg * DEG_TO_RAD : 0.0f;
    float cosH = cos(headingRad);
    float sinH = sin(headingRad);
    double lonMetersPerDegree = 111320.0 * cos(gpsLat * DEG_TO_RAD);
    size_t nearestSlot = geoMapTargetCount;
    float nearestMapDistance = 99999999.0f;

    for (size_t i = 0; i < geoMapTargetCount; i++) {
        if (geoMapTargets[i].distanceM < nearestMapDistance) {
            nearestMapDistance = geoMapTargets[i].distanceM;
            nearestSlot = i;
        }
    }

    for (size_t i = 0; i < geoMapTargetCount; i++) {
        double northM = (geoMapTargets[i].lat - gpsLat) * 111320.0;
        double eastM = (geoMapTargets[i].lon - gpsLon) * lonMetersPerDegree;
        double forwardM = northM * cosH + eastM * sinH;
        double rightM = eastM * cosH - northM * sinH;
        int x = cx + static_cast<int>(rightM * pixelsPerM);
        int y = cy - static_cast<int>(forwardM * pixelsPerM);
        if (x < mapX0 + 3 || x > mapX0 + mapW - 4 ||
            y < mapY0 + 3 || y > mapY0 + mapH - 4) {
            continue;
        }
        bool inside = geoMapTargets[i].distanceM <= geoMapTargets[i].radiusM;
        uint16_t color = inside ? TFT_BLUE : TFT_SKYBLUE;
        M5.Display.fillCircle(x, y, inside ? 4 : 3, color);
        if (i == nearestSlot) {
            M5.Display.drawCircle(x, y, inside ? 6 : 5, TFT_WHITE);
        }
    }

    M5.Display.fillCircle(cx, cy, 4, TFT_WHITE);
    if (trackUp) {
        M5.Display.fillTriangle(cx, cy - 9, cx - 5, cy + 3, cx + 5, cy + 3, TFT_GREEN);
    } else {
        M5.Display.drawFastVLine(cx, cy - 9, 18, TFT_GREEN);
        M5.Display.drawFastHLine(cx - 9, cy, 18, TFT_GREEN);
    }

    M5.Display.setTextSize(1);
    M5.Display.setTextColor(themeLabelColor(), TFT_BLACK);
    M5.Display.drawString("MAP", mapX0 + 4, mapY0 + 4);
    M5.Display.setTextColor(TFT_DARKGREY, TFT_BLACK);
    M5.Display.drawString(trackUp ? "TRK" : "N", mapX0 + mapW - 24, mapY0 + 4);
    M5.Display.drawString(String(GEO_MAP_RANGE_M / 1000.0f, 1) + "km", mapX0 + 4, mapY0 + mapH - 12);
    if (geoActiveGroupCount > 0) {
        M5.Display.drawString(String(geoActiveGroups[0].label), mapX0 + mapW - 54, mapY0 + mapH - 12);
    }
}

static void updateLowerPanel() {
    if (gpsHasFix && geoMapTargetCount > 0) {
        updateGeoMap();
    } else {
        updateRadarSweep();
    }
}

static void drawMenuFrame() {
    M5.Display.fillRect(20, 40, 280, 160, TFT_BLACK);
    M5.Display.drawRect(20, 40, 280, 160, TFT_DARKGREY);
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
    M5.Display.drawString("Menu", 30, 46);
    
    int visibleCount = menuVisibleCount;
    if ((int)menuItemCount < visibleCount) {
        visibleCount = (int)menuItemCount;
    }
    int scrollOffset = 0;
    if ((int)menuItemCount > visibleCount && menuIndex >= visibleCount) {
        scrollOffset = menuIndex - (visibleCount - 1);
    }
    int maxOffset = (int)menuItemCount - visibleCount;
    if (scrollOffset > maxOffset) scrollOffset = maxOffset;
    
    for (int i = 0; i < visibleCount; i++) {
        int itemIndex = scrollOffset + i;
        int y = 70 + (i * 24);
        if (itemIndex == menuIndex) {
            M5.Display.fillRect(28, y - 2, 264, 18, TFT_DARKGREY);
            M5.Display.setTextColor(TFT_WHITE, TFT_DARKGREY);
        } else {
            M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
        }
        if (itemIndex == 2) {
            String label = String(menuItems[itemIndex]) + ": " + String(themePresets[themeIndex].name);
            M5.Display.drawString(label, 36, y);
        } else if (itemIndex == 3) {
            String label = String(menuItems[itemIndex]) + (nightModeEnabled ? ": On" : ": Off");
            M5.Display.drawString(label, 36, y);
        } else if (itemIndex == 4) {
            String label = String(menuItems[itemIndex]) + (commonChannelHopEnabled ? ": On" : ": Off");
            M5.Display.drawString(label, 36, y);
        } else if (itemIndex == 5) {
            String label = String(menuItems[itemIndex]) + (gpsEnabled ? ": On" : ": Off");
            M5.Display.drawString(label, 36, y);
        } else if (itemIndex == 6) {
            String label = String(menuItems[itemIndex]) + ": " + String(carModeModeName());
            M5.Display.drawString(label, 36, y);
        } else if (itemIndex == 7) {
            String label = String(menuItems[itemIndex]) + (screenSaverEnabled ? ": " + String(screenSaverTimeoutSec) + "s" : ": Off");
            M5.Display.drawString(label, 36, y);
        } else if (itemIndex == 8) {
            String label = String(menuItems[itemIndex]) + (batterySaverEnabled ? ": On" : ": Off");
            M5.Display.drawString(label, 36, y);
        } else if (itemIndex == 9) {
            String label = String(menuItems[itemIndex]) + (loggingEnabled ? ": On" : ": Off");
            M5.Display.drawString(label, 36, y);
        } else {
            M5.Display.drawString(menuItems[itemIndex], 36, y);
        }
    }
}

static void drawGpsMenuFrame() {
    M5.Display.fillRect(20, 40, 280, 160, TFT_BLACK);
    M5.Display.drawRect(20, 40, 280, 160, TFT_DARKGREY);
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
    M5.Display.drawString("GPS Settings", 30, 46);

    for (size_t i = 0; i < gpsMenuItemCount; i++) {
        int y = 70 + (i * 24);
        bool disabled = !gpsEnabled && i > 0 && i < 4;
        bool selected = (int)i == gpsMenuIndex;
        if (selected) {
            M5.Display.fillRect(28, y - 2, 264, 18, disabled ? TFT_BLACK : TFT_DARKGREY);
            M5.Display.setTextColor(disabled ? TFT_DARKGREY : TFT_WHITE, disabled ? TFT_BLACK : TFT_DARKGREY);
        } else {
            M5.Display.setTextColor(disabled ? TFT_DARKGREY : TFT_WHITE, TFT_BLACK);
        }

        String label;
        if (i == 0) {
            label = String(gpsMenuItems[i]) + (gpsEnabled ? ": On" : ": Off");
        } else if (i == 1) {
            label = String(gpsMenuItems[i]) + (geoAlertEnabled ? ": On" : ": Off");
        } else if (i == 2) {
            label = String(gpsMenuItems[i]) + ": " + String(gpsPortName());
        } else if (i == 3) {
            label = String(gpsMenuItems[i]) + ": " + String(geoRadiusMeters) + "m";
        } else {
            label = gpsMenuItems[i];
        }
        M5.Display.drawString(label, 36, y);
    }
}

static void drawDebugMenuFrame() {
    M5.Display.fillRect(20, 40, 280, 160, TFT_BLACK);
    M5.Display.drawRect(20, 40, 280, 160, TFT_DARKGREY);
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
    M5.Display.drawString("Debug Settings", 30, 46);

    for (size_t i = 0; i < debugMenuItemCount; i++) {
        int y = 70 + (i * 24);
        if ((int)i == debugMenuIndex) {
            M5.Display.fillRect(28, y - 2, 264, 18, TFT_DARKGREY);
            M5.Display.setTextColor(TFT_WHITE, TFT_DARKGREY);
        } else {
            M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
        }
        M5.Display.drawString(debugMenuItems[i], 36, y);
    }
}

static void drawAdjustGeoRadius() {
    M5.Display.fillRect(20, 40, 280, 160, TFT_BLACK);
    M5.Display.drawRect(20, 40, 280, 160, TFT_DARKGREY);
    M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
    M5.Display.drawString("Geo Radius", 30, 46);
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.drawString("Use left/right to adjust", 30, 70);
    M5.Display.drawString("Center to return", 30, 88);

    M5.Display.setTextSize(2);
    M5.Display.setTextColor(TFT_ORANGE, TFT_BLACK);
    M5.Display.drawString(String(geoRadiusMeters) + "m", 88, 118);
    M5.Display.setTextSize(1);
}

static void drawAdjustTheme() {
    M5.Display.fillRect(20, 40, 280, 160, TFT_BLACK);
    M5.Display.drawRect(20, 40, 280, 160, TFT_DARKGREY);
    M5.Display.setTextColor(themeLabelColor(), TFT_BLACK);
    M5.Display.drawString("Theme", 30, 46);
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.drawString("Use left/right to adjust", 30, 70);
    M5.Display.drawString("Center to return", 30, 88);
    M5.Display.fillRect(30, 120, 240, 30, accentColor);
    M5.Display.setTextColor(TFT_BLACK, accentColor);
    M5.Display.drawString(themePresets[themeIndex].name, 36, 126);
}

static void drawAdjustScreenSaver() {
    M5.Display.fillRect(20, 40, 280, 160, TFT_BLACK);
    M5.Display.drawRect(20, 40, 280, 160, TFT_DARKGREY);
    M5.Display.setTextColor(themeLabelColor(), TFT_BLACK);
    M5.Display.drawString("Screen Saver", 30, 46);
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.drawString("Use left/right to adjust", 30, 70);
    M5.Display.drawString("Center to return", 30, 88);
    M5.Display.setTextSize(2);
    M5.Display.setTextColor(accentColor, TFT_BLACK);
    if (screenSaverEnabled) {
        M5.Display.drawString(String(screenSaverTimeoutSec) + "s", 112, 118);
    } else {
        M5.Display.drawString("Off", 112, 118);
    }
    M5.Display.setTextSize(1);
}

static void drawResetMenuFrame() {
    M5.Display.fillRect(20, 40, 280, 160, TFT_BLACK);
    M5.Display.drawRect(20, 40, 280, 160, TFT_DARKGREY);
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
    M5.Display.drawString("Reset", 30, 46);
    
    for (size_t i = 0; i < resetMenuItemCount; i++) {
        int y = 70 + (i * 24);
        if ((int)i == resetMenuIndex) {
            M5.Display.fillRect(28, y - 2, 264, 18, TFT_DARKGREY);
            M5.Display.setTextColor(TFT_WHITE, TFT_DARKGREY);
        } else {
            M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
        }
        M5.Display.drawString(resetMenuItems[i], 36, y);
    }
}

static void showInfoPopup(const char* text) {
    infoPopupActive = true;
    infoPopupStart = millis();
    infoPopupText = text;
    
    const int boxW = 200;
    const int boxH = 60;
    const int boxX = (320 - boxW) / 2;
    const int boxY = (240 - boxH) / 2;
    
    M5.Display.fillRect(boxX, boxY, boxW, boxH, TFT_BLACK);
    M5.Display.drawRect(boxX, boxY, boxW, boxH, TFT_DARKGREY);
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    int textW = M5.Display.textWidth(text);
    int textH = M5.Display.fontHeight();
    int textX = boxX + (boxW - textW) / 2;
    int textY = boxY + (boxH - textH) / 2;
    M5.Display.setCursor(textX, textY);
    M5.Display.print(text);
}

static void runScreenTest() {
    const uint16_t colors[] = {TFT_RED, TFT_GREEN, TFT_BLUE, TFT_WHITE, TFT_BLACK};
    for (size_t i = 0; i < sizeof(colors) / sizeof(colors[0]); i++) {
        M5.Display.fillScreen(colors[i]);
        M5.update();
        delay(450);
    }
}

static void drawAdjustBacklight() {
    M5.Display.fillRect(20, 40, 280, 160, TFT_BLACK);
    M5.Display.drawRect(20, 40, 280, 160, TFT_DARKGREY);
    M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
    M5.Display.drawString("Backlight", 30, 46);
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.drawString("Use left/right to adjust", 30, 70);
    M5.Display.drawString("Center to save", 30, 88);
    
    int barX = 30;
    int barY = 120;
    int barW = 240;
    int barH = 14;
    M5.Display.drawRect(barX, barY, barW, barH, TFT_DARKGREY);
    int fillW = (displayBrightness * (barW - 2)) / 255;
    M5.Display.fillRect(barX + 1, barY + 1, fillW, barH - 2, TFT_CYAN);
}

static void drawAdjustAccent() {
    M5.Display.fillRect(20, 40, 280, 160, TFT_BLACK);
    M5.Display.drawRect(20, 40, 280, 160, TFT_DARKGREY);
    M5.Display.setTextColor(TFT_CYAN, TFT_BLACK);
    M5.Display.drawString("Accent Color", 30, 46);
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.drawString("Use left/right to adjust", 30, 70);
    M5.Display.drawString("Center to save", 30, 88);
    
    M5.Display.drawRect(30, 120, 240, 30, TFT_DARKGREY);
    M5.Display.fillRect(32, 122, 236, 26, accentOptions[accentIndex].color);
    M5.Display.setTextColor(TFT_BLACK, accentOptions[accentIndex].color);
    M5.Display.drawString(accentOptions[accentIndex].name, 36, 126);
}

static void resetHomeUi() {
    homeScreenActive = true;
    drawHomeFrame();
    updateHomeStats();
    updateRssiGraph();
    updateCertaintyGraph();
    updateScanningBanner();
    lastUiUpdate = millis();
    lastRadarUpdate = millis();
    lastScanBannerUpdate = millis();
}

static void applyDefaultSettings() {
    audioSystem.setVolume(SoundEngine::DEFAULT_VOLUME);
    displayBrightness = 160;
    accentIndex = 0;
    accentColor = accentOptions[accentIndex].color;
    batterySaverEnabled = false;
    commonChannelHopEnabled = true;
    gpsEnabled = true;
    geoAlertEnabled = true;
    loggingEnabled = false;
    loggingTimerStartMs = 0;
    geoRadiusMeters = 300;
    gpsPortMode = 1;
    carModeMode = CAR_MODE_OFF;
    carModePromptActive = false;
    carModeSawExternalPower = false;
    carModeExternalPowerSinceMs = 0;
    nightModeEnabled = false;
    screenSaverEnabled = true;
    screenSaverTimeoutSec = 60;
    themeIndex = 0;
    alertCount = 0;
}

static void setDisplayPower(bool on) {
    if (on) {
        if (displayIsOff) {
            M5.Display.wakeup();
            displayIsOff = false;
        }
        M5.Display.setBrightness(displayBrightness);
    } else {
        M5.Display.setBrightness(0);
        M5.Display.sleep();
        displayIsOff = true;
    }
}

static bool saveSettingsToSd() {
    DynamicJsonDocument doc(1024);
    doc["volume"] = audioSystem.getVolumeLevel();
    doc["brightness"] = displayBrightness;
    doc["accent_index"] = static_cast<int>(accentIndex);
    doc["battery_saver"] = batterySaverEnabled;
    doc["common_channel_hop"] = commonChannelHopEnabled;
    doc["gps_enabled"] = gpsEnabled;
    doc["gps_port"] = gpsPortMode;
    doc["geo_alert"] = geoAlertEnabled;
    doc["logging_enabled"] = loggingEnabled;
    doc["geo_radius_m"] = geoRadiusMeters;
    doc["car_mode"] = isCarModeEnabled();
    doc["car_mode_mode"] = static_cast<int>(carModeMode);
    doc["night_mode"] = nightModeEnabled;
    doc["screen_saver"] = screenSaverEnabled;
    doc["screen_saver_sec"] = screenSaverTimeoutSec;
    doc["theme"] = static_cast<int>(themeIndex);
    doc["alert_count"] = alertCount;
    
    if (SD.exists(configPath)) {
        SD.remove(configPath);
    }
    File file = SD.open(configPath, FILE_WRITE);
    if (!file) {
        Serial.println("[Config] Failed to open config for write");
        return false;
    }
    serializeJson(doc, file);
    file.close();
    return true;
}

static bool loadSettingsFromSd() {
    if (!SD.exists(configPath)) {
        applyDefaultSettings();
        return saveSettingsToSd();
    }
    
    File file = SD.open(configPath, FILE_READ);
    if (!file) {
        Serial.println("[Config] Failed to open config for read");
        return false;
    }
    
    DynamicJsonDocument doc(1024);
    DeserializationError err = deserializeJson(doc, file);
    file.close();
    if (err) {
        Serial.println("[Config] Failed to parse config, using defaults");
        applyDefaultSettings();
        return saveSettingsToSd();
    }
    
    float volume = doc["volume"] | SoundEngine::DEFAULT_VOLUME;
    audioSystem.setVolume(volume);
    displayBrightness = doc["brightness"] | displayBrightness;
    
    int idx = doc["accent_index"] | 0;
    if (idx < 0 || idx >= (int)accentOptionCount) idx = 0;
    accentIndex = idx;
    accentColor = accentOptions[accentIndex].color;
    
    batterySaverEnabled = doc["battery_saver"] | false;
    commonChannelHopEnabled = doc["common_channel_hop"] | true;
    gpsEnabled = doc["gps_enabled"] | true;
    gpsPortMode = doc["gps_port"] | 1;
    if (gpsPortMode > 1) gpsPortMode = 1;
    geoAlertEnabled = doc["geo_alert"] | true;
    loggingEnabled = doc["logging_enabled"] | false;
    if (loggingEnabled) {
        if (loggingTimerStartMs == 0) {
            loggingTimerStartMs = millis();
        }
    } else {
        loggingTimerStartMs = 0;
    }
    geoRadiusMeters = doc["geo_radius_m"] | 300;
    if (geoRadiusMeters < 25) geoRadiusMeters = 25;
    if (geoRadiusMeters > 5000) geoRadiusMeters = 5000;
    if (doc.containsKey("car_mode_mode")) {
        int mode = doc["car_mode_mode"] | 0;
        if (mode < CAR_MODE_OFF || mode > CAR_MODE_AUTO) mode = CAR_MODE_OFF;
        carModeMode = static_cast<CarModeMode>(mode);
    } else {
        carModeMode = (doc["car_mode"] | false) ? CAR_MODE_ON : CAR_MODE_OFF;
    }
    carModePromptActive = false;
    carModeSawExternalPower = false;
    if (isCarModeEnabled()) {
        batterySaverEnabled = false;
    }
    nightModeEnabled = doc["night_mode"] | false;
    screenSaverEnabled = doc["screen_saver"] | true;
    screenSaverTimeoutSec = doc["screen_saver_sec"] | 60;
    if (screenSaverTimeoutSec < 30) screenSaverTimeoutSec = 30;
    if (screenSaverTimeoutSec > 180) screenSaverTimeoutSec = 180;
    int theme = doc["theme"] | 0;
    if (theme < 0 || theme >= (int)themePresetCount) theme = 0;
    themeIndex = theme;
    applyThemePreset();
    alertCount = doc["alert_count"] | 0u;
    return true;
}

static void triggerAlert(bool incrementCount, uint8_t certainty) {
    if (incrementCount) {
        alertCount++;
    }
    alertActive = true;
    alertPopupGeo = false;
    alertStart = millis();
    lastAlertDraw = 0;
    if (batterySaverEnabled) {
        setDisplayPower(true);
    }
    audioSystem.playSoundAsyncAtConfidence("alert", certainty);
}

static void triggerGeoAlert(bool incrementCount) {
    if (incrementCount) {
        alertCount++;
    }
    alertActive = true;
    alertPopupGeo = true;
    alertStart = millis();
    lastAlertDraw = 0;
    if (batterySaverEnabled) {
        setDisplayPower(true);
    }
    audioSystem.playSoundAsyncAtConfidence("geo", 100);
}

static void drawAlertPopup() {
    const int boxX = 20;
    const int boxY = 40;
    const int boxW = 280;
    const int boxH = 160;

    uint16_t bg = alertPopupGeo ? TFT_BLUE : TFT_RED;
    uint16_t fg = alertPopupGeo ? TFT_WHITE : TFT_BLACK;
    uint16_t border = alertPopupGeo ? TFT_CYAN : TFT_WHITE;
    if (nightModeEnabled) {
        bg = alertPopupGeo ? TFT_NAVY : TFT_BLACK;
        fg = alertPopupGeo ? TFT_CYAN : TFT_ORANGE;
        border = fg;
    }

    M5.Display.fillRect(boxX, boxY, boxW, boxH, bg);
    M5.Display.drawRect(boxX, boxY, boxW, boxH, border);
    M5.Display.drawRect(boxX + 2, boxY + 2, boxW - 4, boxH - 4,
                        alertPopupGeo ? TFT_SKYBLUE : TFT_DARKGREY);
    M5.Display.setTextColor(fg, bg);
    M5.Display.setTextSize(nightModeEnabled ? 2 : 3);
    const char* alertText = alertPopupGeo ? "GEO ALERT" : (nightModeEnabled ? "RF ALERT" : "ALERT");
    int textW = M5.Display.textWidth(alertText);
    int textH = M5.Display.fontHeight();
    int textX = boxX + (boxW - textW) / 2;
    int textY = alertPopupGeo ? boxY + 56 : boxY + (boxH - textH) / 2;
    M5.Display.setCursor(textX, textY);
    M5.Display.print(alertText);
    if (alertPopupGeo) {
        M5.Display.setTextSize(1);
        M5.Display.setTextColor(TFT_WHITE, bg);
        String geoLine = nearestGeoDistanceM >= 0.0f
            ? String((int)nearestGeoDistanceM) + "m " + String(nearestGeoLabel)
            : String("Geo test / no fix");
        int lineW = M5.Display.textWidth(geoLine);
        int lineX = boxX + (boxW - lineW) / 2;
        if (lineX < boxX + 8) lineX = boxX + 8;
        M5.Display.drawString(geoLine, lineX, boxY + 104);
    }
    M5.Display.setTextSize(1);
}

static void restoreScreenAfterAlert() {
    if (batterySaverEnabled) {
        setDisplayPower(false);
        return;
    }
    if (menuMode == MenuMode::Main) {
        drawMenuFrame();
    } else if (menuMode == MenuMode::GPSSettings) {
        drawGpsMenuFrame();
    } else if (menuMode == MenuMode::DebugSettings) {
        drawDebugMenuFrame();
    } else if (menuMode == MenuMode::ResetMenu) {
        drawResetMenuFrame();
    } else if (menuMode == MenuMode::AdjustBacklight) {
        drawAdjustBacklight();
    } else if (menuMode == MenuMode::AdjustAccent) {
        drawAdjustAccent();
    } else if (menuMode == MenuMode::AdjustGeoRadius) {
        drawAdjustGeoRadius();
    } else if (menuMode == MenuMode::AdjustTheme) {
        drawAdjustTheme();
    } else if (menuMode == MenuMode::AdjustScreenSaver) {
        drawAdjustScreenSaver();
    } else {
        resetHomeUi();
    }
}

static void handleAlertPopup() {
    if (!alertActive) return;
    
    unsigned long now = millis();
    if (now - alertStart >= ALERT_POPUP_MS) {
        alertActive = false;
        alertPopupGeo = false;
        restoreScreenAfterAlert();
        return;
    }
    
    if (lastAlertDraw == 0) {
        lastAlertDraw = now;
        drawAlertPopup();
    }
}

static void handleInfoPopup() {
    if (!infoPopupActive) return;
    if (millis() - infoPopupStart >= 3000) {
        infoPopupActive = false;
        if (menuMode == MenuMode::Main) {
            drawMenuFrame();
        } else if (menuMode == MenuMode::GPSSettings) {
            drawGpsMenuFrame();
        } else if (menuMode == MenuMode::DebugSettings) {
            drawDebugMenuFrame();
        } else if (menuMode == MenuMode::ResetMenu) {
            drawResetMenuFrame();
        }
    }
}

static void handleMenuButtons() {
    if (carModePromptActive) return;
    if (menuJustOpened) {
        if (!M5.BtnB.isPressed()) {
            menuJustOpened = false;
        }
        return;
    }
    if (infoPopupActive) {
        return;
    }
    
    if (menuMode == MenuMode::Main) {
        if (M5.BtnA.wasPressed()) {
            menuIndex = (menuIndex - 1 + (int)menuItemCount) % (int)menuItemCount;
            drawMenuFrame();
            } else if (M5.BtnC.wasPressed()) {
            menuIndex = (menuIndex + 1) % (int)menuItemCount;
            drawMenuFrame();
        } else if (M5.BtnB.wasPressed()) {
            if (menuIndex == 0) {
                menuMode = MenuMode::AdjustBacklight;
                drawAdjustBacklight();
            } else if (menuIndex == 1) {
                menuMode = MenuMode::AdjustAccent;
                drawAdjustAccent();
            } else if (menuIndex == 2) {
                menuMode = MenuMode::AdjustTheme;
                drawAdjustTheme();
            } else if (menuIndex == 3) {
                nightModeEnabled = !nightModeEnabled;
                if (nightModeEnabled && displayBrightness > 80) {
                    displayBrightness = 80;
                    M5.Display.setBrightness(displayBrightness);
                }
                resetHomeUi();
                menuMode = MenuMode::Main;
                drawMenuFrame();
            } else if (menuIndex == 4) {
                commonChannelHopEnabled = !commonChannelHopEnabled;
                RadioScannerManager::setCommonChannelMode(commonChannelHopEnabled);
                drawMenuFrame();
            } else if (menuIndex == 5) {
                menuMode = MenuMode::GPSSettings;
                gpsMenuIndex = 0;
                drawGpsMenuFrame();
            } else if (menuIndex == 6) {
                carModeMode = static_cast<CarModeMode>((static_cast<uint8_t>(carModeMode) + 1) % 3);
                carModePromptActive = false;
                bool onExternalPower = externalPowerPresent(millis(), true);
                carModeSawExternalPower = onExternalPower;
                carModeExternalPowerSinceMs = onExternalPower ? millis() : 0;
                if (isCarModeEnabled()) {
                    batterySaverEnabled = false;
                    screenSaverActive = false;
                    setDisplayPower(true);
                    bool highPerformance =
                        onExternalPower || (carModeMode == CAR_MODE_ON && !carModeSawExternalPower);
                    RadioScannerManager::setPerformanceMode(highPerformance);
                } else {
                    RadioScannerManager::setPerformanceMode(onExternalPower);
                }
                drawMenuFrame();
            } else if (menuIndex == 7) {
                menuMode = MenuMode::AdjustScreenSaver;
                drawAdjustScreenSaver();
            } else if (menuIndex == 8) {
                if (carModeBlocksPowerSaving()) {
                    batterySaverEnabled = false;
                    showInfoPopup("Car Mode active");
                    return;
                }
                batterySaverEnabled = !batterySaverEnabled;
                menuMode = MenuMode::None;
                if (batterySaverEnabled) {
                    setDisplayPower(false);
                } else {
                    setDisplayPower(true);
                    resetHomeUi();
                }
            } else if (menuIndex == 9) {
                setLoggingEnabled(!loggingEnabled);
                drawMenuFrame();
            } else if (menuIndex == 10) {
                menuMode = MenuMode::DebugSettings;
                debugMenuIndex = 0;
                drawDebugMenuFrame();
            } else if (menuIndex == 11) {
                bool ok = saveSettingsToSd();
                if (ok) {
                    ok = loadSettingsFromSd();
                }
                restartGpsSerial();
                showInfoPopup(ok ? "Settings saved" : "Save failed");
            } else if (menuIndex == 12) {
                menuMode = MenuMode::ResetMenu;
                resetMenuIndex = 0;
                drawResetMenuFrame();
            } else if (menuIndex == 13) {
                menuMode = MenuMode::None;
                resetHomeUi();
            }
        }
    } else if (menuMode == MenuMode::GPSSettings) {
        if (M5.BtnA.wasPressed()) {
            gpsMenuIndex = (gpsMenuIndex - 1 + (int)gpsMenuItemCount) % (int)gpsMenuItemCount;
            drawGpsMenuFrame();
        } else if (M5.BtnC.wasPressed()) {
            gpsMenuIndex = (gpsMenuIndex + 1) % (int)gpsMenuItemCount;
            drawGpsMenuFrame();
        } else if (M5.BtnB.wasPressed()) {
            if (!gpsEnabled && gpsMenuIndex > 0 && gpsMenuIndex < 4) {
                showInfoPopup("GPS Off");
                return;
            }

            if (gpsMenuIndex == 0) {
                gpsEnabled = !gpsEnabled;
                if (!gpsEnabled) {
                    gpsHasFix = false;
                    gpsHasCourse = false;
                    geoInsideFence = false;
                    geoNearFence = false;
                    geoAlertLatched = false;
                    nearestGeoDistanceM = -1.0f;
                    strncpy(nearestGeoLabel, "--", sizeof(nearestGeoLabel) - 1);
                    nearestGeoLabel[sizeof(nearestGeoLabel) - 1] = '\0';
                    clearGeoMapTargets();
                }
                restartGpsSerial();
                drawGpsMenuFrame();
            } else if (gpsMenuIndex == 1) {
                geoAlertEnabled = !geoAlertEnabled;
                if (!geoAlertEnabled) {
                    geoInsideFence = false;
                    geoNearFence = false;
                    geoAlertLatched = false;
                }
                drawGpsMenuFrame();
            } else if (gpsMenuIndex == 2) {
                gpsPortMode = gpsPortMode == 0 ? 1 : 0;
                restartGpsSerial();
                drawGpsMenuFrame();
            } else if (gpsMenuIndex == 3) {
                menuMode = MenuMode::AdjustGeoRadius;
                drawAdjustGeoRadius();
            } else if (gpsMenuIndex == 4) {
                menuMode = MenuMode::Main;
                drawMenuFrame();
            }
        }
    } else if (menuMode == MenuMode::DebugSettings) {
        if (M5.BtnA.wasPressed()) {
            debugMenuIndex = (debugMenuIndex - 1 + (int)debugMenuItemCount) % (int)debugMenuItemCount;
            drawDebugMenuFrame();
        } else if (M5.BtnC.wasPressed()) {
            debugMenuIndex = (debugMenuIndex + 1) % (int)debugMenuItemCount;
            drawDebugMenuFrame();
        } else if (M5.BtnB.wasPressed()) {
            if (debugMenuIndex == 0) {
                menuMode = MenuMode::None;
                resetHomeUi();
                triggerAlert(true);
            } else if (debugMenuIndex == 1) {
                menuMode = MenuMode::None;
                resetHomeUi();
                triggerGeoAlert(true);
            } else if (debugMenuIndex == 2) {
                menuMode = MenuMode::None;
                runScreenTest();
                resetHomeUi();
            } else if (debugMenuIndex == 3) {
                audioSystem.playSound("startup");
                drawDebugMenuFrame();
            } else if (debugMenuIndex == 4) {
                menuMode = MenuMode::Main;
                drawMenuFrame();
            }
        }
    } else if (menuMode == MenuMode::AdjustBacklight) {
        if (M5.BtnA.wasPressed()) {
            displayBrightness = (displayBrightness > 5) ? displayBrightness - 5 : 0;
            M5.Display.setBrightness(displayBrightness);
            drawAdjustBacklight();
        } else if (M5.BtnC.wasPressed()) {
            displayBrightness = (displayBrightness < 250) ? displayBrightness + 5 : 255;
            M5.Display.setBrightness(displayBrightness);
            drawAdjustBacklight();
        } else if (M5.BtnB.wasPressed()) {
            menuMode = MenuMode::Main;
            drawMenuFrame();
        }
    } else if (menuMode == MenuMode::AdjustAccent) {
        if (M5.BtnA.wasPressed()) {
            accentIndex = (accentIndex + accentOptionCount - 1) % accentOptionCount;
            themeIndex = 0;
            accentColor = accentOptions[accentIndex].color;
            drawAdjustAccent();
        } else if (M5.BtnC.wasPressed()) {
            accentIndex = (accentIndex + 1) % accentOptionCount;
            themeIndex = 0;
            accentColor = accentOptions[accentIndex].color;
            drawAdjustAccent();
        } else if (M5.BtnB.wasPressed()) {
            menuMode = MenuMode::Main;
            drawMenuFrame();
        }
    } else if (menuMode == MenuMode::AdjustTheme) {
        if (M5.BtnA.wasPressed()) {
            themeIndex = (themeIndex + themePresetCount - 1) % themePresetCount;
            applyThemePreset();
            drawAdjustTheme();
        } else if (M5.BtnC.wasPressed()) {
            themeIndex = (themeIndex + 1) % themePresetCount;
            applyThemePreset();
            drawAdjustTheme();
        } else if (M5.BtnB.wasPressed()) {
            menuMode = MenuMode::Main;
            drawMenuFrame();
        }
    } else if (menuMode == MenuMode::AdjustGeoRadius) {
        if (M5.BtnA.wasPressed()) {
            geoRadiusMeters = (geoRadiusMeters > 50) ? geoRadiusMeters - 25 : 25;
            drawAdjustGeoRadius();
        } else if (M5.BtnC.wasPressed()) {
            geoRadiusMeters = (geoRadiusMeters < 4975) ? geoRadiusMeters + 25 : 5000;
            drawAdjustGeoRadius();
        } else if (M5.BtnB.wasPressed()) {
            menuMode = MenuMode::GPSSettings;
            drawGpsMenuFrame();
        }
    } else if (menuMode == MenuMode::AdjustScreenSaver) {
        if (M5.BtnA.wasPressed()) {
            if (!screenSaverEnabled) {
                screenSaverEnabled = true;
                screenSaverTimeoutSec = 120;
            } else if (screenSaverTimeoutSec <= 30) {
                screenSaverEnabled = false;
            } else {
                screenSaverTimeoutSec -= 30;
            }
            drawAdjustScreenSaver();
        } else if (M5.BtnC.wasPressed()) {
            if (!screenSaverEnabled) {
                screenSaverEnabled = true;
                screenSaverTimeoutSec = 30;
            } else if (screenSaverTimeoutSec < 180) {
                screenSaverTimeoutSec += 30;
            }
            drawAdjustScreenSaver();
        } else if (M5.BtnB.wasPressed()) {
            menuMode = MenuMode::Main;
            drawMenuFrame();
        }
    } else if (menuMode == MenuMode::ResetMenu) {
        if (M5.BtnA.wasPressed()) {
            resetMenuIndex = (resetMenuIndex - 1 + (int)resetMenuItemCount) % (int)resetMenuItemCount;
            drawResetMenuFrame();
        } else if (M5.BtnC.wasPressed()) {
            resetMenuIndex = (resetMenuIndex + 1) % (int)resetMenuItemCount;
            drawResetMenuFrame();
        } else if (M5.BtnB.wasPressed()) {
            if (resetMenuIndex == 0) {
                alertCount = 0;
                bool ok = saveSettingsToSd();
                showInfoPopup(ok ? "Alerts reset" : "Save failed");
            } else if (resetMenuIndex == 1) {
                applyDefaultSettings();
                saveSettingsToSd();
                restartGpsSerial();
                setDisplayPower(true);
                menuMode = MenuMode::None;
                resetHomeUi();
            } else if (resetMenuIndex == 2) {
                menuMode = MenuMode::Main;
                drawMenuFrame();
            }
        }
    }
}

static void handleVolumeButtons() {
    if (carModePromptActive) return;
    if (menuMode != MenuMode::None) return;
    
    float vol = audioSystem.getVolumeLevel();
    if (M5.BtnA.wasPressed()) {
        vol -= 0.05f;
        if (vol < 0.0f) vol = 0.0f;
        audioSystem.setVolume(vol);
    } else if (M5.BtnC.wasPressed()) {
        vol += 0.05f;
        if (vol > 1.0f) vol = 1.0f;
        audioSystem.setVolume(vol);
    } else if (M5.BtnB.wasPressed()) {
        menuMode = MenuMode::Main;
        drawMenuFrame();
        menuJustOpened = true;
    }
}

static void handleHomeScreen() {
    if (!homeScreenActive && homeScreenPending && (millis() - homeReadyTimestamp >= 4000)) {
        homeScreenActive = true;
        homeScreenPending = false;
        drawHomeFrame();
        lastUiUpdate = 0;
        lastRadarUpdate = 0;
    }
    
    if (!homeScreenActive) return;
    if (carModePromptActive) return;
    if (screenSaverActive) return;
    if (batterySaverEnabled && !carModeBlocksPowerSaving()) {
        setDisplayPower(false);
        return;
    }
    if (alertActive) return;

    unsigned long now = millis();
    if (menuMode != MenuMode::None) {
        if (now - lastUiUpdate >= 500) {
            updateTopBarStats();
            lastUiUpdate = now;
        }
        return;
    }

    if (now - lastUiUpdate >= 500) {
        updateHomeStats();
        updateRssiGraph();
        updateCertaintyGraph();
        lastUiUpdate = now;
    }
    
    if (now - lastScanBannerUpdate >= 1000) {
        updateScanningBanner();
        lastScanBannerUpdate = now;
    }
    
    if (now - lastRadarUpdate >= 500) {
        updateLowerPanel();
        lastRadarUpdate = now;
    }
}
#endif

void loop() {
    M5.update();
    if (M5.BtnA.wasPressed() || M5.BtnB.wasPressed() || M5.BtnC.wasPressed()) {
        markUserInput();
    }
    rfScanner.update();
    audioSystem.update();
    updateGpsGeo();
    updateAccentAnimation();
    uint32_t now = millis();

    // Check external power periodically and adjust scan/display modes
    static bool lastOnExternalPower = false;
    static uint32_t lastPowerCheckMs = 0;
    if (now - lastPowerCheckMs >= 1000) {
        bool onExternalPower = externalPowerPresent(now, true);
        if (onExternalPower != lastOnExternalPower) {
            bool highPerformance = onExternalPower || (carModeMode == CAR_MODE_ON && !carModeSawExternalPower);
            RadioScannerManager::setPerformanceMode(highPerformance);
            if (onExternalPower && (batterySaverEnabled || isCarModeEnabled())) {
                batterySaverEnabled = false;
                setDisplayPower(true);
                resetHomeUi();
            }
            lastOnExternalPower = onExternalPower;
            logFieldEvent(onExternalPower ? "power_usb_on" : "power_usb_off");
        }
        lastPowerCheckMs = now;
    }
#if ENABLE_HOME_UI
    handleCarModePower(now);
#endif

    WiFiFrameEvent frameCopy;
    uint8_t wifiProcessed = 0;
    while (wifiProcessed < WIFI_EVENTS_PER_LOOP &&
           dequeueWiFiFrame(&frameCopy)) {
        wifiFramesSeen++;
        logWifiSighting(frameCopy);
        snprintf(lastMacAddress, sizeof(lastMacAddress),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 frameCopy.mac[0], frameCopy.mac[1], frameCopy.mac[2],
                 frameCopy.mac[3], frameCopy.mac[4], frameCopy.mac[5]);
        lastRssi = frameCopy.rssi;
        rssiHistory[rssiIndex] = lastRssi;
        rssiIndex = (rssiIndex + 1) % RSSI_GRAPH_POINTS;
        if (rssiIndex == 0) rssiFilled = true;
        threatEngine.analyzeWiFiFrame(frameCopy);
        wifiProcessed++;
    }

    BluetoothDeviceEvent bleCopy;
    uint8_t bleProcessed = 0;
    while (bleProcessed < BLE_EVENTS_PER_LOOP &&
           dequeueBleDevice(&bleCopy)) {
        bleDevicesSeen++;
        logBleSighting(bleCopy);
        lastRssi = bleCopy.rssi;
        rssiHistory[rssiIndex] = lastRssi;
        rssiIndex = (rssiIndex + 1) % RSSI_GRAPH_POINTS;
        if (rssiIndex == 0) rssiFilled = true;
        threatEngine.analyzeBluetoothDevice(bleCopy);
        bleProcessed++;
    }

    if (threatEngine.tick(now)) {
        audioSystem.playConfidenceBeep(lastCertainty, lastAlertLevel);
    }

    ThreatEvent threatCopy;
    uint8_t threatsProcessed = 0;
    while (threatsProcessed < THREAT_EVENTS_PER_LOOP &&
           dequeueThreat(&threatCopy)) {
        threatEventsSeen++;
        reporter.handleThreatDetection(threatCopy);
        logFieldEvent("threat", &threatCopy);
        lastThreatSeenMs = now;
        lastAlertLevel = threatCopy.alertLevel;
        lastCertainty = threatCopy.certainty;
        certaintyHistory[certaintyIndex] = lastCertainty;
        certaintyIndex = (certaintyIndex + 1) % CERTAINTY_GRAPH_POINTS;
        if (certaintyIndex == 0) certaintyFilled = true;
        recordActiveThreat(threatCopy);
        strncpy(lastRadioType, threatCopy.radioType, sizeof(lastRadioType) - 1);
        lastRadioType[sizeof(lastRadioType) - 1] = '\0';
        if (threatCopy.matchFlags & DET_FIELD_WATCH_MAC) {
            strncpy(lastDetectionLabel, "field watch", sizeof(lastDetectionLabel) - 1);
        } else if (threatCopy.matchFlags & DET_WIFI_WILDCARD) {
            strncpy(lastDetectionLabel, "wildcard probe", sizeof(lastDetectionLabel) - 1);
        } else if (threatCopy.matchFlags & DET_WIFI_RECEIVER_OUI) {
            strncpy(lastDetectionLabel, "receiver oui", sizeof(lastDetectionLabel) - 1);
        } else if (threatCopy.matchFlags & DET_BLE_MANUFACTURER) {
            strncpy(lastDetectionLabel, "ble mfg id", sizeof(lastDetectionLabel) - 1);
        } else if (threatCopy.matchFlags & DET_RAVEN_CUSTOM_UUID) {
            strncpy(lastDetectionLabel, "raven uuid", sizeof(lastDetectionLabel) - 1);
        } else if (threatCopy.matchFlags & DET_FLOCK_OUI) {
            strncpy(lastDetectionLabel, "flock oui", sizeof(lastDetectionLabel) - 1);
        } else if (threatCopy.matchFlags & DET_SSID_FORMAT) {
            strncpy(lastDetectionLabel, "ssid format", sizeof(lastDetectionLabel) - 1);
        } else if (threatCopy.matchFlags & DET_SSID_KEYWORD) {
            strncpy(lastDetectionLabel, "ssid keyword", sizeof(lastDetectionLabel) - 1);
        } else if (threatCopy.matchFlags & DET_MAC_OUI) {
            strncpy(lastDetectionLabel, "mac oui", sizeof(lastDetectionLabel) - 1);
        } else if (threatCopy.matchFlags & DET_SURVEILLANCE_OUI) {
            strncpy(lastDetectionLabel, "camera oui", sizeof(lastDetectionLabel) - 1);
        } else {
            strncpy(lastDetectionLabel, "matched", sizeof(lastDetectionLabel) - 1);
        }
        lastDetectionLabel[sizeof(lastDetectionLabel) - 1] = '\0';
        addRadarBlip(threatCopy);
        if (threatCopy.shouldAlert) {
            if (shouldEmitAlertForMac(threatCopy.mac, now)) {
                triggerAlert(true, threatCopy.certainty);
                logFieldEvent("alert", &threatCopy);
            } else {
                logFieldEvent("alert_suppressed", &threatCopy);
            }
        } else if (threatCopy.alertLevel == ALERT_SUSPICIOUS && threatCopy.firstDetection) {
            audioSystem.playConfidenceBeep(threatCopy.certainty,
                                           threatCopy.alertLevel);
        }
        threatsProcessed++;
    }

#if ENABLE_HOME_UI
    if (lastThreatSeenMs != 0 &&
        now - lastThreatSeenMs > ACTIVE_THREAT_TIMEOUT_MS &&
        activeThreatInRangeCount() == 0 &&
        lastAlertLevel != ALERT_NONE) {
        clearDisplayedThreat("clear");
    }

    if (now - lastFieldStatusLogMs >= FIELD_LOG_STATUS_INTERVAL_MS) {
        logFieldEvent("status");
        lastFieldStatusLogMs = now;
    }

    if (!carModePromptActive && batterySaverEnabled &&
        (M5.BtnA.wasPressed() || M5.BtnB.wasPressed() || M5.BtnC.wasPressed())) {
        batterySaverEnabled = false;
        setDisplayPower(true);
        resetHomeUi();
    }
    if (!carModePromptActive) {
        handleAlertPopup();
        handleInfoPopup();
        handleVolumeButtons();
        handleMenuButtons();
        handleHomeScreen();
        handleScreenSaver();
    }
#endif
    delay(5);
}
