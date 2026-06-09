#ifndef THREAT_ANALYZER_H
#define THREAT_ANALYZER_H

#include <Arduino.h>
#include "EventBus.h"
#include "DetectorTypes.h"
#include "Detectors.h"

// ============================================================
// Detector Registry
// To add a detector: append one entry to the appropriate array.
// ============================================================

static const WiFiDetectorEntry wifiDetectors[] = {
    { detectWifiWildcardProbe, DET_WIFI_WILDCARD     },
    { detectSsidFormat,       DET_SSID_FORMAT      },
    { detectSsidKeyword,      DET_SSID_KEYWORD     },
    { detectWifiMacOui,       DET_MAC_OUI          },
    { detectWifiReceiverOui,  DET_WIFI_RECEIVER_OUI },
    { detectWifiFieldWatchMac, DET_FIELD_WATCH_MAC },
    { detectFlockOui,         DET_FLOCK_OUI        },
    { detectSurveillanceOui,  DET_SURVEILLANCE_OUI },
};
static const uint8_t WIFI_DETECTOR_COUNT =
    sizeof(wifiDetectors) / sizeof(wifiDetectors[0]);

static const BLEDetectorEntry bleDetectors[] = {
    { detectBleName,              DET_BLE_NAME          },
    { detectRavenCustomUuid,      DET_RAVEN_CUSTOM_UUID },
    { detectRavenStdUuid,         DET_RAVEN_STD_UUID    },
    { detectBleMacOui,            DET_MAC_OUI           },
    { detectBleFlockOui,          DET_FLOCK_OUI         },
    { detectBleManufacturerId,    DET_BLE_MANUFACTURER  },
    { detectBleSurveillanceOui,   DET_SURVEILLANCE_OUI  },
};
static const uint8_t BLE_DETECTOR_COUNT =
    sizeof(bleDetectors) / sizeof(bleDetectors[0]);

// ============================================================
// Flag-based alert tier computation
// ============================================================

inline AlertLevel computeWiFiAlertLevel(uint16_t matchFlags, bool hiddenSsid) {
    if (matchFlags & (DET_SSID_FORMAT | DET_FLOCK_OUI))
        return ALERT_CONFIRMED;
    if (matchFlags & DET_WIFI_WILDCARD)
        return ALERT_SUSPICIOUS;
    if ((matchFlags & DET_SSID_KEYWORD) && (matchFlags & DET_MAC_OUI))
        return ALERT_CONFIRMED;
    if ((matchFlags & DET_WIFI_RECEIVER_OUI) && (matchFlags & DET_MAC_OUI))
        return ALERT_CONFIRMED;
    if (matchFlags & DET_FIELD_WATCH_MAC)
        return ALERT_SUSPICIOUS;
    if (matchFlags & DET_SSID_KEYWORD)
        return ALERT_SUSPICIOUS;
    if (matchFlags & DET_WIFI_RECEIVER_OUI)
        return ALERT_SUSPICIOUS;
    if ((matchFlags & DET_MAC_OUI) && hiddenSsid)
        return ALERT_SUSPICIOUS;
    if (matchFlags & DET_SURVEILLANCE_OUI)
        return ALERT_INFO;
    return ALERT_NONE;
}

inline AlertLevel computeBLEAlertLevel(uint16_t matchFlags) {
    if (matchFlags & (DET_BLE_NAME | DET_RAVEN_CUSTOM_UUID | DET_FLOCK_OUI |
                      DET_BLE_MANUFACTURER))
        return ALERT_CONFIRMED;
    if (matchFlags & DET_MAC_OUI)
        return ALERT_SUSPICIOUS;
    if (matchFlags & DET_RAVEN_STD_UUID)
        return ALERT_SUSPICIOUS;
    if (matchFlags & DET_SURVEILLANCE_OUI)
        return ALERT_INFO;
    return ALERT_NONE;
}

inline bool repeatedSuspiciousConfirmed(uint16_t matchFlags,
                                        uint16_t hitCount,
                                        uint8_t maxCertainty,
                                        int8_t rssi,
                                        const uint8_t* targetMac) {
    bool strongPrefix = targetMac && ouiMatchesStrongPrefix(targetMac);
    bool receiverOnly =
        (matchFlags & DET_WIFI_RECEIVER_OUI) &&
        !(matchFlags & (DET_MAC_OUI | DET_FLOCK_OUI | DET_WIFI_WILDCARD |
                        DET_SSID_FORMAT | DET_SSID_KEYWORD));
    bool repeatedStrongReceiver =
        receiverOnly && strongPrefix &&
        hitCount >= 4 && maxCertainty >= 30 && rssi > -82;
    bool repeatedBroadReceiver =
        receiverOnly && !strongPrefix &&
        hitCount >= 16 && maxCertainty >= 45 && rssi > -62;
    bool repeatedStrongWildcard =
        (matchFlags & DET_WIFI_WILDCARD) && strongPrefix &&
        hitCount >= 1 && maxCertainty >= 90;
    bool repeatedBroadWildcard =
        (matchFlags & DET_WIFI_WILDCARD) && !strongPrefix &&
        hitCount >= 12 && maxCertainty >= 90 && rssi > -65;
    bool repeatedFieldWatch =
        (matchFlags & DET_FIELD_WATCH_MAC) &&
        hitCount >= 2 && maxCertainty >= 50 && rssi > -92;
    bool repeatedKnownOui =
        (matchFlags & DET_MAC_OUI) &&
        ((strongPrefix && hitCount >= 4 && maxCertainty >= 40 && rssi > -80) ||
         (!strongPrefix && hitCount >= 12 && maxCertainty >= 40 && rssi > -65));
    return repeatedStrongReceiver || repeatedBroadReceiver ||
           repeatedStrongWildcard || repeatedBroadWildcard ||
           repeatedFieldWatch ||
           repeatedKnownOui;
}

// ============================================================
// Device Presence Tracker
// ============================================================

class DeviceTracker {
public:
    void initialize() {
        for (uint8_t i = 0; i < MAX_TRACKED_DEVICES; i++) {
            slots[i].state = DeviceState::EMPTY;
            slots[i].hitCount = 0;
            slots[i].maxCertainty = 0;
            slots[i].maxAlertLevel = ALERT_NONE;
            slots[i].alertIssued = false;
            slots[i].lastAlertMs = 0;
        }
    }

    // Age out stale devices. Call every loop iteration.
    void tick(uint32_t nowMs) {
        for (uint8_t i = 0; i < MAX_TRACKED_DEVICES; i++) {
            if (slots[i].state == DeviceState::IN_RANGE ||
                slots[i].state == DeviceState::NEW_DETECT) {
                if (nowMs - slots[i].lastSeenMs > DEVICE_TIMEOUT_MS) {
                    slots[i].state = DeviceState::DEPARTED;
                }
            }
        }
    }

    // Record a detection. Returns the state the device was in BEFORE
    // this update (EMPTY = first time seen).
    DeviceState recordDetection(const uint8_t* mac, uint32_t nowMs,
                                AlertLevel level, uint8_t certainty,
                                uint16_t* hitCountOut,
                                uint8_t* maxCertaintyOut,
                                bool* alertRecentlyIssuedOut) {
        for (uint8_t i = 0; i < MAX_TRACKED_DEVICES; i++) {
            if (slots[i].state != DeviceState::EMPTY &&
                memcmp(slots[i].mac, mac, 6) == 0) {
                if (slots[i].state == DeviceState::DEPARTED &&
                    nowMs - slots[i].lastSeenMs > DEVICE_REACQUIRE_SUPPRESS_MS) {
                    continue;
                }
                DeviceState prev = slots[i].state;
                slots[i].lastSeenMs = nowMs;
                slots[i].state = DeviceState::IN_RANGE;
                if (slots[i].hitCount < UINT16_MAX) slots[i].hitCount++;
                if (certainty > slots[i].maxCertainty)
                    slots[i].maxCertainty = certainty;
                if (level > slots[i].maxAlertLevel)
                    slots[i].maxAlertLevel = level;
                if (hitCountOut) *hitCountOut = slots[i].hitCount;
                if (maxCertaintyOut) *maxCertaintyOut = slots[i].maxCertainty;
                if (alertRecentlyIssuedOut) {
                    bool recentAlert =
                        slots[i].lastAlertMs != 0 &&
                        nowMs - slots[i].lastAlertMs < DEVICE_ALERT_REISSUE_MS;
                    *alertRecentlyIssuedOut = recentAlert;
                }
                return prev;
            }
        }

        uint8_t slot = findFreeSlot();
        memcpy(slots[slot].mac, mac, 6);
        slots[slot].firstSeenMs    = nowMs;
        slots[slot].lastSeenMs     = nowMs;
        slots[slot].hitCount       = 1;
        slots[slot].maxCertainty   = certainty;
        slots[slot].maxAlertLevel  = level;
        slots[slot].state          = DeviceState::NEW_DETECT;
        slots[slot].alertIssued    = false;
        slots[slot].lastAlertMs    = 0;
        if (hitCountOut) *hitCountOut = slots[slot].hitCount;
        if (maxCertaintyOut) *maxCertaintyOut = slots[slot].maxCertainty;
        if (alertRecentlyIssuedOut) *alertRecentlyIssuedOut = false;
        return DeviceState::EMPTY;
    }

    void markAlertIssued(const uint8_t* mac, AlertLevel level, uint32_t nowMs) {
        for (uint8_t i = 0; i < MAX_TRACKED_DEVICES; i++) {
            if (slots[i].state != DeviceState::EMPTY &&
                memcmp(slots[i].mac, mac, 6) == 0) {
                slots[i].alertIssued = true;
                slots[i].lastAlertMs = nowMs;
                if (level > slots[i].maxAlertLevel)
                    slots[i].maxAlertLevel = level;
                return;
            }
        }
    }

    // Returns true if any tracked device is IN_RANGE at SUSPICIOUS or above.
    bool hasHighConfidenceInRange() const {
        for (uint8_t i = 0; i < MAX_TRACKED_DEVICES; i++) {
            if (slots[i].state == DeviceState::IN_RANGE &&
                slots[i].maxAlertLevel >= ALERT_SUSPICIOUS) {
                return true;
            }
        }
        return false;
    }

private:
    TrackedDevice slots[MAX_TRACKED_DEVICES];

    uint8_t findFreeSlot() {
        for (uint8_t i = 0; i < MAX_TRACKED_DEVICES; i++) {
            if (slots[i].state == DeviceState::EMPTY) return i;
        }
        uint8_t oldest = 0;
        uint32_t oldestTime = UINT32_MAX;
        for (uint8_t i = 0; i < MAX_TRACKED_DEVICES; i++) {
            if (slots[i].state == DeviceState::DEPARTED &&
                slots[i].lastSeenMs < oldestTime) {
                oldest = i;
                oldestTime = slots[i].lastSeenMs;
            }
        }
        if (oldestTime < UINT32_MAX) return oldest;
        // All slots active -- evict LRU
        oldest = 0;
        oldestTime = UINT32_MAX;
        for (uint8_t i = 0; i < MAX_TRACKED_DEVICES; i++) {
            if (slots[i].lastSeenMs < oldestTime) {
                oldest = i;
                oldestTime = slots[i].lastSeenMs;
            }
        }
        return oldest;
    }
};

// ============================================================
// Bit position helper
// ============================================================

inline uint8_t detectorBitPosition(uint16_t flag) {
    uint8_t pos = 0;
    while (flag > 1) { flag >>= 1; pos++; }
    return pos;
}

// ============================================================
// ThreatAnalyzer
// Pure logic -- no display/buzzer access. Safe from any context.
// ============================================================

class ThreatAnalyzer {
public:
    void initialize() {
        tracker.initialize();
        lastHeartbeatMs = 0;
    }

    void analyzeWiFiFrame(const WiFiFrameEvent& frame) {
        uint16_t matchFlags = 0;
        uint8_t weights[MAX_DETECTOR_WEIGHTS];
        memset(weights, 0, sizeof(weights));
        int16_t totalWeight = 0;

        for (uint8_t i = 0; i < WIFI_DETECTOR_COUNT; i++) {
            DetectorResult res = wifiDetectors[i].fn(frame);
            if (res.matched) {
                matchFlags |= wifiDetectors[i].flag;
                uint8_t bit = detectorBitPosition(wifiDetectors[i].flag);
                if (bit < sizeof(weights)) weights[bit] = res.weight;
                totalWeight += res.weight;
            }
        }

        if (matchFlags == DET_NONE) return;
        if (shouldSuppressConsumerWifiFrame(frame, matchFlags)) return;

        bool hiddenSsid = (frame.ssid[0] == '\0');

        int8_t rssiMod = rssiModifier(frame.rssi);
        totalWeight += rssiMod;
        uint8_t certainty = (uint8_t)constrain(totalWeight, 0, 100);

        AlertLevel level = computeWiFiAlertLevel(matchFlags, hiddenSsid);

        bool sourceFieldWatch = macMatchesFieldWatch(frame.mac);
        bool receiverFieldWatch = frame.hasReceiverMac &&
                                  macMatchesFieldWatch(frame.receiverMac);
        bool bssidFieldWatch = frame.hasBssid &&
                               macMatchesFieldWatch(frame.bssid);

        const uint8_t* targetMac = frame.mac;
        if (receiverFieldWatch && !sourceFieldWatch) {
            targetMac = frame.receiverMac;
        } else if (bssidFieldWatch && !sourceFieldWatch) {
            targetMac = frame.bssid;
        } else if ((matchFlags & DET_WIFI_RECEIVER_OUI) &&
            !(matchFlags & (DET_MAC_OUI | DET_FLOCK_OUI | DET_WIFI_WILDCARD))) {
            targetMac = frame.receiverMac;
        }

        uint32_t nowMs = millis();
        uint16_t hitCount = 0;
        uint8_t maxCertainty = certainty;
        bool alertRecentlyIssued = false;
        DeviceState prevState = tracker.recordDetection(
            targetMac, nowMs, level, certainty,
            &hitCount, &maxCertainty, &alertRecentlyIssued);

        if (level == ALERT_SUSPICIOUS &&
            repeatedSuspiciousConfirmed(matchFlags, hitCount, maxCertainty,
                                        frame.rssi, targetMac)) {
            level = ALERT_CONFIRMED;
            certainty = maxCertainty;
        }

        ThreatEvent threat;
        memset(&threat, 0, sizeof(threat));
        memcpy(threat.mac, targetMac, 6);
        if (frame.ssid[0] != '\0') {
            strncpy(threat.identifier, frame.ssid,
                    sizeof(threat.identifier) - 1);
        } else if (matchFlags & DET_WIFI_WILDCARD) {
            strncpy(threat.identifier, "wildcard probe",
                    sizeof(threat.identifier) - 1);
        } else if (matchFlags & DET_WIFI_RECEIVER_OUI) {
            strncpy(threat.identifier, "receiver OUI",
                    sizeof(threat.identifier) - 1);
        }
        threat.rssi            = frame.rssi;
        threat.channel         = frame.channel;
        strncpy(threat.radioType, "wifi", sizeof(threat.radioType) - 1);
        threat.certainty       = certainty;
        const char* wifiCat = (matchFlags & DET_SURVEILLANCE_OUI)
            ? "surveillance_camera" : "surveillance_device";
        strncpy(threat.category, wifiCat, sizeof(threat.category) - 1);
        threat.matchFlags      = matchFlags | DET_RSSI_MODIFIER;
        memcpy(threat.detectorWeights, weights, sizeof(weights));
        threat.rssiModifier    = rssiMod;
        threat.alertLevel      = level;
        threat.firstDetection  = (prevState == DeviceState::EMPTY);
        threat.shouldAlert     = (level >= ALERT_CONFIRMED &&
                                  !alertRecentlyIssued);
        if (threat.shouldAlert) {
            tracker.markAlertIssued(targetMac, level, nowMs);
        }

        EventBus::publishThreat(threat);
    }

    void analyzeBluetoothDevice(const BluetoothDeviceEvent& device) {
        uint16_t matchFlags = 0;
        uint8_t weights[MAX_DETECTOR_WEIGHTS];
        memset(weights, 0, sizeof(weights));
        int16_t totalWeight = 0;

        for (uint8_t i = 0; i < BLE_DETECTOR_COUNT; i++) {
            DetectorResult res = bleDetectors[i].fn(device);
            if (res.matched) {
                matchFlags |= bleDetectors[i].flag;
                uint8_t bit = detectorBitPosition(bleDetectors[i].flag);
                if (bit < sizeof(weights)) weights[bit] = res.weight;
                totalWeight += res.weight;
            }
        }

        if (matchFlags == DET_NONE) return;

        int8_t rssiMod = rssiModifier(device.rssi);
        totalWeight += rssiMod;
        uint8_t certainty = (uint8_t)constrain(totalWeight, 0, 100);

        AlertLevel level = computeBLEAlertLevel(matchFlags);

        uint32_t nowMs = millis();
        uint16_t hitCount = 0;
        uint8_t maxCertainty = certainty;
        bool alertRecentlyIssued = false;
        DeviceState prevState = tracker.recordDetection(
            device.mac, nowMs, level, certainty,
            &hitCount, &maxCertainty, &alertRecentlyIssued);

        if (level == ALERT_SUSPICIOUS &&
            repeatedSuspiciousConfirmed(matchFlags, hitCount, maxCertainty,
                                        device.rssi, device.mac)) {
            level = ALERT_CONFIRMED;
            certainty = maxCertainty;
        }

        const char* cat;
        if (matchFlags & (DET_RAVEN_CUSTOM_UUID | DET_RAVEN_STD_UUID))
            cat = "acoustic_detector";
        else if (matchFlags & DET_SURVEILLANCE_OUI)
            cat = "surveillance_camera";
        else
            cat = "surveillance_device";

        ThreatEvent threat;
        memset(&threat, 0, sizeof(threat));
        memcpy(threat.mac, device.mac, 6);
        strncpy(threat.identifier, device.name,
                sizeof(threat.identifier) - 1);
        threat.rssi            = device.rssi;
        threat.channel         = 0;
        strncpy(threat.radioType, "bluetooth", sizeof(threat.radioType) - 1);
        threat.certainty       = certainty;
        strncpy(threat.category, cat, sizeof(threat.category) - 1);
        threat.matchFlags      = matchFlags | DET_RSSI_MODIFIER;
        memcpy(threat.detectorWeights, weights, sizeof(weights));
        threat.rssiModifier    = rssiMod;
        threat.alertLevel      = level;
        threat.firstDetection  = (prevState == DeviceState::EMPTY);
        threat.shouldAlert     = (level >= ALERT_CONFIRMED &&
                                  !alertRecentlyIssued);
        if (threat.shouldAlert) {
            tracker.markAlertIssued(device.mac, level, nowMs);
        }

        EventBus::publishThreat(threat);
    }

    // Call from loop(). Ages out stale devices and returns true
    // if a heartbeat beep should be emitted (caller handles hardware).
    bool tick(uint32_t nowMs) {
        tracker.tick(nowMs);

        if (nowMs - lastHeartbeatMs >= HEARTBEAT_INTERVAL_MS) {
            lastHeartbeatMs = nowMs;
            if (tracker.hasHighConfidenceInRange()) {
                return true;
            }
        }
        return false;
    }

private:
    DeviceTracker tracker;
    uint32_t lastHeartbeatMs;
};

#endif
