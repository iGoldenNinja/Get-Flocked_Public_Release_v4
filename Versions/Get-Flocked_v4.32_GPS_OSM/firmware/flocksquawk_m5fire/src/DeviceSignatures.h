#ifndef DEVICE_SIGNATURES_H
#define DEVICE_SIGNATURES_H

#include <Arduino.h>

namespace DeviceProfiles {

    // MAC address OUI prefixes for target devices (Lite-On Technology)
    const char* const MACPrefixes[] = {
        "58:8e:81", "cc:cc:cc", "ec:1b:bd", "90:35:ea", "04:0d:84",
        "f0:82:c0", "1c:34:f1", "38:5b:44", "94:34:69", "b4:e3:f9",
        "70:c9:4e", "3c:91:80", "d8:f3:bc", "80:30:49", "14:5a:fc",
        "74:4c:a1", "08:3a:88", "9c:2f:9d", "94:08:53", "e4:aa:ea",
        "b8:35:32", "c0:35:32", "f4:6a:dd", "f8:a2:d6", "24:b2:b9",
        "00:f4:8d", "d0:39:57", "e8:d0:fc", "e0:4f:43", "b8:1e:a4",
        "70:08:94", "3c:71:bf", "58:00:e3", "5c:93:a2", "64:6e:69",
        "48:27:ea", "a4:cf:12", "82:6b:f2"
    };
    const size_t MACPrefixCount = sizeof(MACPrefixes) / sizeof(MACPrefixes[0]);

    // Field-confirmed / high-signal prefixes get faster receiver-only promotion.
    // Keep broad prefixes out of this list when field logs show consumer/router
    // traffic can trigger them; they can stay in MACPrefixes without fast alerts.
    const char* const StrongMACPrefixes[] = {
        "14:5a:fc", "b8:35:32", "c0:35:32", "b4:1e:52"
    };
    const size_t StrongMACPrefixCount =
        sizeof(StrongMACPrefixes) / sizeof(StrongMACPrefixes[0]);

    // Optional exact local watch-list entries.
    // Public releases ship empty. Add your own local MACs only after
    // repeated field verification. FieldWatchMacCount stays 0 until then.
    const char* const FieldWatchMacs[] = {
        "00:00:00:00:00:00"
    };
    const size_t FieldWatchMacCount = 0;

    // Flock Safety (direct OUI registration â€” high confidence)
    const char* const FlockSafetyOUI = "b4:1e:52";

    // BLE manufacturer company ID observed in public Flock-You research.
    const uint16_t FlockBleManufacturerId = 0x09C8;

    // Surveillance camera manufacturers (curated from FlockOff database).
    // Dedicated security/surveillance companies only.
    struct SurveillanceOUI {
        const char* prefix;
        const char* manufacturer;
    };

    const SurveillanceOUI SurveillancePrefixes[] = {
        // Avigilon Alta
        { "70:1a:d5", "Avigilon Alta" },
        // Axis Communications
        { "00:40:8c", "Axis Communications" },
        { "ac:cc:8e", "Axis Communications" },
        { "b8:a4:4f", "Axis Communications" },
        { "e8:27:25", "Axis Communications" },
        // FLIR Systems
        { "00:13:56", "FLIR Systems" },
        { "00:40:7f", "FLIR Systems" },
        { "00:1b:d8", "FLIR Systems" },
        // GeoVision
        { "00:13:e2", "GeoVision" },
        // Hanwha Vision
        { "44:b4:23", "Hanwha Vision" },
        { "8c:1d:55", "Hanwha Vision" },
        { "e4:30:22", "Hanwha Vision" },
        // March Networks
        { "00:10:be", "March Networks" },
        { "00:12:81", "March Networks" },
        // Mobotix
        { "00:03:c5", "Mobotix" },
        // Sunell Electronics
        { "00:1c:27", "Sunell Electronics" },
    };
    const size_t SurveillancePrefixCount =
        sizeof(SurveillancePrefixes) / sizeof(SurveillancePrefixes[0]);
}

#endif
