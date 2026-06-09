# Get-Flocked Signal Deck v4.32

Public release package for the M5Stack FIRE detector firmware.

This project is derived from the original FlockSquawk M5Stack FIRE codebase and has been heavily modified for field logging, passive RF analysis, GPS/geofence workflows, audio, debug tools, and M5Stack FIRE ergonomics.

Version note: Added Debug Settings tools: Log Marker, GPS Status, Geo File Test, SD Write Test, BLE Scan Test, and WiFi Channel Test.

Clean-slate policy:
- No field logs are included.
- No saved device config is included.
- No private/personal coordinates are included.
- Public OSM-derived East Coast grouped geofence files are included for ready-to-use GEO setup.
- Local exact-MAC watch-list entries are stripped from this public copy.

GPS note:
RF detection works without GPS. GPS/geofencing features require a compatible UART GPS module installed in the M5Stack FIRE module slot or connected to the configured GPS port, plus a valid satellite fix.

This version supports grouped GPS/OSM geofencing using /geo_index.csv and /geo_groups/*.csv. The public release includes the ready-to-use East Coast OSM-derived grouped geofence dataset; replace or regenerate it with your own lawful data as coverage expands.

Start here:
1. Open this folder in Arduino IDE.
2. Select board: M5Stack-FIRE / esp32:esp32:m5stack-fire.
3. Install libraries used by the sketch, especially M5Unified, NimBLE-Arduino, and ArduinoJson.
4. Copy the matching SD_CARD_CLEAN_SLATE folder contents to the root of a FAT32 microSD card.
5. Flash the sketch.
6. Use Menu > Logging only when you want CSV evidence written to SD.

License and attribution:
The upstream base is FlockSquawk. This release keeps the GPLv3 LICENSE file because GPL terms matter when distributing modified source code.
