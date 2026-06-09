# Get-Flocked Signal Deck for M5Stack FIRE

Get-Flocked Signal Deck is a passive RF/GPS awareness build for the M5Stack FIRE, derived from the original FlockSquawk M5Stack project and heavily reworked through field testing for cleaner logging, better alert behavior, debug tooling, custom tone audio, and optional local GPS/geofence awareness.

It listens passively for WiFi/BLE signals, scores likely camera/device signatures, shows confidence and alert state on the M5Stack screen, and can write field logs to SD for later review. Newer versions add GPS geofencing support using either a simple target CSV or the bundled East Coast OSM-derived grouped geofence files.

GPS/geofencing note: RF detection works without GPS. GEO alerts, GEO radius checks, and map/geofence features require a compatible UART GPS module installed in the M5Stack FIRE module slot or connected to the configured GPS port and a valid satellite fix.

Public release notes:
- No personal logs are included.
- No private/personal coordinates are included.
- East Coast OSM-derived grouped geofence files are included so GEO mode is ready after SD setup.
- Raw generated ALPR export dumps are removed from the public package.
- Local exact-MAC watch-list entries have been stripped.
- Users can rebuild or extend geofence coverage with the included tools and must do their own field validation.

Credit:
- Based on the original FlockSquawk M5Stack FIRE project by its original creator/contributors.
- Accuracy ideas and comparisons were informed by public community projects such as flock-you and other open Flock-detection research.
- This modified source release keeps the GPLv3 license from the upstream codebase.

Hardware target:
- M5Stack FIRE / ESP32
- Arduino IDE / Arduino CLI
- Libraries: M5Unified, NimBLE-Arduino, ArduinoJson

Recommended starting point:
- Use v4.34 for the newest public build.
- Older v4 folders are included for history and comparison.
