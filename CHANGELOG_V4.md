# Get-Flocked Signal Deck v4 Changelog

This public package starts at v4.0 and includes each available v4 folder through v4.34.

- v4.0: Public logging toggle defaulted off, refreshed boot screen, archived old logs, and added field-log workflow.
- v4.1: Added exact local watch-list support, analyzer flag names, and boot-logo-style idle screen. Public release ships that local watch list empty.
- v4.2: Improved exact-site watch behavior, faster strong-signature promotion, and shorter repeat-alert cooldowns.
- v4.21: Cleaned WAV audio path with mono 16-bit 16 kHz assets and lower speaker gain.
- v4.22: Changed default audio to generated tone patterns to avoid WAV static on M5Stack FIRE.
- v4.23: Re-enabled optional WAV support with strict header validation and fallback tones.
- v4.24: Moved custom audio to SD-editable sound_tones.csv and removed bundled WAV dependency.
- v4.25: Tightened weak receiver-only promotion and broad-prefix behavior to reduce false alerts.
- v4.26: Added consumer/router SSID suppression so residential WiFi stays logged without becoming detector evidence.
- v4.27: Added logging-session timer, boot-uptime columns, and clearer field-test timing workflow.
- v4.30: Added grouped GPS/OSM geofencing, separate blue GEO alerts, and lower-panel GPS camera map. Public release ships empty geofence templates.
- v4.31: Removed background option, added GPS and Debug submenus, linked Geo Radius to geofence logic, and kept top status updating in menus.
- v4.32: Added Debug Settings tools: Log Marker, GPS Status, Geo File Test, SD Write Test, BLE Scan Test, and WiFi Channel Test.
- v4.33: Polished menu order and labels, moved GPS Settings near Debug Settings, and made debug tests return to the submenu.
- v4.34: Added softer boot chime, reduced boot-only volume, and kept RF/GEO alert sounds assertive.

Public-release cleanup applied to every version:
- Removed field-log backup folders.
- Removed generated CSV logs and cached Python bytecode.
- Removed saved device config files.
- Kept the public East Coast OSM-derived grouped geofence dataset for ready-to-use GEO setup.
- Removed raw generated ALPR export dumps from the tools folder.
- Removed local exact-MAC watch-list entries.
- Replaced local/project-specific README content with clean public instructions.
