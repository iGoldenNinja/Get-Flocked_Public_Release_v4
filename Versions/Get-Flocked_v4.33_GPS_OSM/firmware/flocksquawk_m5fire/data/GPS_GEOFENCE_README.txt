GPS / GEO PUBLIC RELEASE SETUP

No private/personal coordinates are included in this public release.

GPS/geofencing requires a compatible UART GPS module installed in the M5Stack FIRE module slot or connected to the configured GPS port and a valid satellite fix. RF detection still works without GPS.

Ready-to-use grouped mode, v4.30 and newer:
  /geo_index.csv
  /geo_groups/*.csv

The bundled grouped files are OSM-derived East Coast geofence data intended to make GEO alerts work after setup. Keep /geo_index.csv and /geo_groups/ together on the SD card root.

Fallback single-file mode:
  /geo_targets.csv
  header: id,lat,lon,radius_m,label

Future upgrades:
  Use tools/download_flock_cameras.py and tools/build_geo_groups.py to rebuild or expand the grouped dataset.

Do not add or publish private/sensitive coordinate sets unless you have decided they are safe and lawful to publish.
