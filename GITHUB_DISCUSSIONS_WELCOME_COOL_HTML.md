<div align="center">

<pre>
  ____ _____ _____     _____ _     ___   ____ _  _______ ____  
 / ___| ____|_   _|   |  ___| |   / _ \ / ___| |/ / ____|  _ \ 
| |  _|  _|   | |_____| |_  | |  | | | | |   | ' /|  _| | | | |
| |_| | |___  | |_____|  _| | |__| |_| | |___| . \| |___| |_| |
 \____|_____| |_|     |_|   |_____\___/ \____|_|\_\_____|____/ 
</pre>

<h1>Get-Flocked Signal Deck Discussions</h1>

<p>
  <strong>M5Stack FIRE passive RF awareness firmware</strong><br>
  Derived from FlockSquawk and rebuilt for field logging, debug tools, tone audio,
  and optional GPS/geofence support.
</p>

</div>

---

<table>
  <tr>
    <td><strong>RF Mode</strong></td>
    <td>Works without GPS. Listens passively for WiFi/BLE signal evidence.</td>
  </tr>
  <tr>
    <td><strong>GPS / GEO Mode</strong></td>
    <td>Requires a compatible UART GPS module installed in the M5Stack FIRE module slot or connected to the configured GPS port and a valid satellite fix.</td>
  </tr>
  <tr>
    <td><strong>Public Package</strong></td>
    <td>Clean slate for personal data: no personal logs, private coordinates, saved configs, or local watch-list entries. Includes public East Coast OSM grouped GEO files.</td>
  </tr>
</table>

## What Discussions Are For

<table>
  <tr>
    <td><strong>Setup Help</strong></td>
    <td>Arduino IDE, M5Stack FIRE, SD cards, libraries, tone audio, GPS modules, and flashing.</td>
  </tr>
  <tr>
    <td><strong>Field Testing</strong></td>
    <td>Accuracy reports, repeatable observations, debug screenshots, and clean non-personal test notes.</td>
  </tr>
  <tr>
    <td><strong>Ideas</strong></td>
    <td>Detection logic, menu polish, debug tools, GPS/geofence workflows, docs, and release cleanup.</td>
  </tr>
  <tr>
    <td><strong>Community</strong></td>
    <td>Helping new users get started and comparing clean test methods.</td>
  </tr>
</table>

## Please Do Not Post

> Keep the public repo clean and safe.

- Private coordinates or exact home/work locations.
- Personal field logs that expose private routes or addresses.
- Sensitive local exact-MAC watch-list entries.
- Private addresses, private camera locations, or doxxing-style information.
- Anything you are not comfortable making public forever.

<details>
<summary><strong>Good Field-Test Report Format</strong></summary>

`	ext
Hardware:
Firmware version:
GPS mode: RF-only / GPS enabled
SD card files used:

Test location type:
Approximate test method:
  - approach
  - under/near target
  - exit/background

What happened:
  - confidence:
  - alert:
  - radar:
  - audio:
  - logs available:

Notes:
`

</details>

<details>
<summary><strong>Quick Start Reminder</strong></summary>

1. Flash a public release version.
2. Copy that version's <code>SD_CARD_CLEAN_SLATE</code> contents to the SD card root.
3. Turn on Logging only when collecting test evidence.
4. Use RF-only mode if you do not have a compatible GPS module in the M5Stack FIRE module slot/port.
5. Enable GPS/GEO features only after connecting a compatible UART GPS module and getting a valid fix.

</details>

---

<div align="center">

<strong>Introduce yourself below.</strong><br>
Tell us your hardware, firmware version, whether you are using GPS or RF-only mode,
and what you want to test or improve.

</div>
