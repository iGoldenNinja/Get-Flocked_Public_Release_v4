#!/usr/bin/env python3
import argparse
import csv
import os
from collections import defaultdict
from datetime import datetime, timedelta


ALERT_NAMES = {
    "0": "NONE",
    "1": "INFO",
    "2": "SUSPICIOUS",
    "3": "CONFIRMED",
}

DETECTOR_FLAGS = [
    (0x0001, "ssid_format"),
    (0x0002, "ssid_keyword"),
    (0x0004, "mac_oui"),
    (0x0008, "ble_name"),
    (0x0010, "raven_custom_uuid"),
    (0x0020, "raven_std_uuid"),
    (0x0040, "rssi_modifier"),
    (0x0080, "flock_oui"),
    (0x0100, "surveillance_oui"),
    (0x0200, "wifi_wildcard_probe"),
    (0x0400, "wifi_receiver_oui"),
    (0x0800, "ble_manufacturer_id"),
    (0x1000, "field_watch_mac"),
]


def as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value, default=None):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_mac(value):
    return (value or "").strip().lower()


def decode_match_flags(value):
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        flags = int(raw, 16)
    except ValueError:
        return ""
    names = [name for bit, name in DETECTOR_FLAGS if flags & bit]
    return "+".join(names)


def decode_match_flag_set(values):
    names = set()
    for value in values:
        decoded = decode_match_flags(value)
        if decoded:
            names.update(decoded.split("+"))
    return "+".join(sorted(names))


def duration_ms(entry):
    return (entry["last_ms"] or 0) - (entry["first_ms"] or 0)


def default_sibling(path, filename):
    return os.path.join(os.path.dirname(os.path.abspath(path)), filename)


def hms_from_ms(ms):
    total = max(0, as_int(ms)) // 1000
    hours = total // 3600
    minutes = (total // 60) % 60
    seconds = total % 60
    return f"{hours}:{minutes:02}:{seconds:02}"


def parse_clock(value, reference=None):
    if not value:
        return None

    raw = value.strip()
    compact = raw.lower().replace(" ", "")
    has_meridian = "am" in compact or "pm" in compact
    candidates = []

    formats = [
        "%I:%M%p", "%I:%M:%S%p", "%H:%M", "%H:%M:%S",
        "%Y-%m-%d%I:%M%p", "%Y-%m-%d%I:%M:%S%p",
        "%Y-%m-%d%H:%M", "%Y-%m-%d%H:%M:%S",
    ]
    for fmt in formats:
        try:
            parsed = datetime.strptime(compact, fmt)
            candidates.append(parsed)
        except ValueError:
            pass

    if not candidates:
        raise ValueError(f"Could not parse time: {value}")

    parsed = candidates[0]
    if reference is None:
        return parsed

    base = parsed.replace(year=reference.year, month=reference.month, day=reference.day)
    choices = [base, base + timedelta(days=1)]
    if not has_meridian and parsed.hour < 12:
        choices.extend([base + timedelta(hours=12), base + timedelta(hours=36)])

    future = [choice for choice in choices if choice >= reference]
    return min(future, key=lambda choice: choice - reference) if future else max(choices)


def clock_text(start_clock, ms):
    if not start_clock:
        return ""
    return (start_clock + timedelta(milliseconds=as_int(ms))).strftime("%I:%M:%S%p").lstrip("0").lower()


def row_ms(row):
    if row.get("ms") not in (None, ""):
        return as_int(row.get("ms"))
    if row.get("uptime_s") not in (None, ""):
        return as_int(row.get("uptime_s")) * 1000
    return 0


def load_rows(path):
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        rows = list(csv.DictReader(f))

    auto_session = 1
    last_ms = None
    for row in rows:
        ms = row_ms(row)
        explicit = (row.get("session_id") or "").strip()
        if explicit:
            row["_session_id"] = explicit
        else:
            if last_ms is not None and ms < last_ms:
                auto_session += 1
            row["_session_id"] = f"auto_{auto_session}"
        last_ms = ms
    return rows


def filter_session(rows, session_id):
    if session_id in (None, "all"):
        return rows
    return [row for row in rows if row.get("_session_id") == session_id]


def choose_session(rows, requested):
    if not rows:
        return requested
    sessions = []
    seen = set()
    for row in rows:
        sid = row.get("_session_id")
        if sid and sid not in seen:
            seen.add(sid)
            sessions.append(sid)
    if requested == "latest":
        return rows[-1].get("_session_id")
    return requested


def mac_kind(mac):
    if not mac:
        return "-"
    try:
        first = int(mac[:2], 16)
    except ValueError:
        return "unknown"
    if first & 0x01:
        return "multicast"
    if first & 0x02:
        return "randomized"
    return "public"


def main():
    parser = argparse.ArgumentParser(
        description="Summarize Get-Flocked /field_log.csv from an SD card field run."
    )
    parser.add_argument("csv_path", help="Path to field_log.csv")
    parser.add_argument("--top", type=int, default=20, help="Number of targets to show")
    parser.add_argument(
        "--sightings",
        help="Path to wifi_sightings.csv. Defaults to the file beside field_log.csv when present.",
    )
    parser.add_argument(
        "--ble-sightings",
        help="Path to ble_sightings.csv. Defaults to the file beside field_log.csv when present.",
    )
    parser.add_argument(
        "--start-time",
        help="Wall-clock time when the device booted, e.g. 12:50pm or 2026-05-31 12:50pm.",
    )
    parser.add_argument(
        "--near-time",
        action="append",
        default=[],
        help="Wall-clock time to inspect around, e.g. 1:10pm. Requires --start-time. Can be repeated.",
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=90,
        help="Seconds before/after each --near-time to print raw rows.",
    )
    parser.add_argument(
        "--session",
        default="latest",
        help="Session to analyze: latest, all, auto_1, auto_2, or a logged session_id.",
    )
    args = parser.parse_args()
    start_clock = parse_clock(args.start_time) if args.start_time else None
    all_field_rows = load_rows(args.csv_path)
    selected_session = choose_session(all_field_rows, args.session)
    field_rows = filter_session(all_field_rows, selected_session)

    targets = defaultdict(lambda: {
        "events": 0,
        "alerts": 0,
        "suppressed": 0,
        "would_alert": 0,
        "first_ms": None,
        "last_ms": None,
        "max_certainty": 0,
        "best_rssi": -128,
        "alert_level": "0",
        "flags": set(),
        "labels": set(),
        "categories": set(),
        "first_gps": "",
        "last_gps": "",
    })
    event_counts = defaultdict(int)
    status_rows = []
    detected_macs = set()

    for row in field_rows:
        event = row.get("event", "")
        event_counts[event] += 1
        if event == "status":
            status_rows.append(row)

        if event not in ("threat", "alert", "alert_suppressed"):
            continue

        mac = normalize_mac(row.get("mac"))
        if not mac:
            continue

        entry = targets[mac]
        detected_macs.add(mac)
        ms = row_ms(row)
        certainty = as_int(row.get("certainty"))
        rssi = as_int(row.get("rssi"), -128)
        level = row.get("alert_level", "0")

        entry["events"] += 1
        if event == "alert":
            entry["alerts"] += 1
        if event == "alert_suppressed":
            entry["suppressed"] += 1
        if row.get("should_alert") == "1":
            entry["would_alert"] += 1
        if entry["first_ms"] is None or ms < entry["first_ms"]:
            entry["first_ms"] = ms
            entry["first_gps"] = gps_text(row)
        if entry["last_ms"] is None or ms > entry["last_ms"]:
            entry["last_ms"] = ms
            entry["last_gps"] = gps_text(row)
        entry["max_certainty"] = max(entry["max_certainty"], certainty)
        entry["best_rssi"] = max(entry["best_rssi"], rssi)
        if as_int(level) > as_int(entry["alert_level"]):
            entry["alert_level"] = level
        if row.get("match_flags"):
            entry["flags"].add(row["match_flags"])
        if row.get("identifier"):
            entry["labels"].add(row["identifier"])
        if row.get("category"):
            entry["categories"].add(row["category"])

    print("Field log summary")
    print("=================")
    if selected_session and selected_session != "all":
        print(f"Session: {selected_session}")
    if start_clock:
        print(f"Clock sync: boot={start_clock.strftime('%I:%M:%S%p').lstrip('0').lower()}")
    print("Events: " + ", ".join(f"{k}={v}" for k, v in sorted(event_counts.items())))
    if status_rows:
        last = status_rows[-1]
        print(
            "Last counters: "
            f"wifi_frames={last.get('wifi_frames', '')}, "
            f"ble_devices={last.get('ble_devices', '')}, "
            f"threat_events={last.get('threat_events', '')}, "
            f"wifi_sightings={last.get('wifi_sightings', '')}, "
            f"ble_sightings={last.get('ble_sightings', '')}, "
            f"ble_scan_starts={last.get('ble_scan_starts', '')}, "
            f"ble_scan_ends={last.get('ble_scan_ends', '')}, "
            f"ble_scan_results={last.get('ble_scan_results', '')}, "
            f"ble_scan_failures={last.get('ble_scan_failures', '')}, "
            f"alert_count={last.get('alert_count', '')}, "
            f"battery={last.get('battery', '')}%"
        )
    print()

    ranked = sorted(
        targets.items(),
        key=lambda item: (
            item[1]["alerts"],
            item[1]["suppressed"],
            item[1]["max_certainty"],
            item[1]["best_rssi"],
            item[1]["events"],
        ),
        reverse=True,
    )

    print(f"Top {min(args.top, len(ranked))} targets")
    print("----------------")
    for mac, entry in ranked[:args.top]:
        labels = ";".join(sorted(entry["labels"])) or "-"
        flags = ";".join(sorted(entry["flags"])) or "-"
        flag_names = decode_match_flag_set(entry["flags"]) or "-"
        categories = ";".join(sorted(entry["categories"])) or "-"
        print(
            f"{mac} level={ALERT_NAMES.get(entry['alert_level'], entry['alert_level'])} "
            f"max={entry['max_certainty']}% rssi={entry['best_rssi']} "
            f"events={entry['events']} alerts={entry['alerts']} "
            f"suppressed={entry['suppressed']} would_alert={entry['would_alert']} "
            f"uptime={hms_from_ms(entry['first_ms'])}-{hms_from_ms(entry['last_ms'])} "
            f"duration_ms={duration_ms(entry)}"
        )
        if start_clock:
            print(
                f"  clock={clock_text(start_clock, entry['first_ms'])}-"
                f"{clock_text(start_clock, entry['last_ms'])}"
            )
        print(f"  flags={flags} names={flag_names} category={categories} label={labels}")
        if entry["first_gps"] or entry["last_gps"]:
            print(f"  gps first={entry['first_gps'] or '-'} last={entry['last_gps'] or '-'}")

    wifi_sightings = args.sightings
    if not wifi_sightings:
        candidate = default_sibling(args.csv_path, "wifi_sightings.csv")
        if os.path.exists(candidate):
            wifi_sightings = candidate
    if wifi_sightings:
        summarize_wifi_sightings(wifi_sightings, detected_macs, args.top, start_clock, selected_session)

    ble_sightings = args.ble_sightings
    if not ble_sightings:
        candidate = default_sibling(args.csv_path, "ble_sightings.csv")
        if os.path.exists(candidate):
            ble_sightings = candidate
    if ble_sightings:
        summarize_ble_sightings(ble_sightings, detected_macs, args.top, start_clock, selected_session)

    if args.near_time:
        if not start_clock:
            print("\n--near-time requires --start-time so clock time can be converted to uptime.")
        else:
            summarize_time_windows(
                args.csv_path,
                wifi_sightings,
                ble_sightings,
                start_clock,
                args.near_time,
                args.window_seconds,
                selected_session,
                detected_macs,
            )


def summarize_wifi_sightings(path, detected_macs, top, start_clock=None, session_id="latest"):
    sightings = defaultdict(lambda: {
        "events": 0,
        "first_ms": None,
        "last_ms": None,
        "best_rssi": -128,
        "channels": set(),
        "roles": set(),
        "ssids": set(),
        "wildcards": 0,
        "first_gps": "",
        "last_gps": "",
    })

    try:
        for row in filter_session(load_rows(path), session_id):
                mac = normalize_mac(row.get("mac"))
                if not mac:
                    continue
                entry = sightings[mac]
                ms = row_ms(row)
                rssi = as_int(row.get("rssi"), -128)
                entry["events"] += 1
                if entry["first_ms"] is None or ms < entry["first_ms"]:
                    entry["first_ms"] = ms
                    entry["first_gps"] = gps_text(row)
                if entry["last_ms"] is None or ms > entry["last_ms"]:
                    entry["last_ms"] = ms
                    entry["last_gps"] = gps_text(row)
                entry["best_rssi"] = max(entry["best_rssi"], rssi)
                if row.get("channel"):
                    entry["channels"].add(row["channel"])
                if row.get("role"):
                    entry["roles"].add(row["role"])
                if row.get("ssid"):
                    entry["ssids"].add(row["ssid"])
                if row.get("wildcard_ssid") == "1":
                    entry["wildcards"] += 1
    except FileNotFoundError:
        print(f"\nWiFi sightings file not found: {path}")
        return

    print()
    print("Strong raw-only WiFi sightings")
    print("------------------------------")
    raw_only = [(mac, entry) for mac, entry in sightings.items() if mac not in detected_macs]
    ranked = sorted(
        raw_only,
        key=lambda item: (item[1]["best_rssi"], item[1]["events"], duration_ms(item[1])),
        reverse=True,
    )
    if not ranked:
        print("No raw-only WiFi MACs found.")
        return

    print("RAW_ONLY means the MAC was seen in wifi_sightings.csv but did not become a detector target.")
    for mac, entry in ranked[:top]:
        roles = ";".join(sorted(entry["roles"])) or "-"
        channels = ";".join(sorted(entry["channels"])) or "-"
        ssids = ";".join(sorted(entry["ssids"])) or "-"
        print(
            f"{mac} rssi={entry['best_rssi']} events={entry['events']} "
            f"uptime={hms_from_ms(entry['first_ms'])}-{hms_from_ms(entry['last_ms'])} "
            f"duration_ms={duration_ms(entry)} roles={roles} ch={channels} "
            f"wildcards={entry['wildcards']}"
        )
        if start_clock:
            print(
                f"  clock={clock_text(start_clock, entry['first_ms'])}-"
                f"{clock_text(start_clock, entry['last_ms'])}"
            )
        print(f"  ssid={ssids}")
        if entry["first_gps"] or entry["last_gps"]:
            print(f"  gps first={entry['first_gps'] or '-'} last={entry['last_gps'] or '-'}")


def summarize_ble_sightings(path, detected_macs, top, start_clock=None, session_id="latest"):
    sightings = defaultdict(lambda: {
        "events": 0,
        "first_ms": None,
        "last_ms": None,
        "best_rssi": -128,
        "names": set(),
        "manufacturers": set(),
        "uuids": set(),
        "first_gps": "",
        "last_gps": "",
    })

    try:
        for row in filter_session(load_rows(path), session_id):
                mac = normalize_mac(row.get("mac"))
                if not mac:
                    continue
                entry = sightings[mac]
                ms = row_ms(row)
                rssi = as_int(row.get("rssi"), -128)
                entry["events"] += 1
                if entry["first_ms"] is None or ms < entry["first_ms"]:
                    entry["first_ms"] = ms
                    entry["first_gps"] = gps_text(row)
                if entry["last_ms"] is None or ms > entry["last_ms"]:
                    entry["last_ms"] = ms
                    entry["last_gps"] = gps_text(row)
                entry["best_rssi"] = max(entry["best_rssi"], rssi)
                if row.get("name"):
                    entry["names"].add(row["name"])
                if row.get("manufacturer_id"):
                    entry["manufacturers"].add(row["manufacturer_id"])
                if row.get("service_uuid"):
                    entry["uuids"].add(row["service_uuid"])
    except FileNotFoundError:
        print(f"\nBLE sightings file not found: {path}")
        return

    print()
    print("Strong raw-only BLE sightings")
    print("-----------------------------")
    raw_only = [(mac, entry) for mac, entry in sightings.items() if mac not in detected_macs]
    ranked = sorted(
        raw_only,
        key=lambda item: (item[1]["best_rssi"], item[1]["events"], duration_ms(item[1])),
        reverse=True,
    )
    if not ranked:
        print("No raw-only BLE MACs found.")
        return

    for mac, entry in ranked[:top]:
        names = ";".join(sorted(entry["names"])) or "-"
        manufacturers = ";".join(sorted(entry["manufacturers"])) or "-"
        uuids = ";".join(sorted(entry["uuids"])) or "-"
        print(
            f"{mac} rssi={entry['best_rssi']} events={entry['events']} "
            f"uptime={hms_from_ms(entry['first_ms'])}-{hms_from_ms(entry['last_ms'])} "
            f"duration_ms={duration_ms(entry)} name={names} "
            f"mfg={manufacturers} uuid={uuids}"
        )
        if start_clock:
            print(
                f"  clock={clock_text(start_clock, entry['first_ms'])}-"
                f"{clock_text(start_clock, entry['last_ms'])}"
            )
        if entry["first_gps"] or entry["last_gps"]:
            print(f"  gps first={entry['first_gps'] or '-'} last={entry['last_gps'] or '-'}")


def summarize_time_windows(field_path, wifi_path, ble_path, start_clock, near_times, window_seconds,
                           session_id, detected_macs):
    print()
    print("Time windows")
    print("------------")
    for near in near_times:
        target_clock = parse_clock(near, reference=start_clock)
        target_ms = int((target_clock - start_clock).total_seconds() * 1000)
        low_ms = target_ms - (window_seconds * 1000)
        high_ms = target_ms + (window_seconds * 1000)
        print(
            f"{near} => uptime {hms_from_ms(target_ms)} "
            f"(+/- {window_seconds}s)"
        )
        print_window_rows(field_path, "field", low_ms, high_ms, start_clock, session_id, detected_macs)
        if wifi_path:
            print_window_rows(wifi_path, "wifi", low_ms, high_ms, start_clock, session_id, detected_macs)
        if ble_path:
            print_window_rows(ble_path, "ble", low_ms, high_ms, start_clock, session_id, detected_macs)


def print_window_rows(path, kind, low_ms, high_ms, start_clock, session_id, detected_macs):
    try:
        rows = [
            row for row in filter_session(load_rows(path), session_id)
            if low_ms <= row_ms(row) <= high_ms
        ]
    except FileNotFoundError:
        return

    if not rows:
        print(f"  {kind}: no rows")
        return

    print(f"  {kind}: {len(rows)} rows")
    if kind in ("wifi", "ble"):
        print_window_mac_summary(rows, kind, start_clock, detected_macs)
    for row in rows[:40]:
        ms = row_ms(row)
        prefix = f"    {hms_from_ms(ms)} {clock_text(start_clock, ms)}"
        if kind == "field":
            event = row.get("event", "")
            if event not in ("threat", "alert", "alert_suppressed", "clear", "status"):
                continue
            flag_names = decode_match_flags(row.get("match_flags")) or "-"
            print(
                f"{prefix} {event} mac={normalize_mac(row.get('mac')) or '-'} "
                f"rssi={row.get('rssi', '') or '-'} conf={row.get('certainty', '') or '-'} "
                f"level={row.get('alert_level', '') or '-'} flags={row.get('match_flags', '') or '-'} "
                f"names={flag_names} label={row.get('identifier', '') or '-'}"
            )
        elif kind == "wifi":
            print(
                f"{prefix} wifi mac={normalize_mac(row.get('mac')) or '-'} "
                f"role={row.get('role', '') or '-'} rssi={row.get('rssi', '') or '-'} "
                f"ch={row.get('channel', '') or '-'} ssid={row.get('ssid', '') or '-'}"
            )
        else:
            print(
                f"{prefix} ble mac={normalize_mac(row.get('mac')) or '-'} "
                f"rssi={row.get('rssi', '') or '-'} name={row.get('name', '') or '-'} "
                f"mfg={row.get('manufacturer_id', '') or '-'} uuid={row.get('service_uuid', '') or '-'}"
            )
    if len(rows) > 40:
        print(f"    ... {len(rows) - 40} more rows in this window")


def print_window_mac_summary(rows, kind, start_clock, detected_macs):
    grouped = defaultdict(lambda: {
        "events": 0,
        "first_ms": None,
        "last_ms": None,
        "best_rssi": -128,
        "roles": set(),
        "channels": set(),
        "labels": set(),
    })
    for row in rows:
        mac = normalize_mac(row.get("mac"))
        if not mac:
            continue
        entry = grouped[mac]
        ms = row_ms(row)
        entry["events"] += 1
        entry["first_ms"] = ms if entry["first_ms"] is None else min(entry["first_ms"], ms)
        entry["last_ms"] = ms if entry["last_ms"] is None else max(entry["last_ms"], ms)
        entry["best_rssi"] = max(entry["best_rssi"], as_int(row.get("rssi"), -128))
        if row.get("role"):
            entry["roles"].add(row["role"])
        if row.get("channel"):
            entry["channels"].add(row["channel"])
        label = row.get("ssid") or row.get("name") or row.get("manufacturer_id") or row.get("service_uuid")
        if label:
            entry["labels"].add(label)

    ranked = sorted(
        grouped.items(),
        key=lambda item: (item[1]["events"], item[1]["best_rssi"], duration_ms(item[1])),
        reverse=True,
    )
    if not ranked:
        return
    print("    repeated MAC summary:")
    for mac, entry in ranked[:15]:
        status = "DETECTED" if mac in detected_macs else "RAW_ONLY"
        labels = ";".join(sorted(entry["labels"])) or "-"
        roles = ";".join(sorted(entry["roles"])) or "-"
        channels = ";".join(sorted(entry["channels"])) or "-"
        print(
            f"      {mac} {status} {mac_kind(mac)} rssi={entry['best_rssi']} "
            f"events={entry['events']} clock={clock_text(start_clock, entry['first_ms'])}-"
            f"{clock_text(start_clock, entry['last_ms'])} roles={roles} ch={channels} "
            f"label={labels[:80]}"
        )


def gps_text(row):
    if row.get("gps_fix") != "1":
        return ""
    lat = row.get("lat", "")
    lon = row.get("lon", "")
    if not lat or not lon:
        return ""
    geo = row.get("geo_status", "")
    dist = row.get("geo_distance_m", "")
    suffix = f" {geo}" if geo else ""
    if dist:
        suffix += f" {dist}m"
    return f"{lat},{lon}{suffix}"


if __name__ == "__main__":
    main()
