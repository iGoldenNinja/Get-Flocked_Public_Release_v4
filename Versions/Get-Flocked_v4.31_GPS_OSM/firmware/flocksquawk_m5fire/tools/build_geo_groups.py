#!/usr/bin/env python3
"""Build grouped GPS geofence CSVs for the M5Stack SD card.

The input files are plain text camera exports such as
north_carolina_all_alpr_cameras.txt:

    ID: sample001
    Made byExample Source
    ZoneExample
    CoordsLATITUDE, LONGITUDE

Output files go into the sketch data folder so they can be copied to the SD
card root:

    data/geo_index.csv
    data/geo_groups/NC001.csv
"""

from __future__ import annotations

import argparse
import csv
import math
import re
from collections import defaultdict
from pathlib import Path


DEFAULT_CELL_DEGREES = 0.35
DEFAULT_GROUP_PAD_M = 3000.0
DEFAULT_TARGET_RADIUS_M = 300
EARTH_RADIUS_M = 6371000.0
STATE_CODES = {
    "connecticut": "CT",
    "delaware": "DE",
    "florida": "FL",
    "georgia": "GA",
    "maine": "ME",
    "maryland": "MD",
    "massachusetts": "MA",
    "new_hampshire": "NH",
    "new_jersey": "NJ",
    "new_york": "NY",
    "north_carolina": "NC",
    "rhode_island": "RI",
    "south_carolina": "SC",
    "virginia": "VA",
    "nc": "NC",
}


def distance_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2.0) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2.0) ** 2
    return EARTH_RADIUS_M * (2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a)))


def parse_camera_text(path: Path) -> list[dict[str, object]]:
    cameras: list[dict[str, object]] = []
    current_id: str | None = None
    current_zone = ""
    seen: set[tuple[str, str, str]] = set()

    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        id_match = re.match(r"ID:\s*(\S+)", line)
        if id_match:
            current_id = id_match.group(1)
            current_zone = ""
            continue

        zone_match = re.match(r"Zone\s*(.*)", line)
        if zone_match:
            current_zone = zone_match.group(1).strip() or "unknown"
            continue

        coord_match = re.match(
            r"Coords\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)",
            line,
        )
        if not coord_match:
            continue

        lat = float(coord_match.group(1))
        lon = float(coord_match.group(2))
        camera_id = current_id or f"cam{len(cameras) + 1:05d}"
        key = (camera_id, f"{lat:.6f}", f"{lon:.6f}")
        if key in seen:
            continue
        seen.add(key)
        cameras.append(
            {
                "id": camera_id,
                "lat": lat,
                "lon": lon,
                "zone": current_zone or "unknown",
            }
        )

    return cameras


def state_code_from_path(path: Path) -> str:
    name = path.stem.lower()
    for key in sorted(STATE_CODES, key=len, reverse=True):
        if name.startswith(key):
            return STATE_CODES[key]
    raise ValueError(f"Could not infer state code from filename: {path.name}")


def group_cameras(
    cameras: list[dict[str, object]],
    cell_degrees: float,
    state_code: str,
) -> list[dict[str, object]]:
    buckets: dict[tuple[int, int], list[dict[str, object]]] = defaultdict(list)
    for camera in cameras:
        key = (
            math.floor(float(camera["lat"]) / cell_degrees),
            math.floor(float(camera["lon"]) / cell_degrees),
        )
        buckets[key].append(camera)

    groups: list[dict[str, object]] = []
    for _, members in sorted(buckets.items()):
        center_lat = sum(float(c["lat"]) for c in members) / len(members)
        center_lon = sum(float(c["lon"]) for c in members) / len(members)
        farthest = max(distance_m(center_lat, center_lon, float(c["lat"]), float(c["lon"])) for c in members)
        groups.append(
            {
                "members": sorted(members, key=lambda c: (float(c["lat"]), float(c["lon"]), str(c["id"]))),
                "center_lat": center_lat,
                "center_lon": center_lon,
                "radius_m": int(math.ceil(farthest + DEFAULT_GROUP_PAD_M)),
            }
        )

    groups.sort(key=lambda g: (float(g["center_lat"]), float(g["center_lon"])))
    for index, group in enumerate(groups, start=1):
        group["state"] = state_code
        group["group_id"] = f"{state_code}{index:03d}"
        group["path"] = f"/geo_groups/{group['group_id']}.csv"
        group["label"] = f"{state_code}-{index:03d}"
    return groups


def write_outputs(groups: list[dict[str, object]], data_dir: Path, state_codes: set[str]) -> None:
    group_dir = data_dir / "geo_groups"
    group_dir.mkdir(parents=True, exist_ok=True)

    for state_code in state_codes:
        for old in group_dir.glob(f"{state_code}*.csv"):
            old.unlink()

    index_path = data_dir / "geo_index.csv"
    with index_path.open("w", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["state", "group_id", "center_lat", "center_lon", "radius_m", "count", "path", "label"])
        for group in sorted(groups, key=lambda g: (str(g["state"]), float(g["center_lat"]), float(g["center_lon"]))):
            writer.writerow(
                [
                    group["state"],
                    group["group_id"],
                    f"{float(group['center_lat']):.6f}",
                    f"{float(group['center_lon']):.6f}",
                    int(group["radius_m"]),
                    len(group["members"]),
                    group["path"],
                    group["label"],
                ]
            )

    for group in groups:
        out_path = group_dir / f"{group['group_id']}.csv"
        with out_path.open("w", newline="") as f:
            writer = csv.writer(f, lineterminator="\n")
            writer.writerow(["id", "lat", "lon", "radius_m", "label"])
            for camera in group["members"]:
                camera_id = str(camera["id"])
                label = f"{group['state']}-{camera_id[-5:]}"
                writer.writerow(
                    [
                        camera_id,
                        f"{float(camera['lat']):.6f}",
                        f"{float(camera['lon']):.6f}",
                        DEFAULT_TARGET_RADIUS_M,
                        label,
                    ]
                )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build grouped geofence CSVs from an OSM camera text export.")
    parser.add_argument("input", type=Path, nargs="+", help="Input text files, such as tools/*_all_alpr_cameras.txt")
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).resolve().parents[1] / "data")
    parser.add_argument("--cell-degrees", type=float, default=DEFAULT_CELL_DEGREES)
    args = parser.parse_args()

    all_groups: list[dict[str, object]] = []
    state_codes: set[str] = set()
    total_cameras = 0
    for input_path in args.input:
        state_code = state_code_from_path(input_path)
        cameras = parse_camera_text(input_path)
        if not cameras:
            raise SystemExit(f"No camera coordinates found in {input_path}")
        groups = group_cameras(cameras, args.cell_degrees, state_code)
        all_groups.extend(groups)
        state_codes.add(state_code)
        total_cameras += len(cameras)
        print(f"{state_code}: parsed {len(cameras)} cameras into {len(groups)} groups")

    write_outputs(all_groups, args.data_dir, state_codes)

    largest = max(len(g["members"]) for g in all_groups)
    print(f"Parsed {total_cameras} total cameras into {len(all_groups)} total groups")
    print(f"Largest group: {largest} cameras")
    print(f"Wrote {args.data_dir / 'geo_index.csv'}")
    print(f"Wrote {args.data_dir / 'geo_groups'}")


if __name__ == "__main__":
    main()
