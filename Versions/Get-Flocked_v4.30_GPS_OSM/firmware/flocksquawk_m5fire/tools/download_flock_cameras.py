#!/usr/bin/env python3
"""
Download Flock Safety / ALPR camera coordinates from OpenStreetMap Overpass.

Examples:
  python download_flock_cameras.py --bbox "SOUTH,WEST,NORTH,EAST" --output cameras.txt
  python download_flock_cameras.py --place "Example City" --output cameras.txt
  python download_flock_cameras.py --around "LATITUDE,LONGITUDE,METERS" --output cameras.txt
  python download_flock_cameras.py --place "Example Region" --search all-alpr --tile-size 0.5 --output local_all_alpr_cameras.txt

The default output block intentionally matches this OSM-style example:

ALPR Camera

ID: sample001
Made byFlock Safety
Zonetraffic
CoordsLATITUDE, LONGITUDE
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_OVERPASS_URL = "https://overpass-api.de/api/interpreter"
DEFAULT_NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
DEFAULT_USER_AGENT = "flock-camera-osm-export/1.0"
FLOCK_WIKIDATA_IDS = {"Q108485435", "Q115167664"}


@dataclass(frozen=True)
class Camera:
    element_type: str
    element_id: int
    lat: float
    lon: float
    tags: dict[str, str]


@dataclass(frozen=True)
class Region:
    bbox: tuple[float, float, float, float] | None
    area_id: int | None = None
    around: tuple[float, float, float] | None = None


@dataclass(frozen=True)
class QueryRegion:
    filter: str
    bbox: tuple[float, float, float, float] | None = None
    row: int | None = None
    col: int | None = None


def parse_csv_floats(value: str, expected: int, label: str) -> list[float]:
    parts = [part.strip() for part in value.split(",")]
    if len(parts) != expected:
        raise argparse.ArgumentTypeError(
            f"{label} must contain {expected} comma-separated numbers"
        )
    try:
        return [float(part) for part in parts]
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{label} contains a non-number") from exc


def parse_bbox(value: str) -> tuple[float, float, float, float]:
    south, west, north, east = parse_csv_floats(value, 4, "--bbox")
    if south >= north:
        raise argparse.ArgumentTypeError("--bbox south must be less than north")
    if west >= east:
        raise argparse.ArgumentTypeError("--bbox west must be less than east")
    if not (-90 <= south <= 90 and -90 <= north <= 90):
        raise argparse.ArgumentTypeError("--bbox latitude values must be -90..90")
    if not (-180 <= west <= 180 and -180 <= east <= 180):
        raise argparse.ArgumentTypeError("--bbox longitude values must be -180..180")
    return south, west, north, east


def parse_around(value: str) -> tuple[float, float, float]:
    lat, lon, meters = parse_csv_floats(value, 3, "--around")
    if not (-90 <= lat <= 90):
        raise argparse.ArgumentTypeError("--around latitude must be -90..90")
    if not (-180 <= lon <= 180):
        raise argparse.ArgumentTypeError("--around longitude must be -180..180")
    if meters <= 0:
        raise argparse.ArgumentTypeError("--around radius must be greater than 0")
    return lat, lon, meters


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than 0")
    return parsed


def non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a number") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be 0 or greater")
    return parsed


def non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be 0 or greater")
    return parsed


def http_get_json(url: str, params: dict[str, str], user_agent: str, timeout: int) -> object:
    query = urllib.parse.urlencode(params)
    request = urllib.request.Request(
        f"{url}?{query}",
        headers={"User-Agent": user_agent, "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def http_post_overpass(
    url: str, query: str, user_agent: str, timeout: int
) -> dict[str, object]:
    payload = urllib.parse.urlencode({"data": query}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "User-Agent": user_agent,
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout + 30) as response:
        return json.loads(response.read().decode("utf-8"))


def place_region(
    place: str,
    nominatim_url: str,
    user_agent: str,
    timeout: int,
    email: str | None,
) -> Region:
    params = {"format": "jsonv2", "limit": "1", "q": place}
    if email:
        params["email"] = email

    data = http_get_json(nominatim_url, params, user_agent, timeout)
    if not isinstance(data, list) or not data:
        raise RuntimeError(f"Nominatim could not find a bounding box for {place!r}")

    result = data[0]
    bbox = result.get("boundingbox")
    if not isinstance(bbox, list) or len(bbox) != 4:
        raise RuntimeError(f"Nominatim returned no usable bounding box for {place!r}")

    south, north, west, east = [float(part) for part in bbox]
    area_id = None
    osm_type = str(result.get("osm_type", "")).lower()
    osm_id = result.get("osm_id")
    if osm_type == "relation" and isinstance(osm_id, int):
        area_id = 3_600_000_000 + osm_id
    elif osm_type == "way" and isinstance(osm_id, int):
        area_id = 2_400_000_000 + osm_id

    return Region(bbox=(south, west, north, east), area_id=area_id)


def resolve_region(args: argparse.Namespace) -> Region:
    if args.bbox:
        return Region(bbox=args.bbox)
    if args.around:
        return Region(bbox=None, around=args.around)
    if args.place:
        region = place_region(
            args.place,
            args.nominatim_url,
            args.user_agent,
            args.http_timeout,
            args.email,
        )
        if not region.bbox:
            raise RuntimeError(f"Nominatim returned no usable bounding box for {args.place!r}")
        south, west, north, east = region.bbox
        area_note = f", area id {region.area_id}" if region.area_id else ""
        print(
            f"Resolved {args.place!r} to bbox "
            f"{south:.6f},{west:.6f},{north:.6f},{east:.6f}{area_note}",
            file=sys.stderr,
        )
        return region

    raise RuntimeError("Choose one region option: --bbox, --place, or --around")


def bbox_region_filter(bbox: tuple[float, float, float, float]) -> str:
    south, west, north, east = bbox
    return f"({south:.7f},{west:.7f},{north:.7f},{east:.7f})"


def around_region_filter(around: tuple[float, float, float]) -> str:
    lat, lon, meters = around
    return f"(around:{meters:.2f},{lat:.7f},{lon:.7f})"


def split_bbox(
    bbox: tuple[float, float, float, float],
    tile_size: float,
) -> list[tuple[tuple[float, float, float, float], int, int]]:
    south, west, north, east = bbox
    tiles: list[tuple[tuple[float, float, float, float], int, int]] = []
    current_south = south
    row = 0
    while current_south < north:
        current_north = min(current_south + tile_size, north)
        current_west = west
        col = 0
        while current_west < east:
            current_east = min(current_west + tile_size, east)
            tile = (current_south, current_west, current_north, current_east)
            tiles.append((tile, row, col))
            current_west = current_east
            col += 1
        current_south = current_north
        row += 1
    return tiles


def query_regions(region: Region, tile_size: float) -> list[QueryRegion]:
    if region.around:
        if tile_size:
            print("--tile-size is ignored when --around is used", file=sys.stderr)
        return [QueryRegion(filter=around_region_filter(region.around))]

    if not region.bbox:
        raise RuntimeError("No usable region was provided")

    if tile_size <= 0:
        return [QueryRegion(filter=bbox_region_filter(region.bbox), bbox=region.bbox)]

    return [
        QueryRegion(filter=bbox_region_filter(tile), bbox=tile, row=row, col=col)
        for tile, row, col in split_bbox(region.bbox, tile_size)
    ]


def selector(
    tag_filters: Iterable[str],
    region_filter: str,
    area_filter: str,
    element_type: str,
) -> str:
    filters = "".join(tag_filters)
    return f"  {element_type}{filters}{region_filter}{area_filter};"


def build_query(
    region_filter: str,
    search_mode: str,
    timeout: int,
    area_id: int | None = None,
    element_type: str = "node",
) -> str:
    alpr_filter = '["surveillance:type"~"(^|;)ALPR($|;)",i]'
    base_filter = '["man_made"="surveillance"]'
    area_filter = "(area.searchArea)" if area_id else ""
    flock_filters = [
        '["manufacturer"~"flock",i]',
        '["brand"~"flock",i]',
        '["operator"~"flock",i]',
        '["name"~"flock",i]',
        '["model"~"flock|falcon",i]',
        '["manufacturer:wikidata"~"Q108485435|Q115167664"]',
    ]

    lines: list[str] = []

    if search_mode == "all-alpr":
        lines.append(selector([base_filter, alpr_filter], region_filter, area_filter, element_type))
        lines.append(selector([base_filter, '["camera:type"~"ALPR",i]'], region_filter, area_filter, element_type))
        lines.append(selector([base_filter, '["surveillance"~"ANPR|license_plate_scanner",i]'], region_filter, area_filter, element_type))
    elif search_mode == "broad-flock":
        for flock_filter in flock_filters:
            lines.append(selector([base_filter, flock_filter], region_filter, area_filter, element_type))
    else:
        for flock_filter in flock_filters:
            lines.append(selector([base_filter, alpr_filter, flock_filter], region_filter, area_filter, element_type))

    query_lines = [f"[out:json][timeout:{timeout}];"]
    if area_id:
        query_lines.append(f"area(id:{area_id})->.searchArea;")
    query_lines.extend(["(", *lines, ");", "out body center qt;"])
    return "\n".join(query_lines)


def element_coords(element: dict[str, object]) -> tuple[float, float] | None:
    if "lat" in element and "lon" in element:
        return float(element["lat"]), float(element["lon"])
    center = element.get("center")
    if isinstance(center, dict) and "lat" in center and "lon" in center:
        return float(center["lat"]), float(center["lon"])
    return None


def cameras_from_overpass(data: dict[str, object]) -> list[Camera]:
    elements = data.get("elements")
    if not isinstance(elements, list):
        raise RuntimeError("Overpass response did not contain an elements list")

    cameras_by_key: dict[tuple[str, int], Camera] = {}
    for element in elements:
        if not isinstance(element, dict):
            continue

        element_type = str(element.get("type", "node"))
        element_id = element.get("id")
        coords = element_coords(element)
        if not isinstance(element_id, int) or coords is None:
            continue

        raw_tags = element.get("tags", {})
        tags = {
            str(key): str(value)
            for key, value in raw_tags.items()
        } if isinstance(raw_tags, dict) else {}

        cameras_by_key[(element_type, element_id)] = Camera(
            element_type=element_type,
            element_id=element_id,
            lat=coords[0],
            lon=coords[1],
            tags=tags,
        )

    return sorted(
        cameras_by_key.values(),
        key=lambda camera: (camera.lat, camera.lon, camera.element_type, camera.element_id),
    )


def display_manufacturer(tags: dict[str, str]) -> str:
    for key in ("manufacturer", "brand"):
        if tags.get(key):
            return tags[key]

    wikidata = tags.get("manufacturer:wikidata", "")
    if any(item in FLOCK_WIKIDATA_IDS for item in wikidata.replace(";", " ").split()):
        return "Flock Safety"

    for key in ("operator", "name", "model"):
        if "flock" in tags.get(key, "").lower():
            return tags[key]

    return "Unknown"


def display_zone(tags: dict[str, str]) -> str:
    for key in ("surveillance:zone", "zone", "surveillance"):
        if tags.get(key):
            return tags[key]
    return "Unknown"


def display_title(tags: dict[str, str]) -> str:
    kind = tags.get("surveillance:type") or tags.get("camera:type") or "ALPR"
    if "ALPR" in kind.upper() or "ANPR" in kind.upper():
        return "ALPR Camera"
    return f"{kind} Camera"


def format_camera(camera: Camera, exact_prefixes: bool) -> str:
    title = display_title(camera.tags)
    made_by = display_manufacturer(camera.tags)
    zone = display_zone(camera.tags)

    if exact_prefixes:
        return "\n".join(
            [
                title,
                "",
                f"ID: {camera.element_id}",
                f"Made by{made_by}",
                f"Zone{zone}",
                f"Coords{camera.lat:.5f}, {camera.lon:.5f}",
            ]
        )

    return "\n".join(
        [
            title,
            "",
            f"ID: {camera.element_id}",
            f"Made by: {made_by}",
            f"Zone: {zone}",
            f"Coords: {camera.lat:.5f}, {camera.lon:.5f}",
        ]
    )


def write_camera_file(path: Path, cameras: list[Camera], exact_prefixes: bool) -> None:
    blocks = [format_camera(camera, exact_prefixes) for camera in cameras]
    text = "\n\n".join(blocks)
    if text:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def progress_bar(completed: int, total: int, width: int = 34) -> str:
    if total <= 0:
        return "[" + "-" * width + "]"
    filled = round(width * completed / total)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def draw_progress(
    regions: list[QueryRegion],
    statuses: list[str],
    message: str,
    unique_count: int,
    show_map: bool,
) -> None:
    total = len(statuses)
    completed = sum(1 for status in statuses if status in {"done", "error"})
    percent = (completed / total * 100) if total else 100.0
    print("", file=sys.stderr)
    print(message, file=sys.stderr)
    print(
        f"{progress_bar(completed, total)} {completed}/{total} "
        f"tiles checked ({percent:5.1f}%) | {unique_count} unique cameras",
        file=sys.stderr,
    )

    tile_regions = [
        (index, region)
        for index, region in enumerate(regions)
        if region.row is not None and region.col is not None
    ]
    if not show_map or not tile_regions:
        return

    max_row = max(region.row for _, region in tile_regions if region.row is not None)
    max_col = max(region.col for _, region in tile_regions if region.col is not None)
    grid = [["." for _ in range(max_col + 1)] for _ in range(max_row + 1)]
    chars = {"pending": ".", "running": ">", "done": "#", "error": "x"}

    for index, region in tile_regions:
        if region.row is None or region.col is None:
            continue
        grid[region.row][region.col] = chars.get(statuses[index], "?")

    print("Map: north is up, west-to-east is left-to-right", file=sys.stderr)
    for row in range(max_row, -1, -1):
        print("".join(grid[row]), file=sys.stderr)
    print("Legend: # done  > current  . waiting  x failed", file=sys.stderr)


def fetch_overpass_with_retries(
    args: argparse.Namespace,
    query: str,
    tile_label: str,
) -> dict[str, object]:
    last_error: Exception | None = None
    for attempt in range(args.retries + 1):
        try:
            return http_post_overpass(
                args.overpass_url,
                query,
                args.user_agent,
                args.overpass_timeout,
            )
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt >= args.retries:
                break
            wait_seconds = args.retry_delay * (attempt + 1)
            print(
                f"{tile_label} failed ({exc}); retrying in {wait_seconds:.1f}s",
                file=sys.stderr,
            )
            time.sleep(wait_seconds)

    if last_error:
        raise last_error
    raise RuntimeError(f"{tile_label} failed without a reported error")


def fetch_all_cameras(args: argparse.Namespace, region: Region) -> list[Camera]:
    regions = query_regions(region, args.tile_size)
    area_id = None if args.no_place_area else region.area_id
    element_type = "nwr" if args.include_ways_relations else "node"
    cameras_by_key: dict[tuple[str, int], Camera] = {}
    total_tiles = len(regions)
    statuses = ["pending"] * total_tiles
    show_map = not args.no_progress_map

    for index, query_region in enumerate(regions, start=1):
        query = build_query(
            query_region.filter,
            args.search,
            args.overpass_timeout,
            area_id=area_id,
            element_type=element_type,
        )
        if args.print_query:
            print(query, file=sys.stderr)

        tile_label = f"Tile {index}/{total_tiles}" if total_tiles > 1 else "Query"
        statuses[index - 1] = "running"
        draw_progress(
            regions,
            statuses,
            f"{tile_label}: requesting {query_region.filter}",
            len(cameras_by_key),
            show_map=show_map,
        )
        try:
            data = fetch_overpass_with_retries(args, query, tile_label)
        except Exception:
            statuses[index - 1] = "error"
            draw_progress(
                regions,
                statuses,
                f"{tile_label}: failed after retries",
                len(cameras_by_key),
                show_map=show_map,
            )
            raise

        tile_cameras = cameras_from_overpass(data)
        for camera in tile_cameras:
            cameras_by_key[(camera.element_type, camera.element_id)] = camera
        statuses[index - 1] = "done"
        draw_progress(
            regions,
            statuses,
            f"{tile_label}: {len(tile_cameras)} returned, "
            f"{len(cameras_by_key)} unique total",
            len(cameras_by_key),
            show_map=show_map,
        )
        if args.tile_size and args.tile_delay and index < total_tiles:
            time.sleep(args.tile_delay)

    return sorted(
        cameras_by_key.values(),
        key=lambda camera: (camera.lat, camera.lon, camera.element_type, camera.element_id),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Download OSM/DeFlock-style Flock Safety camera coordinates to TXT.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Region formats:\n"
            '  --bbox "south,west,north,east"\n'
            "  --place \"City, State\"  (uses Nominatim once to get a bbox)\n"
            '  --around "lat,lon,meters"\n\n'
            "Search modes:\n"
            "  flock        Flock-tagged ALPR cameras only (default)\n"
            "  all-alpr     any OSM ALPR/ANPR camera in the region\n"
            "  broad-flock  any surveillance node tagged as Flock, even if not ALPR-tagged\n"
        ),
    )

    region = parser.add_mutually_exclusive_group(required=True)
    region.add_argument("--bbox", type=parse_bbox, help="Bounding box: south,west,north,east")
    region.add_argument("--place", help='Place name, e.g. "Example City"')
    region.add_argument("--around", type=parse_around, help="Circle: lat,lon,radius_meters")

    parser.add_argument(
        "--search",
        choices=("flock", "all-alpr", "broad-flock"),
        default="flock",
        help="What to search for in OSM tags. Default: flock",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("flock_cameras.txt"),
        help="TXT file to write. Default: flock_cameras.txt",
    )
    parser.add_argument(
        "--tile-size",
        type=positive_float,
        default=0.0,
        help=(
            "Split bbox/place regions into degree-sized tiles to avoid Overpass 504s. "
            "Try 0.5 for a whole state. Default: off"
        ),
    )
    parser.add_argument(
        "--retries",
        type=non_negative_int,
        default=2,
        help="Retry each Overpass tile this many times after a temporary failure. Default: 2",
    )
    parser.add_argument(
        "--retry-delay",
        type=positive_float,
        default=10.0,
        help="Seconds to wait between tile retries. Default: 10",
    )
    parser.add_argument(
        "--tile-delay",
        type=non_negative_float,
        default=2.0,
        help="Seconds to pause between successful tiled Overpass requests. Default: 2",
    )
    parser.add_argument(
        "--no-place-area",
        action="store_true",
        help="For --place, use only the bounding box instead of the OSM area boundary.",
    )
    parser.add_argument(
        "--include-ways-relations",
        action="store_true",
        help="Query OSM ways/relations too. Slower; camera data is normally stored as nodes.",
    )
    parser.add_argument(
        "--no-progress-map",
        action="store_true",
        help="Hide the PowerShell progress bar and tile map.",
    )
    parser.add_argument(
        "--pretty-labels",
        action="store_true",
        help="Use labels like 'Made by: Flock Safety' instead of the exact prefix style.",
    )
    parser.add_argument(
        "--overpass-url",
        default=DEFAULT_OVERPASS_URL,
        help=f"Overpass endpoint. Default: {DEFAULT_OVERPASS_URL}",
    )
    parser.add_argument(
        "--nominatim-url",
        default=DEFAULT_NOMINATIM_URL,
        help=f"Nominatim endpoint used by --place. Default: {DEFAULT_NOMINATIM_URL}",
    )
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="HTTP User-Agent to send to OSM services.",
    )
    parser.add_argument(
        "--email",
        help="Optional contact email for Nominatim requests.",
    )
    parser.add_argument(
        "--overpass-timeout",
        type=int,
        default=180,
        help="Overpass query timeout in seconds. Default: 180",
    )
    parser.add_argument(
        "--http-timeout",
        type=int,
        default=30,
        help="HTTP connection timeout in seconds. Default: 30",
    )
    parser.add_argument(
        "--print-query",
        action="store_true",
        help="Print the generated Overpass query before running it.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        region = resolve_region(args)
        started = time.time()
        cameras = fetch_all_cameras(args, region)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_camera_file(args.output, cameras, exact_prefixes=not args.pretty_labels)

        elapsed = time.time() - started
        print(f"Wrote {len(cameras)} cameras to {args.output} in {elapsed:.1f}s")
        print("Data source: OpenStreetMap via Overpass API", file=sys.stderr)
        return 0
    except urllib.error.HTTPError as exc:
        print(f"HTTP error {exc.code}: {exc.reason}", file=sys.stderr)
    except urllib.error.URLError as exc:
        print(f"Network error: {exc.reason}", file=sys.stderr)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
