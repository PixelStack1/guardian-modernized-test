import contextlib
import json
import re
import time
from pathlib import Path

import requests

from util.network import cidr_to_tuple, construct_cidr_block_set
from util.paths import data_file
from util.types import CIDR_BLOCK

# This file contains classes and methods to manage acquiring, parsing, and updating a possibly dynamic list of IP ranges
# that Guardian needs to be aware of. Such ranges include R* / T2 official IPs, as well as IPs that can be used for
# miscellaneous R* Services, such as Microsoft Azure.


class ScrapeError(Exception):
    """Could not scrape the HTML for data for some reason."""


# https://whois.ipip.net/AS202021
T2_EU_FALLBACK = {
    "185.56.64.0/24",
    "185.56.64.0/22",
    "185.56.65.0/24",
    "185.56.66.0/24",
    "185.56.67.0/24",
}

# https://whois.ipip.net/AS46555
T2_US_FALLBACK = {
    "104.255.104.0/24",
    "104.255.104.0/22",
    "104.255.105.0/24",
    "104.255.106.0/24",
    "104.255.107.0/24",
    "192.81.240.0/24",
    "192.81.240.0/22",
    "192.81.241.0/24",
    "192.81.242.0/24",
    "192.81.243.0/24",
    "192.81.244.0/24",
    "192.81.244.0/22",
    "192.81.245.0/24",
    "192.81.246.0/24",
    "192.81.247.0/24",
    "198.133.210.0/24",
}


MAX_AZURE_BYTES = 10 * 1024 * 1024
MAX_RIPE_BYTES = 1 * 1024 * 1024
MAX_PAGE_BYTES = 2 * 1024 * 1024


class ResponseTooLarge(Exception):
    """Remote response exceeded the configured size cap."""


def get_capped(url: str, max_bytes: int, **kwargs: object) -> bytes:
    """GET with stream=True, refusing bodies larger than max_bytes."""
    with requests.get(url, stream=True, **kwargs) as response:  # type: ignore[arg-type]
        response.raise_for_status()
        length = response.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > max_bytes:
            raise ResponseTooLarge(f"{url}: {length} bytes > {max_bytes}")
        chunks = []
        total = 0
        for chunk in response.iter_content(chunk_size=65536):
            total += len(chunk)
            if total > max_bytes:
                raise ResponseTooLarge(f"{url}: more than {max_bytes} bytes")
            chunks.append(chunk)
        return b"".join(chunks)


RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
AS_T2_EU = 202021
AS_T2_US = 46555


MAX_LIST_CHANGE_RATIO = 0.30


class ListRejected(ValueError):
    """A freshly downloaded IP list failed validation; the last good list is kept."""


def _cache_path(name: str, cache_dir: Path | None) -> Path:
    return (
        (cache_dir / f"cache_{name}.json")
        if cache_dir
        else data_file(f"cache_{name}.json")
    )


def load_cached_list(name: str, cache_dir: Path | None = None) -> set[str] | None:
    try:
        data = json.loads(_cache_path(name, cache_dir).read_text())
        prefixes = data["prefixes"]
        if not isinstance(prefixes, list) or not all(
            isinstance(x, str) for x in prefixes
        ):
            return None
        return set(prefixes)
    except Exception:
        return None


def validate_list(new: set[str], old: set[str] | None) -> None:
    """Raise ListRejected if new is empty, malformed, or differs from old by more than 30%."""
    if not new:
        raise ListRejected("empty list")
    for prefix in new:
        try:
            cidr_to_tuple(prefix)
        except (ValueError, IndexError, TypeError, AttributeError) as e:
            raise ListRejected(f"malformed prefix {prefix!r}") from e
    if old:
        ratio = len(old ^ new) / len(old)
        if ratio > MAX_LIST_CHANGE_RATIO:
            raise ListRejected(
                f"list changed by {ratio:.0%} (> {MAX_LIST_CHANGE_RATIO:.0%})"
            )


def accept_list(
    name: str, new: set[str] | None, fallback: set[str], cache_dir: Path | None = None
) -> set[str]:
    """Return new (and cache it) if valid, else the last good cached list, else fallback."""
    old = load_cached_list(name, cache_dir)
    if new is not None:
        try:
            validate_list(new, old)
        except ListRejected as e:
            print(f"WARNING: rejected new {name} list ({e}); keeping previous list.")
        else:
            with contextlib.suppress(OSError):
                _cache_path(name, cache_dir).write_text(
                    json.dumps({"saved": time.time(), "prefixes": sorted(new)})
                )
            return set(new)
    return set(old) if old else set(fallback)


def parse_ripe_prefixes(body: bytes | str) -> set[str]:
    """Parse a RIPEstat announced-prefixes answer; IPv4 only. Raises ValueError on bad structure."""
    try:
        entries = json.loads(body)["data"]["prefixes"]
        prefixes = {entry["prefix"] for entry in entries}
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"malformed RIPEstat answer: {e}") from e
    if not all(isinstance(p, str) for p in prefixes):
        raise ValueError("non-string prefix")
    return {p for p in prefixes if ":" not in p}  # Guardian is IPv4-only


def get_announced_prefixes(
    asn: int, fallback: set[str], timeout: float = 10, cache_dir: Path | None = None
) -> set[str]:
    """
    Query RIPEstat for the prefixes announced by an AS. Replaces the `prsw` library, which broke when
    RIPEstat added new fields to its responses (upstream issue #163). Never raises: any error or
    rejected list returns the last good cached list, else the static fallback.
    """
    new: set[str] | None
    try:
        body = get_capped(
            RIPESTAT_URL,
            MAX_RIPE_BYTES,
            params={"resource": f"AS{asn}"},
            headers={"User-Agent": "Guardian - GTA5 Firewall"},
            timeout=timeout,
        )
        new = parse_ripe_prefixes(body)
    except Exception:
        new = None
    return accept_list(f"ripe_AS{asn}", new, fallback, cache_dir)


def get_t2_ranges() -> set[str]:
    return get_announced_prefixes(AS_T2_EU, T2_EU_FALLBACK) | get_announced_prefixes(
        AS_T2_US, T2_US_FALLBACK
    )


# This URL should return information about the most up-to-date JSON file containing Azure IP ranges.
# Microsoft claims that a new file is published every 7 days, and that any new IPs will not be used for another 7 days.
# Note that we could also possibly manually generate the URL if necessary.
# I'm not very good at web development so idk what the best practice is for this lol
AZURE_GET_PUBLIC_CLOUD_URL = (
    "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
)
# The regex pattern to find download files on the page.
MICROSOFT_DOWNLOAD_REGEX = re.compile(
    r"https://download\.microsoft\.com/download[^\"]*\.json"
)


def determine_best_azure_file(urls: list[str]) -> tuple[str, bytes]:
    """
    Given multiple azure URLs, identify the best JSON file to return based on the largest changeNumber
    Returns the URL, and the contents of the JSON file as bytes
    """
    # Return only the JSON file with the highest changeNumber
    highest_change_number = 0
    best_response = b""
    best_url = ""
    for url in urls:
        content = get_capped(url, MAX_AZURE_BYTES, timeout=30)
        change_number = json.loads(content)["changeNumber"]
        if change_number > highest_change_number:
            highest_change_number = change_number
            best_response = content
            best_url = url
    return best_url, best_response


def get_azure_ip_ranges_download(
    page_to_search: str = AZURE_GET_PUBLIC_CLOUD_URL,
) -> tuple[str, bytes]:
    """
    Finds the URL to the most recent JSON file. I looked it up and yes, apparently, there is no actual API that allows
    requesting the most up-to-date ranges. We have to download the human-readable page, then parse / search through the
    HTML response to find the link.

    This method is *meant* to be comprehensive and robust enough to not break if Microsoft changes the HTML content of
    their pages. When this code was written, the download file occurred multiple times in the HTML page, but it was the
    only URL to match the regular expression.

    If multiple possibly valid files were found on the page, only the file with the highest changeNumber will be returned.
    """

    # Get the actual page.
    try:
        page = get_capped(
            page_to_search,
            MAX_PAGE_BYTES,
            headers={"User-Agent": "Guardian - GTA5 Firewall"},
            timeout=30,
        )

        # Search through the HTML for all download.microsoft.com JSON files.
        re_files = re.findall(MICROSOFT_DOWNLOAD_REGEX, str(page))
        if not re_files:
            raise ScrapeError(
                "Did not find any valid download URLs while searching the page."
            )

        files = list(set(re_files))
        return determine_best_azure_file(files)

    except (ScrapeError, ResponseTooLarge, requests.exceptions.RequestException) as e:
        # TODO: attempt to generate the URL manually.
        # TODO: Figure out what times (and timezones) Microsoft publish their IP ranges at.
        raise e


def azure_file_add_timestamp(azure_file_contents: bytes, filename: str) -> bytes:
    as_list = azure_file_contents.splitlines(True)
    # add timestamp and filename (should be formatted the same as the actual file)
    as_list.insert(1, f'  "acquiredFrom": "{filename}",\n'.encode())
    as_list.insert(1, f'  "acquiredWhen": "{time.time()}",\n'.encode())
    return b"".join(as_list)


def ipv4_only(ranges: list[str]) -> list[str]:
    return [r for r in ranges if ":" not in r]


def parse_azure_ip_ranges(azure_file_contents: bytes) -> list[str]:
    """Parse the Azure service-tags JSON. Raises ValueError on any malformed structure."""
    try:
        azure_cloud_json = json.loads(azure_file_contents)
        categories = azure_cloud_json["values"]
        arr_ranges = next(
            (
                cat["properties"]["addressPrefixes"]
                for cat in categories
                if cat["name"] == "AzureCloud"
            ),
            None,
        )
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise ValueError(f"malformed Azure file: {e}") from e
    if arr_ranges is None:
        raise ValueError("Could not find AzureCloud category in values array.")
    if not isinstance(arr_ranges, list) or not all(
        isinstance(r, str) for r in arr_ranges
    ):
        raise ValueError("addressPrefixes is not a list of strings")
    return list(arr_ranges)


def get_dynamic_blacklist(backup_file: str | None = None) -> set[CIDR_BLOCK]:
    # TODO: We can tell if the file has been updated by checking `changeNumber`, but that requires attempting
    # to download the file anyways. Ideally, we want to be able to skip trying to download all together because
    # the method isn't entirely reliable, and also fallback to the previously saved version if the download fails.

    backup_path = Path(backup_file) if backup_file else data_file("db.json")
    try:
        download_link, content = get_azure_ip_ranges_download()
        ranges = parse_azure_ip_ranges(content)
        previous = None
        if backup_path.is_file():
            with contextlib.suppress(Exception):
                previous = set(
                    ipv4_only(parse_azure_ip_ranges(backup_path.read_bytes()))
                )
        validate_list(
            set(ipv4_only(ranges)), previous
        )  # raises ListRejected -> keep backup
        backup_path.write_bytes(azure_file_add_timestamp(content, download_link))
    except Exception as e:
        print("ERROR: Could not parse Azure ranges from URL. Reason: ", e)
        if not backup_path.is_file():
            raise FileNotFoundError(
                f"ERROR: Could not find backup file {backup_path}."
            ) from e
        ranges = parse_azure_ip_ranges(backup_path.read_bytes())
    # R* / T2 ranges are always added, also when falling back to the Azure backup file
    # (upstream only added them on the success path).
    ranges.extend(get_t2_ranges())
    return construct_cidr_block_set(ranges)
