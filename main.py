import os
import time
import ipaddress
import requests

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List


# =========================================================
# ARGUSSCOPE
# High-Precision Intelligence Engine
# =========================================================

app = FastAPI(
    title="ArgusScope High-Precision Intelligence Engine",
    version="2.1.0"
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# ENVIRONMENT VARIABLES
# =========================================================

WIGLE_USER = os.getenv("WIGLE_API_USER", "")
WIGLE_TOKEN = os.getenv("WIGLE_API_KEY", "")


# =========================================================
# CACHE
# =========================================================

SEARCH_CACHE = {}

CACHE_TTL_SECONDS = 600
REQUEST_TIMEOUT = 15


# =========================================================
# DATA MODELS
# =========================================================

class ScanTarget(BaseModel):
    netid: str
    rssi: int = -70


class MultiBSSIDRequest(BaseModel):
    scans: List[ScanTarget]


# =========================================================
# HELPERS
# =========================================================

def sanitize_mac(mac: str) -> str:
    """
    Normalize a MAC/BSSID into lowercase colon-separated format.
    """
    return (
        mac
        .strip()
        .lower()
        .replace("-", ":")
    )


def is_valid_ip(ip: str) -> bool:
    """
    Validate IPv4/IPv6 address.
    """
    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False


# =========================================================
# ROOT / HEALTH CHECK
# =========================================================

@app.get("/")
def read_root():

    return {
        "status": "ArgusScope Advanced Recon Engine Online",

        "version": "2.1.0",

        "capabilities": [
            "Single BSSID Lookup",
            "IP Geolocation",
            "Multi-Point Centroid Fusion",
            "TTL Caching"
        ]
    }


# =========================================================
# BSSID LOOKUP
# =========================================================

@app.get("/api/v1/locate-bssid")
async def locate_bssid(netid: str):

    target_mac = sanitize_mac(netid)

    # -----------------------------------------------------
    # CACHE CHECK
    # -----------------------------------------------------

    now = time.time()

    if target_mac in SEARCH_CACHE:

        cached = SEARCH_CACHE[target_mac]

        if (
            now - cached["timestamp"]
            < CACHE_TTL_SECONDS
        ):

            result = cached["data"].copy()

            result["source"] = (
                "Cache (Optimized Memory)"
            )

            return result

        del SEARCH_CACHE[target_mac]


    # -----------------------------------------------------
    # CHECK WIGLE CREDENTIALS
    # -----------------------------------------------------

    if not WIGLE_USER or not WIGLE_TOKEN:

        return {
            "error":
            "WiGLE API credentials not configured "
            "on server backend."
        }


    # -----------------------------------------------------
    # WIGLE API
    # -----------------------------------------------------

    url = (
        "https://api.wigle.net/"
        "api/v2/network/search"
    )

    params = {

        "netid":
        target_mac,

        "resultsPerPage":
        1,

        "latrange1":
        -90.0,

        "latrange2":
        90.0,

        "longrange1":
        -180.0,

        "longrange2":
        180.0
    }

    headers = {

        "Accept":
        "application/json",

        "User-Agent":
        "ArgusScope/2.1"
    }


    try:

        response = requests.get(

            url,

            params=params,

            headers=headers,

            auth=(
                WIGLE_USER,
                WIGLE_TOKEN
            ),

            timeout=REQUEST_TIMEOUT
        )


        # -------------------------------------------------
        # RATE LIMIT
        # -------------------------------------------------

        if response.status_code == 429:

            return {
                "error":
                "WiGLE rate limit exceeded (429)."
            }


        # -------------------------------------------------
        # OTHER HTTP ERRORS
        # -------------------------------------------------

        if response.status_code != 200:

            return {
                "error":
                f"WiGLE API error: "
                f"HTTP {response.status_code}"
            }


        # -------------------------------------------------
        # SAFE JSON PARSING
        # -------------------------------------------------

        try:

            data = response.json()

        except ValueError:

            return {
                "error":
                "WiGLE returned an invalid JSON response."
            }


        # -------------------------------------------------
        # RESULTS
        # -------------------------------------------------

        if (
            data.get("success")
            and data.get("results")
        ):

            result = data["results"][0]


            latitude = result.get(
                "trilat"
            )

            longitude = result.get(
                "trilong"
            )


            if (
                latitude is None
                or longitude is None
            ):

                return {
                    "error":
                    "WiGLE returned a result "
                    "without coordinates."
                }


            # ---------------------------------------------
            # CONFIDENCE
            # ---------------------------------------------

            obs_count = result.get(
                "count",
                1
            )


            if obs_count > 40:

                radius = 12

                confidence = (
                    "High "
                    "(Dense Telemetry Cluster)"
                )


            elif obs_count > 5:

                radius = 25

                confidence = (
                    "Medium-High "
                    "(Standard Triangulation)"
                )


            else:

                radius = 50

                confidence = (
                    "Low-Medium "
                    "(Sparse Observation)"
                )


            # ---------------------------------------------
            # RESPONSE
            # ---------------------------------------------

            payload = {

                "bssid":
                result.get("netid"),

                "ssid":
                result.get(
                    "ssid",
                    "Unknown Network"
                ),

                "latitude":
                latitude,

                "longitude":
                longitude,

                "accuracy_radius_m":
                radius,

                "confidence":
                confidence,

                "observations":
                obs_count,

                "source":
                "WiGLE Live Database"
            }


            # ---------------------------------------------
            # SAVE CACHE
            # ---------------------------------------------

            SEARCH_CACHE[target_mac] = {

                "timestamp":
                now,

                "data":
                payload
            }


            return payload


        return {

            "error":
            "Target BSSID not cataloged "
            "in WiGLE database."
        }


    except requests.RequestException as exc:

        return {

            "error":
            f"WiGLE request failed: {str(exc)}"
        }


    except Exception as exc:

        return {

            "error":
            f"Internal routing failure: {str(exc)}"
        }


# =========================================================
# MULTI-BSSID TRIANGULATION
# =========================================================

@app.post("/api/v1/triangulate-cluster")
async def triangulate_cluster(
    payload: MultiBSSIDRequest
):

    # -----------------------------------------------------
    # CHECK CREDENTIALS
    # -----------------------------------------------------

    if not WIGLE_USER or not WIGLE_TOKEN:

        return {

            "error":
            "WiGLE API credentials not configured "
            "on server backend."
        }


    url = (
        "https://api.wigle.net/"
        "api/v2/network/search"
    )


    headers = {

        "Accept":
        "application/json",

        "User-Agent":
        "ArgusScope/2.1"
    }


    valid_points = []

    total_weight = 0


    # -----------------------------------------------------
    # PROCESS EACH BSSID
    # -----------------------------------------------------

    for scan in payload.scans:

        clean_mac = sanitize_mac(
            scan.netid
        )


        params = {

            "netid":
            clean_mac,

            "resultsPerPage":
            1,

            "latrange1":
            -90.0,

            "latrange2":
            90.0,

            "longrange1":
            -180.0,

            "longrange2":
            180.0
        }


        try:

            response = requests.get(

                url,

                params=params,

                headers=headers,

                auth=(
                    WIGLE_USER,
                    WIGLE_TOKEN
                ),

                timeout=REQUEST_TIMEOUT
            )


            if response.status_code != 200:

                continue


            # ---------------------------------------------
            # SAFE JSON PARSING
            # ---------------------------------------------

            try:

                data = response.json()

            except ValueError:

                continue


            if (
                data.get("success")
                and data.get("results")
            ):

                result = data["results"][0]


                latitude = result.get(
                    "trilat"
                )

                longitude = result.get(
                    "trilong"
                )


                if (
                    latitude is not None
                    and longitude is not None
                ):

                    # Stronger RSSI =
                    # greater weighting

                    weight = max(
                        1,
                        100 - abs(scan.rssi)
                    )


                    valid_points.append({

                        "lat":
                        float(latitude),

                        "lon":
                        float(longitude),

                        "weight":
                        weight
                    })


                    total_weight += weight


        except requests.RequestException:

            continue


        except Exception:

            continue


    # -----------------------------------------------------
    # NO RESULTS
    # -----------------------------------------------------

    if (
        not valid_points
        or total_weight <= 0
    ):

        return {

            "error":
            "No valid coordinates resolved "
            "from the provided BSSID cluster."
        }


    # -----------------------------------------------------
    # RSSI-WEIGHTED CENTROID
    # -----------------------------------------------------

    weighted_lat = (

        sum(
            point["lat"]
            * point["weight"]

            for point in valid_points
        )

        / total_weight
    )


    weighted_lon = (

        sum(
            point["lon"]
            * point["weight"]

            for point in valid_points
        )

        / total_weight
    )


    # -----------------------------------------------------
    # RESPONSE
    # -----------------------------------------------------

    return {

        "cluster_size":
        len(valid_points),

        "latitude":
        weighted_lat,

        "longitude":
        weighted_lon,

        "accuracy_radius_m":
        max(
            5,
            30 -
            (
                len(valid_points)
                * 5
            )
        ),

        "confidence": (
            "High "
            "(Multi-Point Fusion Across "
            f"{len(valid_points)} Nodes)"
        ),

        "source":
        "WiGLE Cluster Centroid Calculation"
    }


# =========================================================
# IP GEOLOCATION
# =========================================================

@app.get("/api/v1/locate-ip")
async def locate_ip(ip: str):

    ip = ip.strip()


    # -----------------------------------------------------
    # VALIDATE IP
    # -----------------------------------------------------

    if not is_valid_ip(ip):

        return {

            "error":
            "Invalid IP address."
        }


    try:

        parsed_ip = ipaddress.ip_address(ip)


        # -------------------------------------------------
        # PRIVATE / NON-ROUTABLE IP
        # -------------------------------------------------

        if (

            parsed_ip.is_private
            or parsed_ip.is_loopback
            or parsed_ip.is_link_local
            or parsed_ip.is_reserved
            or parsed_ip.is_multicast

        ):

            return {

                "error":
                "Private or non-routable IP "
                "addresses cannot be geolocated."
            }


        # -------------------------------------------------
        # IPWHO.IS
        # -------------------------------------------------

        url = f"https://ipwho.is/{ip}"


        response = requests.get(

            url,

            headers={

                "Accept":
                "application/json",

                "User-Agent":
                "ArgusScope/2.1"
            },

            timeout=REQUEST_TIMEOUT
        )


        # -------------------------------------------------
        # HTTP ERROR
        # -------------------------------------------------

        if response.status_code != 200:

            return {

                "error":
                "IP geolocation service returned "
                f"HTTP {response.status_code}."
            }


        # -------------------------------------------------
        # SAFE JSON PARSING
        # -------------------------------------------------

        try:

            ip_data = response.json()

        except ValueError:

            return {

                "error":
                "IP geolocation service "
                "returned invalid JSON."
            }


        # -------------------------------------------------
        # API FAILURE
        # -------------------------------------------------

        if not ip_data.get("success"):

            return {

                "error":
                ip_data.get(
                    "message",
                    "IP target resolution failed."
                )
            }


        # -------------------------------------------------
        # COORDINATES
        # -------------------------------------------------

        latitude = ip_data.get(
            "latitude"
        )

        longitude = ip_data.get(
            "longitude"
        )


        if (
            latitude is None
            or longitude is None
        ):

            return {

                "error":
                "No coordinates returned for this IP."
            }


        # -------------------------------------------------
        # OPTIONAL DATA
        # -------------------------------------------------

        timezone = ip_data.get(
            "timezone"
        )

        connection = ip_data.get(
            "connection"
        )


        if not isinstance(
            timezone,
            dict
        ):

            timezone = {}


        if not isinstance(
            connection,
            dict
        ):

            connection = {}


        # -------------------------------------------------
        # ARGUSSCOPE RESPONSE
        # -------------------------------------------------

        return {

            "ip":
            ip_data.get(
                "ip",
                ip
            ),

            "latitude":
            latitude,

            "longitude":
            longitude,

            "city":
            ip_data.get(
                "city"
            ),

            "region":
            ip_data.get(
                "region"
            ),

            "country":
            ip_data.get(
                "country"
            ),

            "country_code":
            ip_data.get(
                "country_code"
            ),

            "postal":
            ip_data.get(
                "postal"
            ),

            "timezone":
            timezone.get(
                "id"
            ),

            "isp":
            connection.get(
                "isp"
            ),

            "org":
            connection.get(
                "org"
            ),

            "confidence":
            "Medium (Regional ISP Geolocation)",

            "accuracy_radius_m":
            5000,

            "source":
            "IPWho.is Geo Lookup"
        }


    # -----------------------------------------------------
    # NETWORK FAILURE
    # -----------------------------------------------------

    except requests.RequestException as exc:

        return {

            "error":
            f"IP geolocation request failed: "
            f"{str(exc)}"
        }


    # -----------------------------------------------------
    # INTERNAL FAILURE
    # -----------------------------------------------------

    except Exception as exc:

        return {

            "error":
            f"Internal IP lookup failure: "
            f"{str(exc)}"
        }
