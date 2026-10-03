import os
import time
import ipaddress
import requests

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List


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
# ENVIRONMENT
# =========================================================

WIGLE_USER = os.getenv("WIGLE_API_USER", "")
WIGLE_TOKEN = os.getenv("WIGLE_API_KEY", "")


# =========================================================
# CACHE
# =========================================================

SEARCH_CACHE = {}

CACHE_TTL_SECONDS = 600


# =========================================================
# MODELS
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
    return (
        mac
        .strip()
        .lower()
        .replace("-", ":")
    )


def valid_ip(ip: str) -> bool:

    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False


# =========================================================
# ROOT
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
# IP GEOLOCATION
# =========================================================

@app.get("/api/v1/locate-ip")
async def locate_ip(ip: str):

    ip = ip.strip()

    # -----------------------------------------
    # Validate IP
    # -----------------------------------------

    if not valid_ip(ip):

        return {
            "error": "Invalid IP address."
        }


    try:

        # -----------------------------------------
        # Use HTTPS JSON endpoint
        # -----------------------------------------

        url = f"https://ipwho.is/{ip}"

        response = requests.get(
            url,
            timeout=10,
            headers={
                "Accept": "application/json",
                "User-Agent": "ArgusScope/2.1"
            }
        )


        # -----------------------------------------
        # HTTP failure
        # -----------------------------------------

        if response.status_code != 200:

            return {
                "error": (
                    f"IP geolocation service returned "
                    f"HTTP {response.status_code}."
                )
            }


        # -----------------------------------------
        # Protect against invalid JSON
        # -----------------------------------------

        try:

            ip_data = response.json()

        except ValueError:

            return {
                "error": (
                    "IP geolocation service returned "
                    "an invalid response."
                )
            }


        # -----------------------------------------
        # API-level failure
        # -----------------------------------------

        if not ip_data.get("success", False):

            return {
                "error": (
                    ip_data.get(
                        "message",
                        "IP target resolution failed."
                    )
                )
            }


        # -----------------------------------------
        # Extract location
        # -----------------------------------------

        latitude = ip_data.get("latitude")
        longitude = ip_data.get("longitude")


        if latitude is None or longitude is None:

            return {
                "error": "No coordinates returned for this IP."
            }


        # -----------------------------------------
        # Return ArgusScope format
        # -----------------------------------------

        return {

            "ip": ip_data.get(
                "ip",
                ip
            ),

            "latitude": latitude,

            "longitude": longitude,

            "city": ip_data.get(
                "city"
            ),

            "region": ip_data.get(
                "region"
            ),

            "country": ip_data.get(
                "country"
            ),

            "country_code": ip_data.get(
                "country_code"
            ),

            "postal": ip_data.get(
                "postal"
            ),

            "timezone": (
                ip_data.get("timezone", {})
                .get("id")
                if isinstance(
                    ip_data.get("timezone"),
                    dict
                )
                else None
            ),

            "isp": (
                ip_data.get("connection", {})
                .get("isp")
                if isinstance(
                    ip_data.get("connection"),
                    dict
                )
                else None
            ),

            "org": (
                ip_data.get("connection", {})
                .get("org")
                if isinstance(
                    ip_data.get("connection"),
                    dict
                )
                else None
            ),

            "confidence": (
                "Medium "
                "(Regional ISP Geolocation)"
            ),

            "accuracy_radius_m": 5000,

            "source": "IPWho.is Geo Lookup"
        }


    except requests.RequestException as e:

        return {
            "error": (
                f"IP geolocation request failed: {str(e)}"
            )
        }


    except Exception as e:

        return {
            "error": (
                f"Internal IP lookup failure: {str(e)}"
            )
        }


# =========================================================
# BSSID LOOKUP
# =========================================================

@app.get("/api/v1/locate-bssid")
async def locate_bssid(netid: str):

    target_mac = sanitize_mac(netid)


    # -----------------------------------------
    # Cache
    # -----------------------------------------

    now = time.time()


    if target_mac in SEARCH_CACHE:

        cached = SEARCH_CACHE[target_mac]


        if (
            now - cached["timestamp"]
            < CACHE_TTL_SECONDS
        ):

            res_data = cached["data"].copy()

            res_data["source"] = (
                "Cache (Optimized Memory)"
            )

            return res_data


        else:

            del SEARCH_CACHE[target_mac]


    # -----------------------------------------
    # WiGLE
    # -----------------------------------------

    url = (
        "https://api.wigle.net/"
        "api/v2/network/search"
    )


    params = {

        "netid": target_mac,

        "resultsPerPage": 1,

        "latrange1": -90.0,

        "latrange2": 90.0,

        "longrange1": -180.0,

        "longrange2": 180.0
    }


    headers = {
        "Accept": "application/json"
    }


    try:

        if not WIGLE_USER or not WIGLE_TOKEN:

            return {
                "error":
                "WiGLE API credentials not configured "
                "on server backend."
            }


        response = requests.get(

            url,

            params=params,

            headers=headers,

            auth=(
                WIGLE_USER,
                WIGLE_TOKEN
            ),

            timeout=15
        )


        if response.status_code == 429:

            return {
                "error":
                "WiGLE rate limit exceeded (429)."
            }


        if response.status_code != 200:

            return {
                "error":
                f"WiGLE API error: "
                f"Status code {response.status_code}"
            }


        try:

            data = response.json()

        except ValueError:

            return {
                "error":
                "WiGLE returned an invalid response."
            }


        if (
            data.get("success")
            and data.get("results")
            and len(data["results"]) > 0
        ):

            result = data["results"][0]


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


            payload = {

                "bssid":
                result.get("netid"),

                "ssid":
                result.get(
                    "ssid",
                    "Unknown Network"
                ),

                "latitude":
                result.get("trilat"),

                "longitude":
                result.get("trilong"),

                "accuracy_radius_m":
                radius,

                "confidence":
                confidence,

                "observations":
                obs_count,

                "source":
                "WiGLE Live Database"
            }


            SEARCH_CACHE[target_mac] = {

                "timestamp":
                now,

                "data":
                payload
            }


            return payload


        else:

            return {
                "error":
                "Target BSSID not cataloged "
                "in WiGLE database."
            }


    except requests.RequestException as e:

        return {
            "error":
            f"WiGLE request failed: {str(e)}"
        }


    except Exception as e:

        return {
            "error":
            f"Internal routing failure: {str(e)}"
        }


# =========================================================
# MULTI-BSSID TRIANGULATION
# =========================================================

@app.post("/api/v1/triangulate-cluster")
async def triangulate_cluster(
    payload: MultiBSSIDRequest
):

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
        "Accept": "application/json"
    }


    valid_points = []

    total_weight = 0


    for scan in payload.scans:

        clean_mac =
            sanitize_mac(scan.netid)


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

                timeout=15
            )


            if response.status_code != 200:
                continue


            try:

                data = response.json()

            except ValueError:

                continue


            if (
                data.get("success")
                and data.get("results")
            ):

                res =
                    data["results"][0]


                lat =
                    res.get("trilat")

                lon =
                    res.get("trilong")


                if (
                    lat is not None
                    and lon is not None
                ):

                    weight = max(
                        1,
                        100 - abs(scan.rssi)
                    )


                    valid_points.append({

                        "lat":
                        lat,

                        "lon":
                        lon,

                        "weight":
                        weight
                    })


                    total_weight += weight


        except Exception:

            continue


    if not valid_points:

        return {

            "error":
            "No valid coordinates resolved "
            "from the provided BSSID cluster."
        }


    weighted_lat = (

        sum(
            p["lat"] * p["weight"]
            for p in valid_points
        )
        / total_weight
    )


    weighted_lon = (

        sum(
            p["lon"] * p["weight"]
            for p in valid_points
        )
        / total_weight
    )


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
            30 - (
                len(valid_points) * 5
            )
        ),

        "confidence":
        (
            "High "
            "(Multi-Point Fusion Across "
            f"{len(valid_points)} Nodes)"
        ),

        "source":
        "WiGLE Cluster Centroid Calculation"
    }
