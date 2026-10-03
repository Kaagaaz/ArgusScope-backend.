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
# INTELLIGENCE ENGINE BACKEND
# =========================================================

APP_VERSION = "2.2.0"

app = FastAPI(
    title="ArgusScope Intelligence Engine",
    version=APP_VERSION
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
# CONFIGURATION
# =========================================================

REQUEST_TIMEOUT = 15
CACHE_TTL = 600


# =========================================================
# MEMORY CACHE
# =========================================================

BSSID_CACHE = {}


# =========================================================
# DATA MODELS
# =========================================================

class ScanTarget(BaseModel):
    netid: str
    rssi: int = -70


class MultiBSSIDRequest(BaseModel):
    scans: List[ScanTarget]


# =========================================================
# GENERAL HELPERS
# =========================================================

def sanitize_mac(mac: str) -> str:
    """
    Normalize a BSSID/MAC address.
    """

    return (
        mac
        .strip()
        .lower()
        .replace("-", ":")
    )


def is_valid_ip(ip: str) -> bool:
    """
    Check whether the supplied value is a valid
    IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    """
    Check whether an IP is publicly routable.
    """

    try:
        address = ipaddress.ip_address(ip)

        return (
            not address.is_private
            and not address.is_loopback
            and not address.is_link_local
            and not address.is_reserved
            and not address.is_multicast
            and not address.is_unspecified
        )

    except ValueError:
        return False


# =========================================================
# ROOT
# =========================================================

@app.get("/")
async def root():

    return {
        "status": "online",
        "service": "ArgusScope Intelligence Engine",
        "version": APP_VERSION,

        "endpoints": [
            "/api/v1/locate-ip",
            "/api/v1/locate-bssid",
            "/api/v1/triangulate-cluster"
        ]
    }


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
async def health():

    return {
        "status": "healthy",
        "service": "ArgusScope",
        "version": APP_VERSION
    }


# =========================================================
# IP GEOLOCATION
# =========================================================

@app.get("/api/v1/locate-ip")
async def locate_ip(ip: str):

    ip = ip.strip()

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not is_valid_ip(ip):

        return {
            "success": False,
            "error": "Invalid IP address."
        }


    # -----------------------------------------------------
    # PUBLIC IP CHECK
    # -----------------------------------------------------

    if not is_public_ip(ip):

        return {
            "success": False,
            "error":
            "Private or non-routable IP addresses "
            "cannot be geolocated."
        }


    # =====================================================
    # PROVIDER 1
    # IPAPI.CO
    # =====================================================

    try:

        url = f"https://ipapi.co/{ip}/json/"

        response = requests.get(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "ArgusScope/2.2"
            },
            timeout=REQUEST_TIMEOUT
        )


        # -------------------------------------------------
        # SUCCESS
        # -------------------------------------------------

        if response.status_code == 200:

            try:
                data = response.json()

            except ValueError:
                data = None


            if data:

                # ipapi uses "error": true on failure

                if not data.get("error"):

                    latitude = data.get("latitude")
                    longitude = data.get("longitude")


                    if (
                        latitude is not None
                        and longitude is not None
                    ):

                        return {
                            "success": True,

                            "ip":
                            data.get("ip", ip),

                            "latitude":
                            latitude,

                            "longitude":
                            longitude,

                            "city":
                            data.get("city"),

                            "region":
                            data.get("region"),

                            "country":
                            data.get("country_name"),

                            "country_code":
                            data.get("country_code"),

                            "postal":
                            data.get("postal"),

                            "timezone":
                            data.get("timezone"),

                            "isp":
                            data.get("org"),

                            "org":
                            data.get("org"),

                            "asn":
                            data.get("asn"),

                            "confidence":
                            "Medium (Regional ISP Geolocation)",

                            "accuracy_radius_m":
                            5000,

                            "source":
                            "ipapi.co"
                        }


    except requests.RequestException:

        pass

    except Exception:

        pass


    # =====================================================
    # PROVIDER 2
    # IP-API
    # =====================================================

    try:

        url = f"https://ip-api.com/json/{ip}"

        params = {
            "fields":
            "status,message,country,countryCode,"
            "regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        }

        response = requests.get(
            url,
            params=params,
            headers={
                "Accept": "application/json",
                "User-Agent": "ArgusScope/2.2"
            },
            timeout=REQUEST_TIMEOUT
        )


        if response.status_code == 200:

            try:
                data = response.json()

            except ValueError:
                data = None


            if data and data.get("status") == "success":

                latitude = data.get("lat")
                longitude = data.get("lon")


                if (
                    latitude is not None
                    and longitude is not None
                ):

                    return {
                        "success": True,

                        "ip":
                        data.get("query", ip),

                        "latitude":
                        latitude,

                        "longitude":
                        longitude,

                        "city":
                        data.get("city"),

                        "region":
                        data.get("regionName"),

                        "country":
                        data.get("country"),

                        "country_code":
                        data.get("countryCode"),

                        "postal":
                        data.get("zip"),

                        "timezone":
                        data.get("timezone"),

                        "isp":
                        data.get("isp"),

                        "org":
                        data.get("org"),

                        "asn":
                        data.get("as"),

                        "confidence":
                        "Medium (Regional ISP Geolocation)",

                        "accuracy_radius_m":
                        5000,

                        "source":
                        "ip-api.com"
                    }


    except requests.RequestException:

        pass

    except Exception:

        pass


    # =====================================================
    # ALL PROVIDERS FAILED
    # =====================================================

    return {
        "success": False,

        "error":
        "IP geolocation providers could not resolve "
        "this address. The providers may be rate-limited "
        "or temporarily unavailable."
    }


# =========================================================
# WIGLE BSSID LOOKUP
# =========================================================

@app.get("/api/v1/locate-bssid")
async def locate_bssid(netid: str):

    target_mac = sanitize_mac(netid)


    # -----------------------------------------------------
    # BASIC MAC VALIDATION
    # -----------------------------------------------------

    compact = target_mac.replace(":", "")

    if len(compact) != 12:

        return {
            "success": False,
            "error": "Invalid BSSID format."
        }


    try:

        int(compact, 16)

    except ValueError:

        return {
            "success": False,
            "error": "Invalid BSSID format."
        }


    # =====================================================
    # CACHE
    # =====================================================

    now = time.time()

    cached = BSSID_CACHE.get(target_mac)


    if cached:

        age = now - cached["timestamp"]

        if age < CACHE_TTL:

            result = cached["data"].copy()

            result["source"] = (
                "ArgusScope Cache"
            )

            return result

        else:

            del BSSID_CACHE[target_mac]


    # =====================================================
    # WIGLE CREDENTIAL CHECK
    # =====================================================

    if not WIGLE_USER or not WIGLE_TOKEN:

        return {
            "success": False,

            "error":
            "WiGLE API credentials are not configured "
            "on the Render server."
        }


    # =====================================================
    # WIGLE REQUEST
    # =====================================================

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
        -90,

        "latrange2":
        90,

        "longrange1":
        -180,

        "longrange2":
        180
    }


    headers = {

        "Accept":
        "application/json",

        "User-Agent":
        "ArgusScope/2.2"
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
                "success": False,

                "error":
                "WiGLE rate limit exceeded. "
                "Please wait before trying again."
            }


        # -------------------------------------------------
        # OTHER ERROR
        # -------------------------------------------------

        if response.status_code != 200:

            return {
                "success": False,

                "error":
                f"WiGLE returned HTTP "
                f"{response.status_code}."
            }


        # -------------------------------------------------
        # JSON
        # -------------------------------------------------

        try:

            data = response.json()

        except ValueError:

            return {
                "success": False,

                "error":
                "WiGLE returned invalid JSON."
            }


        # -------------------------------------------------
        # RESULT
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
                    "success": False,

                    "error":
                    "WiGLE returned a result "
                    "without coordinates."
                }


            observations = result.get(
                "count",
                1
            )


            # ---------------------------------------------
            # CONFIDENCE
            # ---------------------------------------------

            if observations >= 40:

                radius = 12

                confidence = (
                    "High (Dense Telemetry)"
                )

            elif observations >= 5:

                radius = 25

                confidence = (
                    "Medium-High "
                    "(Multiple Observations)"
                )

            else:

                radius = 50

                confidence = (
                    "Low-Medium "
                    "(Sparse Observation)"
                )


            payload = {

                "success": True,

                "bssid":
                result.get(
                    "netid",
                    target_mac
                ),

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
                observations,

                "source":
                "WiGLE"
            }


            # ---------------------------------------------
            # CACHE
            # ---------------------------------------------

            BSSID_CACHE[target_mac] = {

                "timestamp":
                now,

                "data":
                payload
            }


            return payload


        # -------------------------------------------------
        # NOT FOUND
        # -------------------------------------------------

        return {
            "success": False,

            "error":
            "BSSID not found in the WiGLE database."
        }


    except requests.RequestException as exc:

        return {
            "success": False,

            "error":
            f"WiGLE request failed: {str(exc)}"
        }


    except Exception as exc:

        return {
            "success": False,

            "error":
            f"Internal BSSID lookup error: {str(exc)}"
        }


# =========================================================
# MULTI-BSSID TRIANGULATION
# =========================================================

@app.post("/api/v1/triangulate-cluster")
async def triangulate_cluster(
    payload: MultiBSSIDRequest
):

    # -----------------------------------------------------
    # CREDENTIALS
    # -----------------------------------------------------

    if not WIGLE_USER or not WIGLE_TOKEN:

        return {
            "success": False,

            "error":
            "WiGLE API credentials are not configured "
            "on the Render server."
        }


    # -----------------------------------------------------
    # EMPTY REQUEST
    # -----------------------------------------------------

    if not payload.scans:

        return {
            "success": False,

            "error":
            "No BSSID observations were supplied."
        }


    url = (
        "https://api.wigle.net/"
        "api/v2/network/search"
    )


    headers = {

        "Accept":
        "application/json",

        "User-Agent":
        "ArgusScope/2.2"
    }


    valid_points = []


    # =====================================================
    # PROCESS BSSIDS
    # =====================================================

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
            -90,

            "latrange2":
            90,

            "longrange1":
            -180,

            "longrange2":
            180
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


            try:

                data = response.json()

            except ValueError:

                continue


            if not (
                data.get("success")
                and data.get("results")
            ):

                continue


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

                continue


            # -------------------------------------------------
            # RSSI WEIGHT
            # -------------------------------------------------

            rssi = scan.rssi

            weight = max(
                1,
                100 - abs(rssi)
            )


            valid_points.append({

                "latitude":
                float(latitude),

                "longitude":
                float(longitude),

                "weight":
                weight
            })


        except requests.RequestException:

            continue


        except Exception:

            continue


    # =====================================================
    # NO VALID POINTS
    # =====================================================

    if not valid_points:

        return {
            "success": False,

            "error":
            "No valid coordinates could be resolved "
            "from the supplied BSSID cluster."
        }


    # =====================================================
    # WEIGHTED CENTROID
    # =====================================================

    total_weight = sum(
        point["weight"]
        for point in valid_points
    )


    latitude = (

        sum(
            point["latitude"]
            * point["weight"]

            for point in valid_points
        )

        / total_weight
    )


    longitude = (

        sum(
            point["longitude"]
            * point["weight"]

            for point in valid_points
        )

        / total_weight
    )


    # =====================================================
    # ESTIMATED ACCURACY
    # =====================================================

    count = len(valid_points)


    if count >= 5:

        radius = 10

        confidence = (
            "High (Multi-Point Fusion)"
        )

    elif count >= 3:

        radius = 20

        confidence = (
            "Medium-High (Cluster Fusion)"
        )

    elif count == 2:

        radius = 35

        confidence = (
            "Medium (Two-Point Fusion)"
        )

    else:

        radius = 50

        confidence = (
            "Low-Medium (Single Point)"
        )


    # =====================================================
    # RESPONSE
    # =====================================================

    return {

        "success": True,

        "cluster_size":
        count,

        "latitude":
        latitude,

        "longitude":
        longitude,

        "accuracy_radius_m":
        radius,

        "confidence":
        confidence,

        "source":
        "ArgusScope WiGLE Cluster Fusion"
    }


# =========================================================
# STARTUP
# =========================================================

@app.on_event("startup")
async def startup_event():

    print(
        "=========================================="
    )

    print(
        "ArgusScope Intelligence Engine"
    )

    print(
        f"Version: {APP_VERSION}"
    )

    print(
        "Backend initialized successfully."
    )

    print(
        "=========================================="
    )
