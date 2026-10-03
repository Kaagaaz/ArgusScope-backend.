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

APP_VERSION = "3.0.0"

app = FastAPI(
    title="ArgusScope Intelligence Engine",
    version=APP_VERSION
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://kaagaaz.github.io",
        "http://localhost",
        "http://127.0.0.1",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# =========================================================
# ENVIRONMENT VARIABLES
# =========================================================

WIGLE_USER = os.getenv("WIGLE_API_USER", "").strip()
WIGLE_TOKEN = os.getenv("WIGLE_API_KEY", "").strip()

# Optional but recommended.
# Create this in Render Environment as:
#
# IPAPIIS_API_KEY=your_key
#
IPAPIIS_KEY = os.getenv("IPAPIIS_API_KEY", "").strip()


# =========================================================
# CONFIGURATION
# =========================================================

REQUEST_TIMEOUT = 10

IP_CACHE_TTL = 600
BSSID_CACHE_TTL = 600


# =========================================================
# MEMORY CACHES
# =========================================================

IP_CACHE = {}
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
        .upper()
        .replace("-", ":")
        .replace(".", "")
    )


def normalize_bssid(mac: str) -> str:
    """
    Convert a MAC/BSSID into AA:BB:CC:DD:EE:FF format.
    """

    clean = (
        mac
        .strip()
        .upper()
        .replace("-", "")
        .replace(":", "")
        .replace(".", "")
    )

    if len(clean) != 12:
        return ""

    try:
        int(clean, 16)
    except ValueError:
        return ""

    return ":".join(
        clean[i:i + 2]
        for i in range(0, 12, 2)
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
            address.is_global
            and not address.is_private
            and not address.is_loopback
            and not address.is_link_local
            and not address.is_reserved
            and not address.is_multicast
            and not address.is_unspecified
        )

    except ValueError:
        return False


def cache_get(cache, key, ttl):
    """
    Return cached data if it has not expired.
    """

    entry = cache.get(key)

    if not entry:
        return None

    age = time.time() - entry["timestamp"]

    if age > ttl:
        cache.pop(key, None)
        return None

    return entry["data"]


def cache_set(cache, key, data):
    """
    Store data in memory cache.
    """

    cache[key] = {
        "timestamp": time.time(),
        "data": data
    }


def safe_json(response):
    """
    Safely parse JSON without throwing
    'Expecting value' errors.
    """

    try:
        return response.json()

    except ValueError:
        return None


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():

    return {
        "status": "online",
        "service": "ArgusScope Intelligence Engine",
        "version": APP_VERSION,
        "endpoints": [
            "/health",
            "/api/v1/locate-ip",
            "/api/v1/locate-bssid",
            "/api/v1/triangulate-cluster"
        ]
    }


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "service": "ArgusScope",
        "version": APP_VERSION,
        "ip_provider": "ipapi.is",
        "wigle_configured": bool(
            WIGLE_USER and WIGLE_TOKEN
        )
    }


# =========================================================
# IP PROVIDER
# IPAPI.IS
# =========================================================

def lookup_ip_ipapi_is(ip: str):
    """
    Primary IP geolocation provider.

    ipapi.is supports:
        city
        region
        country
        latitude
        longitude
        timezone
        ASN
        company

    An API key is optional, but recommended.
    """

    params = {
        "q": ip
    }

    if IPAPIIS_KEY:
        params["key"] = IPAPIIS_KEY

    try:

        response = requests.get(
            "https://api.ipapi.is/",
            params=params,
            headers={
                "Accept": "application/json",
                "User-Agent": "ArgusScope/3.0"
            },
            timeout=REQUEST_TIMEOUT
        )

    except requests.RequestException as exc:

        return {
            "success": False,
            "provider": "ipapi.is",
            "error": str(exc)
        }


    if response.status_code == 429:

        return {
            "success": False,
            "provider": "ipapi.is",
            "rate_limited": True,
            "error": "IP geolocation provider rate limit reached."
        }


    if response.status_code != 200:

        return {
            "success": False,
            "provider": "ipapi.is",
            "error":
                f"Provider returned HTTP "
                f"{response.status_code}."
        }


    data = safe_json(response)

    if not isinstance(data, dict):

        return {
            "success": False,
            "provider": "ipapi.is",
            "error": "Provider returned invalid JSON."
        }


    # -----------------------------------------------------
    # BOGON
    # -----------------------------------------------------

    if data.get("is_bogon") is True:

        return {
            "success": False,
            "provider": "ipapi.is",
            "error": "The supplied IP is a bogon/reserved address."
        }


    latitude = data.get("lat")
    longitude = data.get("lon")


    if latitude is None or longitude is None:

        return {
            "success": False,
            "provider": "ipapi.is",
            "error":
                "Provider returned no geographic coordinates."
        }


    try:

        latitude = float(latitude)
        longitude = float(longitude)

    except (TypeError, ValueError):

        return {
            "success": False,
            "provider": "ipapi.is",
            "error":
                "Provider returned invalid coordinates."
        }


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
            data.get("country"),

        "country_code":
            data.get("country_code"),

        "timezone":
            data.get("timezone"),

        "isp":
            data.get("company"),

        "org":
            data.get("company"),

        "asn":
            data.get("asn"),

        "confidence":
            "Approximate IP geolocation",

        "source":
            "ipapi.is"
    }


# =========================================================
# FALLBACK PROVIDER
# IPWHOIS.IO
# =========================================================

def lookup_ip_ipwhois(ip: str):
    """
    Secondary fallback provider.

    Used only when the primary provider fails.
    """

    try:

        response = requests.get(
            f"https://ipwho.is/{ip}",
            headers={
                "Accept": "application/json",
                "User-Agent": "ArgusScope/3.0"
            },
            timeout=REQUEST_TIMEOUT
        )

    except requests.RequestException as exc:

        return {
            "success": False,
            "provider": "ipwho.is",
            "error": str(exc)
        }


    if response.status_code == 429:

        return {
            "success": False,
            "provider": "ipwho.is",
            "rate_limited": True,
            "error":
                "Fallback provider rate limit reached."
        }


    if response.status_code != 200:

        return {
            "success": False,
            "provider": "ipwho.is",
            "error":
                f"Provider returned HTTP "
                f"{response.status_code}."
        }


    data = safe_json(response)

    if not isinstance(data, dict):

        return {
            "success": False,
            "provider": "ipwho.is",
            "error":
                "Provider returned invalid JSON."
        }


    if not data.get("success", False):

        return {
            "success": False,
            "provider": "ipwho.is",
            "error":
                data.get(
                    "message",
                    "Provider could not resolve the IP."
                )
        }


    latitude = data.get("latitude")
    longitude = data.get("longitude")


    if latitude is None or longitude is None:

        return {
            "success": False,
            "provider": "ipwho.is",
            "error":
                "Provider returned no coordinates."
        }


    try:

        latitude = float(latitude)
        longitude = float(longitude)

    except (TypeError, ValueError):

        return {
            "success": False,
            "provider": "ipwho.is",
            "error":
                "Provider returned invalid coordinates."
        }


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
            data.get("country"),

        "country_code":
            data.get("country_code"),

        "timezone":
            data.get("timezone", {}).get("id")
            if isinstance(
                data.get("timezone"),
                dict
            )
            else None,

        "isp":
            (
                data.get("connection", {}).get("isp")
                if isinstance(
                    data.get("connection"),
                    dict
                )
                else None
            ),

        "org":
            (
                data.get("connection", {}).get("org")
                if isinstance(
                    data.get("connection"),
                    dict
                )
                else None
            ),

        "asn":
            (
                data.get("connection", {}).get("asn")
                if isinstance(
                    data.get("connection"),
                    dict
                )
                else None
            ),

        "confidence":
            "Approximate IP geolocation",

        "source":
            "ipwho.is"
    }


# =========================================================
# IP GEOLOCATION
# =========================================================

@app.get("/api/v1/locate-ip")
def locate_ip(ip: str):

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


    # -----------------------------------------------------
    # CACHE
    # -----------------------------------------------------

    cached = cache_get(
        IP_CACHE,
        ip,
        IP_CACHE_TTL
    )

    if cached:

        result = cached.copy()

        result["cached"] = True

        return result


    # =====================================================
    # PRIMARY PROVIDER
    # =====================================================

    result = lookup_ip_ipapi_is(ip)


    if result.get("success"):

        result["cached"] = False

        cache_set(
            IP_CACHE,
            ip,
            result
        )

        return result


    # =====================================================
    # FALLBACK
    # =====================================================

    fallback = lookup_ip_ipwhois(ip)


    if fallback.get("success"):

        fallback["cached"] = False

        cache_set(
            IP_CACHE,
            ip,
            fallback
        )

        return fallback


    # =====================================================
    # FAILURE
    # =====================================================

    errors = []

    if result.get("error"):
        errors.append(
            f"ipapi.is: {result['error']}"
        )

    if fallback.get("error"):
        errors.append(
            f"ipwho.is: {fallback['error']}"
        )


    return {
        "success": False,

        "error":
            "No IP geolocation provider could resolve "
            "this address.",

        "details":
            errors
    }


# =========================================================
# WIGLE BSSID LOOKUP
# =========================================================

@app.get("/api/v1/locate-bssid")
def locate_bssid(netid: str):

    target_mac = normalize_bssid(netid)


    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not target_mac:

        return {
            "success": False,
            "error":
                "Invalid BSSID format. Expected "
                "AA:BB:CC:DD:EE:FF."
        }


    # -----------------------------------------------------
    # CACHE
    # -----------------------------------------------------

    cached = cache_get(
        BSSID_CACHE,
        target_mac,
        BSSID_CACHE_TTL
    )


    if cached:

        result = cached.copy()

        result["source"] = "ArgusScope Cache"
        result["cached"] = True

        return result


    # -----------------------------------------------------
    # CREDENTIAL CHECK
    # -----------------------------------------------------

    if not WIGLE_USER or not WIGLE_TOKEN:

        return {
            "success": False,
            "error":
                "WiGLE API credentials are not configured "
                "on the Render server."
        }


    # =====================================================
    # WIGLE
    # =====================================================

    url = (
        "https://api.wigle.net/"
        "api/v2/network/search"
    )


    params = {
        "netid": target_mac,
        "resultsPerPage": 1,
        "latrange1": -90,
        "latrange2": 90,
        "longrange1": -180,
        "longrange2": 180
    }


    headers = {
        "Accept": "application/json",
        "User-Agent": "ArgusScope/3.0"
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


    except requests.RequestException as exc:

        return {
            "success": False,
            "error":
                f"WiGLE request failed: {str(exc)}"
        }


    # -----------------------------------------------------
    # RATE LIMIT
    # -----------------------------------------------------

    if response.status_code == 429:

        return {
            "success": False,
            "error":
                "WiGLE rate limit exceeded. "
                "Please wait before trying again."
        }


    # -----------------------------------------------------
    # AUTH FAILURE
    # -----------------------------------------------------

    if response.status_code in (401, 403):

        return {
            "success": False,
            "error":
                "WiGLE authentication failed. "
                "Check the Render environment variables."
        }


    # -----------------------------------------------------
    # OTHER HTTP ERRORS
    # -----------------------------------------------------

    if response.status_code != 200:

        return {
            "success": False,
            "error":
                f"WiGLE returned HTTP "
                f"{response.status_code}."
        }


    # -----------------------------------------------------
    # JSON
    # -----------------------------------------------------

    data = safe_json(response)


    if not isinstance(data, dict):

        return {
            "success": False,
            "error":
                "WiGLE returned invalid JSON."
        }


    # -----------------------------------------------------
    # RESULTS
    # -----------------------------------------------------

    results = data.get("results")


    if not data.get("success") or not results:

        return {
            "success": False,
            "error":
                "BSSID not found in the WiGLE database."
        }


    result = results[0]


    latitude = result.get("trilat")
    longitude = result.get("trilong")


    if latitude is None or longitude is None:

        return {
            "success": False,
            "error":
                "WiGLE returned a result without coordinates."
        }


    try:

        latitude = float(latitude)
        longitude = float(longitude)

    except (TypeError, ValueError):

        return {
            "success": False,
            "error":
                "WiGLE returned invalid coordinates."
        }


    observations = result.get("count", 1)


    try:

        observations = int(observations)

    except (TypeError, ValueError):

        observations = 1


    # =====================================================
    # CONFIDENCE
    # =====================================================

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
            "WiGLE",

        "cached":
            False
    }


    # -----------------------------------------------------
    # CACHE
    # -----------------------------------------------------

    cache_set(
        BSSID_CACHE,
        target_mac,
        payload
    )


    return payload


# =========================================================
# MULTI-BSSID CLUSTER
# =========================================================

@app.post("/api/v1/triangulate-cluster")
def triangulate_cluster(
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
        "Accept": "application/json",
        "User-Agent": "ArgusScope/3.0"
    }


    valid_points = []


    # =====================================================
    # PROCESS BSSIDS
    # =====================================================

    for scan in payload.scans:

        clean_mac = normalize_bssid(
            scan.netid
        )


        if not clean_mac:
            continue


        # -------------------------------------------------
        # CACHE FIRST
        # -------------------------------------------------

        cached = cache_get(
            BSSID_CACHE,
            clean_mac,
            BSSID_CACHE_TTL
        )


        if cached and cached.get("success"):

            latitude = cached.get("latitude")
            longitude = cached.get("longitude")

        else:

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


            except requests.RequestException:

                continue


            if response.status_code != 200:
                continue


            data = safe_json(response)


            if not isinstance(data, dict):
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
        # VALIDATE COORDINATES
        # -------------------------------------------------

        try:

            latitude = float(latitude)
            longitude = float(longitude)

        except (TypeError, ValueError):

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
                latitude,

            "longitude":
                longitude,

            "weight":
                weight
        })


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
    # CONFIDENCE
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
def startup_event():

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
        f"IPAPIIS key configured: "
        f"{bool(IPAPIIS_KEY)}"
    )

    print(
        f"WiGLE configured: "
        f"{bool(WIGLE_USER and WIGLE_TOKEN)}"
    )

    print(
        "=========================================="
    )
