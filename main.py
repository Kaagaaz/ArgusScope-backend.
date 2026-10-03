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

APP_VERSION = "3.2.0"

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
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# ENVIRONMENT VARIABLES
# =========================================================

WIGLE_USER = os.getenv(
    "WIGLE_API_USER",
    ""
).strip()

WIGLE_TOKEN = os.getenv(
    "WIGLE_API_KEY",
    ""
).strip()

IPAPIDEV_KEY = os.getenv(
    "IPAPIDEV_API_KEY",
    ""
).strip()


# =========================================================
# CONFIGURATION
# =========================================================

REQUEST_TIMEOUT = 10

IP_CACHE_TTL = 600

BSSID_CACHE_TTL = 600


# =========================================================
# MEMORY CACHE
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

def safe_json(response):

    try:
        return response.json()

    except ValueError:
        return None


def is_valid_ip(ip):

    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False


def is_public_ip(ip):

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


def normalize_bssid(mac):

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


def cache_get(cache, key, ttl):

    entry = cache.get(key)

    if not entry:
        return None

    age = time.time() - entry["timestamp"]

    if age > ttl:

        cache.pop(
            key,
            None
        )

        return None

    return entry["data"]


def cache_set(cache, key, data):

    cache[key] = {
        "timestamp": time.time(),
        "data": data
    }


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():

    return {

        "status": "online",

        "service":
            "ArgusScope Intelligence Engine",

        "version":
            APP_VERSION,

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

        "status":
            "healthy",

        "service":
            "ArgusScope",

        "version":
            APP_VERSION,

        "ip_providers":
            "ip-api.dev → ipapi.co → ipwho.is",

        "wigle_configured":
            bool(
                WIGLE_USER
                and WIGLE_TOKEN
            ),

        "ipapidev_key_configured":
            bool(IPAPIDEV_KEY)

    }


# =========================================================
# IP PROVIDER 1
# IP-API.DEV
# =========================================================

def lookup_ip_ipapidev(ip):

    headers = {

        "Accept":
            "application/json",

        "User-Agent":
            "ArgusScope/3.2"

    }

    if IPAPIDEV_KEY:

        headers["X-API-Key"] = IPAPIDEV_KEY


    try:

        response = requests.get(

            "https://ip-api.dev/api",

            params={
                "q": ip
            },

            headers=headers,

            timeout=REQUEST_TIMEOUT

        )

    except requests.RequestException as exc:

        return {

            "success":
                False,

            "provider":
                "ip-api.dev",

            "error":
                str(exc)

        }


    if response.status_code == 429:

        return {

            "success":
                False,

            "provider":
                "ip-api.dev",

            "error":
                "Provider rate limit reached."

        }


    if response.status_code in (401, 403):

        return {

            "success":
                False,

            "provider":
                "ip-api.dev",

            "error":
                "Provider authentication or access restriction."

        }


    if response.status_code != 200:

        return {

            "success":
                False,

            "provider":
                "ip-api.dev",

            "error":
                f"Provider returned HTTP "
                f"{response.status_code}."

        }


    data = safe_json(response)


    if not isinstance(data, dict):

        return {

            "success":
                False,

            "provider":
                "ip-api.dev",

            "error":
                "Provider returned invalid JSON."

        }


    # -----------------------------------------------------
    # LOCATION OBJECT
    # -----------------------------------------------------

    location = data.get(
        "location"
    )

    if not isinstance(
        location,
        dict
    ):

        location = {}


    latitude = location.get(
        "latitude"
    )

    longitude = location.get(
        "longitude"
    )


    # -----------------------------------------------------
    # FALLBACK FOR ALTERNATIVE RESPONSE FORMATS
    # -----------------------------------------------------

    if latitude is None:

        latitude = data.get(
            "latitude"
        )

    if longitude is None:

        longitude = data.get(
            "longitude"
        )


    if latitude is None:

        latitude = data.get(
            "lat"
        )

    if longitude is None:

        longitude = data.get(
            "lon"
        )


    if (
        latitude is None
        or longitude is None
    ):

        return {

            "success":
                False,

            "provider":
                "ip-api.dev",

            "error":
                "Provider returned no geographic coordinates."

        }


    try:

        latitude = float(
            latitude
        )

        longitude = float(
            longitude
        )

    except (
        TypeError,
        ValueError
    ):

        return {

            "success":
                False,

            "provider":
                "ip-api.dev",

            "error":
                "Provider returned invalid coordinates."

        }


    # -----------------------------------------------------
    # ORGANIZATION
    # -----------------------------------------------------

    organization = data.get(
        "organization"
    )

    if isinstance(
        organization,
        dict
    ):

        organization_name = (
            organization.get("name")
        )

    else:

        organization_name = (
            organization
        )


    # -----------------------------------------------------
    # ASN
    # -----------------------------------------------------

    asn_data = data.get(
        "asn"
    )

    if isinstance(
        asn_data,
        dict
    ):

        asn_number = (
            asn_data.get("number")
        )

        asn_name = (
            asn_data.get("name")
        )

    else:

        asn_number = asn_data
        asn_name = None


    if asn_number:

        asn = (
            str(asn_number)
            if str(asn_number).upper().startswith("AS")
            else f"AS{asn_number}"
        )

    else:

        asn = None


    if not organization_name:

        organization_name = asn_name


    # -----------------------------------------------------
    # COUNTRY
    # -----------------------------------------------------

    country = (
        location.get("country_name")
        or location.get("country")
        or data.get("country_name")
        or data.get("country")
    )


    country_code = (
        location.get("country_code")
        or location.get("countryCode")
        or data.get("country_code")
        or data.get("countryCode")
    )


    # -----------------------------------------------------
    # REGION
    # -----------------------------------------------------

    region = (
        location.get("state")
        or location.get("region")
        or data.get("region")
    )


    # -----------------------------------------------------
    # CITY
    # -----------------------------------------------------

    city = (
        location.get("city")
        or data.get("city")
    )


    # -----------------------------------------------------
    # POSTAL
    # -----------------------------------------------------

    postal = (
        location.get("zip")
        or location.get("postal")
        or data.get("zip")
        or data.get("postal")
    )


    # -----------------------------------------------------
    # TIMEZONE
    # -----------------------------------------------------

    timezone = (
        location.get("timezone")
        or data.get("timezone")
    )


    # -----------------------------------------------------
    # RESPONSE
    # -----------------------------------------------------

    return {

        "success":
            True,

        "ip":
            data.get(
                "ip",
                ip
            ),

        "latitude":
            latitude,

        "longitude":
            longitude,

        "city":
            city,

        "region":
            region,

        "country":
            country,

        "country_code":
            country_code,

        "postal":
            postal,

        "timezone":
            timezone,

        "isp":
            organization_name,

        "org":
            organization_name,

        "asn":
            asn,

        "confidence":
            "Approximate IP geolocation",

        "accuracy_radius_m":
            None,

        "source":
            "ip-api.dev"

    }


# =========================================================
# IP PROVIDER 2
# IPAPI.CO
# =========================================================

def lookup_ip_ipapi(ip):

    try:

        response = requests.get(

            f"https://ipapi.co/{ip}/json/",

            headers={

                "Accept":
                    "application/json",

                "User-Agent":
                    "ArgusScope/3.2"

            },

            timeout=REQUEST_TIMEOUT

        )

    except requests.RequestException as exc:

        return {

            "success":
                False,

            "provider":
                "ipapi.co",

            "error":
                str(exc)

        }


    if response.status_code == 429:

        return {

            "success":
                False,

            "provider":
                "ipapi.co",

            "error":
                "Provider rate limit reached."

        }


    if response.status_code != 200:

        return {

            "success":
                False,

            "provider":
                "ipapi.co",

            "error":
                f"Provider returned HTTP "
                f"{response.status_code}."

        }


    data = safe_json(
        response
    )


    if not isinstance(
        data,
        dict
    ):

        return {

            "success":
                False,

            "provider":
                "ipapi.co",

            "error":
                "Provider returned invalid JSON."

        }


    if data.get("error"):

        return {

            "success":
                False,

            "provider":
                "ipapi.co",

            "error":
                data.get(
                    "reason",
                    "Provider could not resolve the IP."
                )

        }


    latitude = data.get(
        "latitude"
    )

    longitude = data.get(
        "longitude"
    )


    if (
        latitude is None
        or longitude is None
    ):

        return {

            "success":
                False,

            "provider":
                "ipapi.co",

            "error":
                "Provider returned no geographic coordinates."

        }


    try:

        latitude = float(
            latitude
        )

        longitude = float(
            longitude
        )

    except (
        TypeError,
        ValueError
    ):

        return {

            "success":
                False,

            "provider":
                "ipapi.co",

            "error":
                "Provider returned invalid coordinates."

        }


    return {

        "success":
            True,

        "ip":
            data.get(
                "ip",
                ip
            ),

        "latitude":
            latitude,

        "longitude":
            longitude,

        "city":
            data.get(
                "city"
            ),

        "region":
            data.get(
                "region"
            ),

        "country":
            data.get(
                "country_name"
            ),

        "country_code":
            data.get(
                "country_code"
            ),

        "postal":
            data.get(
                "postal"
            ),

        "timezone":
            data.get(
                "timezone"
            ),

        "isp":
            data.get(
                "org"
            ),

        "org":
            data.get(
                "org"
            ),

        "asn":
            data.get(
                "asn"
            ),

        "confidence":
            "Approximate IP geolocation",

        "accuracy_radius_m":
            5000,

        "source":
            "ipapi.co"

    }


# =========================================================
# IP PROVIDER 3
# IPWHO.IS
# =========================================================

def lookup_ip_ipwhois(ip):

    try:

        response = requests.get(

            f"https://ipwho.is/{ip}",

            headers={

                "Accept":
                    "application/json",

                "User-Agent":
                    "ArgusScope/3.2"

            },

            timeout=REQUEST_TIMEOUT

        )

    except requests.RequestException as exc:

        return {

            "success":
                False,

            "provider":
                "ipwho.is",

            "error":
                str(exc)

        }


    if response.status_code == 429:

        return {

            "success":
                False,

            "provider":
                "ipwho.is",

            "error":
                "Provider rate limit reached."

        }


    if response.status_code != 200:

        return {

            "success":
                False,

            "provider":
                "ipwho.is",

            "error":
                f"Provider returned HTTP "
                f"{response.status_code}."

        }


    data = safe_json(
        response
    )


    if not isinstance(
        data,
        dict
    ):

        return {

            "success":
                False,

            "provider":
                "ipwho.is",

            "error":
                "Provider returned invalid JSON."

        }


    if not data.get(
        "success",
        False
    ):

        return {

            "success":
                False,

            "provider":
                "ipwho.is",

            "error":
                data.get(
                    "message",
                    "Provider could not resolve the IP."
                )

        }


    latitude = data.get(
        "latitude"
    )

    longitude = data.get(
        "longitude"
    )


    if (
        latitude is None
        or longitude is None
    ):

        return {

            "success":
                False,

            "provider":
                "ipwho.is",

            "error":
                "Provider returned no coordinates."

        }


    try:

        latitude = float(
            latitude
        )

        longitude = float(
            longitude
        )

    except (
        TypeError,
        ValueError
    ):

        return {

            "success":
                False,

            "provider":
                "ipwho.is",

            "error":
                "Provider returned invalid coordinates."

        }


    timezone = data.get(
        "timezone"
    )

    connection = data.get(
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


    return {

        "success":
            True,

        "ip":
            data.get(
                "ip",
                ip
            ),

        "latitude":
            latitude,

        "longitude":
            longitude,

        "city":
            data.get(
                "city"
            ),

        "region":
            data.get(
                "region"
            ),

        "country":
            data.get(
                "country"
            ),

        "country_code":
            data.get(
                "country_code"
            ),

        "postal":
            data.get(
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

        "asn":
            connection.get(
                "asn"
            ),

        "confidence":
            "Approximate IP geolocation",

        "accuracy_radius_m":
            5000,

        "source":
            "ipwho.is"

    }


# =========================================================
# IP LOOKUP
# =========================================================

@app.get("/api/v1/locate-ip")
def locate_ip(ip: str):

    ip = ip.strip()


    # =====================================================
    # VALIDATION
    # =====================================================

    if not is_valid_ip(ip):

        return {

            "success":
                False,

            "error":
                "Invalid IP address."

        }


    # =====================================================
    # PUBLIC IP CHECK
    # =====================================================

    if not is_public_ip(ip):

        return {

            "success":
                False,

            "error":
                "Private or non-routable IP addresses "
                "cannot be geolocated."

        }


    # =====================================================
    # CACHE
    # =====================================================

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
    # PROVIDER 1
    # =====================================================

    provider_1 = lookup_ip_ipapidev(
        ip
    )


    if provider_1.get(
        "success"
    ):

        provider_1["cached"] = False

        cache_set(

            IP_CACHE,

            ip,

            provider_1

        )

        return provider_1


    # =====================================================
    # PROVIDER 2
    # =====================================================

    provider_2 = lookup_ip_ipapi(
        ip
    )


    if provider_2.get(
        "success"
    ):

        provider_2["cached"] = False

        cache_set(

            IP_CACHE,

            ip,

            provider_2

        )

        return provider_2


    # =====================================================
    # PROVIDER 3
    # =====================================================

    provider_3 = lookup_ip_ipwhois(
        ip
    )


    if provider_3.get(
        "success"
    ):

        provider_3["cached"] = False

        cache_set(

            IP_CACHE,

            ip,

            provider_3

        )

        return provider_3


    # =====================================================
    # ALL FAILED
    # =====================================================

    details = []


    for provider in (
        provider_1,
        provider_2,
        provider_3
    ):

        name = provider.get(
            "provider",
            "unknown"
        )

        error = provider.get(
            "error",
            "Unknown provider error."
        )

        details.append(
            f"{name}: {error}"
        )


    return {

        "success":
            False,

        "error":
            "No IP geolocation provider "
            "could resolve this address.",

        "details":
            details

    }


# =========================================================
# WIGLE BSSID LOOKUP
# =========================================================

@app.get("/api/v1/locate-bssid")
def locate_bssid(netid: str):

    target_mac = normalize_bssid(
        netid
    )


    if not target_mac:

        return {

            "success":
                False,

            "error":
                "Invalid BSSID format. Expected "
                "AA:BB:CC:DD:EE:FF."

        }


    # =====================================================
    # CACHE
    # =====================================================

    cached = cache_get(

        BSSID_CACHE,

        target_mac,

        BSSID_CACHE_TTL

    )


    if cached:

        result = cached.copy()

        result["source"] = (
            "ArgusScope Cache"
        )

        result["cached"] = True

        return result


    # =====================================================
    # CREDENTIAL CHECK
    # =====================================================

    if (
        not WIGLE_USER
        or not WIGLE_TOKEN
    ):

        return {

            "success":
                False,

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
            "ArgusScope/3.2"

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

            "success":
                False,

            "error":
                f"WiGLE request failed: "
                f"{str(exc)}"

        }


    if response.status_code == 429:

        return {

            "success":
                False,

            "error":
                "WiGLE rate limit exceeded. "
                "Please wait before trying again."

        }


    if response.status_code in (
        401,
        403
    ):

        return {

            "success":
                False,

            "error":
                "WiGLE authentication failed. "
                "Check the Render environment variables."

        }


    if response.status_code != 200:

        return {

            "success":
                False,

            "error":
                f"WiGLE returned HTTP "
                f"{response.status_code}."

        }


    data = safe_json(
        response
    )


    if not isinstance(
        data,
        dict
    ):

        return {

            "success":
                False,

            "error":
                "WiGLE returned invalid JSON."

        }


    results = data.get(
        "results"
    )


    if not data.get(
        "success"
    ) or not results:

        return {

            "success":
                False,

            "error":
                "BSSID not found in the WiGLE database."

        }


    result = results[0]


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

            "success":
                False,

            "error":
                "WiGLE returned a result without coordinates."

        }


    try:

        latitude = float(
            latitude
        )

        longitude = float(
            longitude
        )

    except (
        TypeError,
        ValueError
    ):

        return {

            "success":
                False,

            "error":
                "WiGLE returned invalid coordinates."

        }


    observations = result.get(
        "count",
        1
    )


    try:

        observations = int(
            observations
        )

    except (
        TypeError,
        ValueError
    ):

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

        "success":
            True,

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

    if (
        not WIGLE_USER
        or not WIGLE_TOKEN
    ):

        return {

            "success":
                False,

            "error":
                "WiGLE API credentials are not configured "
                "on the Render server."

        }


    if not payload.scans:

        return {

            "success":
                False,

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
            "ArgusScope/3.2"

    }


    valid_points = []


    # =====================================================
    # PROCESS SCANS
    # =====================================================

    for scan in payload.scans:

        clean_mac = normalize_bssid(
            scan.netid
        )


        if not clean_mac:
            continue


        # -------------------------------------------------
        # CACHE
        # -------------------------------------------------

        cached = cache_get(

            BSSID_CACHE,

            clean_mac,

            BSSID_CACHE_TTL

        )


        if cached:

            latitude = cached.get(
                "latitude"
            )

            longitude = cached.get(
                "longitude"
            )

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


            data = safe_json(
                response
            )


            if not isinstance(
                data,
                dict
            ):

                continue


            if not (
                data.get("success")
                and data.get("results")
            ):

                continue


            result = data[
                "results"
            ][0]


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


            try:

                latitude = float(
                    latitude
                )

                longitude = float(
                    longitude
                )

            except (
                TypeError,
                ValueError
            ):

                continue


            observations = result.get(
                "count",
                1
            )


            try:

                observations = int(
                    observations
                )

            except (
                TypeError,
                ValueError
            ):

                observations = 1


            cache_set(

                BSSID_CACHE,

                clean_mac,

                {

                    "success":
                        True,

                    "bssid":
                        result.get(
                            "netid",
                            clean_mac
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

                    "observations":
                        observations,

                    "source":
                        "WiGLE"

                }

            )


        # -------------------------------------------------
        # VALIDATE
        # -------------------------------------------------

        try:

            latitude = float(
                latitude
            )

            longitude = float(
                longitude
            )

        except (
            TypeError,
            ValueError
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
                latitude,

            "longitude":
                longitude,

            "weight":
                weight

        })


    # =====================================================
    # NO POINTS
    # =====================================================

    if not valid_points:

        return {

            "success":
                False,

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

    count = len(
        valid_points
    )


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

        "success":
            True,

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
        "IP providers:"
    )

    print(
        "  1. ip-api.dev"
    )

    print(
        "  2. ipapi.co"
    )

    print(
        "  3. ipwho.is"
    )

    print(
        f"ip-api.dev key configured: "
        f"{bool(IPAPIDEV_KEY)}"
    )

    print(
        f"WiGLE configured: "
        f"{bool(WIGLE_USER and WIGLE_TOKEN)}"
    )

    print(
        "=========================================="
    )
