from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx
import socket
import re
import asyncio

app = FastAPI(title="ArgusScope Recon Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Common IATA airport/city code mappings found in ISP rDNS hostnames
IATA_CITY_MAP = {
    "bom": "Mumbai", "del": "Delhi", "ccu": "Kolkata", "maa": "Chennai",
    "blr": "Bengaluru", "hyd": "Hyderabad", "gau": "Guwahati", "pat": "Patna",
    "ixa": "Agartala", "dmv": "Dimapur", "scl": "Silchar", "lhr": "London",
    "jfk": "New York", "sin": "Singapore", "hkg": "Hong Kong"
}

def parse_rdns_city(hostname: str) -> str:
    """Extract potential city location from rDNS ISP hostname patterns."""
    if not hostname or hostname == "N/A":
        return None
    hostname_lower = hostname.lower()
    for code, city in IATA_CITY_MAP.items():
        if re.search(r'[\.\-\_]' + code + r'[\.\-\_]', hostname_lower):
            return f"{city} (via rDNS code: {code.upper()})"
    return None

async def fetch_ip_api(client: httpx.AsyncClient, ip: str):
    try:
        res = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,org,as,query")
        data = res.json()
        if data.get("status") == "success":
            return {
                "source": "IP-API",
                "lat": float(data["lat"]),
                "lon": float(data["lon"]),
                "city": data.get("city"),
                "country": data.get("country"),
                "org": data.get("org") or data.get("as")
            }
    except Exception:
        pass
    return None

async def fetch_ipinfo(client: httpx.AsyncClient, ip: str):
    try:
        res = await client.get(f"https://ipinfo.io/{ip}/json")
        data = res.json()
        if "loc" in data:
            lat, lon = map(float, data["loc"].split(","))
            return {
                "source": "IPInfo",
                "lat": lat,
                "lon": lon,
                "city": data.get("city"),
                "country": data.get("country"),
                "org": data.get("org")
            }
    except Exception:
        pass
    return None

@app.get("/")
def read_root():
    return {"status": "ArgusScope Recon Engine Active"}

@app.get("/api/v1/locate-ip")
async def locate_ip(ip: str):
    target_input = ip.strip()
    target_ip = target_input

    # 1. Resolve Domain Name to IP if necessary
    try:
        target_ip = socket.gethostbyname(target_input)
    except Exception:
        pass

    # 2. Reverse DNS Lookup (PTR Record)
    rdns_hostname = "N/A"
    try:
        rdns_hostname = socket.gethostbyaddr(target_ip)[0]
    except Exception:
        pass

    rdns_inferred_city = parse_rdns_city(rdns_hostname)

    # 3. Query Geolocation APIs Concurrently
    async with httpx.AsyncClient(timeout=4.0) as client:
        results = await asyncio.gather(
            fetch_ip_api(client, target_ip),
            fetch_ipinfo(client, target_ip),
            return_exceptions=True
        )

    valid_results = [r for r in results if isinstance(r, dict) and r is not None]

    if not valid_results:
        return {"ip": target_ip, "error": "Unable to locate target IP"}

    # 4. Calculate Consensus Coordinates & Dispersion (Accuracy Radius)
    avg_lat = sum(r["lat"] for r in valid_results) / len(valid_results)
    avg_lon = sum(r["lon"] for r in valid_results) / len(valid_results)

    # Estimate uncertainty radius based on provider disagreement (minimum 8km)
    max_delta = 0.0
    for r in valid_results:
        delta = ((r["lat"] - avg_lat)**2 + (r["lon"] - avg_lon)**2) ** 0.5
        if delta > max_delta:
            max_delta = delta
            
    # Convert lat/lon delta to approximate radius in meters
    radius_meters = max(int(max_delta * 111000), 8000)

    # Determine confidence classification
    if len(valid_results) > 1 and max_delta < 0.1:
        confidence = "HIGH (Multi-Source Alignment)"
    elif len(valid_results) > 1:
        confidence = "MODERATE (Provider Variance Detected)"
    else:
        confidence = "LOW (Single-Source Data)"

    primary = valid_results[0]

    return {
        "ip": target_ip,
        "domain": target_input if target_input != target_ip else "N/A",
        "hostname": rdns_hostname,
        "rdns_city_hint": rdns_inferred_city or "None Detected",
        "latitude": round(avg_lat, 5),
        "longitude": round(avg_lon, 5),
        "accuracy_radius_m": radius_meters,
        "confidence": confidence,
        "city": primary.get("city") or "Unknown",
        "country": primary.get("country") or "Unknown",
        "org": primary.get("org") or "Unknown ISP",
        "sources_queried": len(valid_results)
    }
