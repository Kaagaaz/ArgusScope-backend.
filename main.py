import os
import time
import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List

app = FastAPI(title="ArgusScope High-Precision Intelligence Engine", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Environment credentials
WIGLE_USER = os.getenv("WIGLE_API_USER", "")
WIGLE_TOKEN = os.getenv("WIGLE_API_KEY", "")

# In-memory TTL cache to mitigate 429 rate limits and speed up responses
SEARCH_CACHE = {}
CACHE_TTL_SECONDS = 600  # 10 minutes cache duration

class ScanTarget(BaseModel):
    netid: str
    rssi: int = -70  # Default signal strength fallback

class MultiBSSIDRequest(BaseModel):
    scans: List[ScanTarget]

def sanitize_mac(mac: str) -> str:
    """Normalizes MAC addresses into standard colon-separated lowercase format."""
    return mac.strip().lower().replace("-", ":")

@app.get("/")
def read_root():
    return {
        "status": "ArgusScope Advanced Recon Engine Online",
        "capabilities": ["Single BSSID Lookup", "IP Geolocation", "Multi-Point Centroid Fusion", "TTL Caching"]
    }

@app.get("/api/v1/locate-bssid")
async def locate_bssid(netid: str):
    target_mac = sanitize_mac(netid)
    
    # 1. Check Memory Cache Layer
    now = time.time()
    if target_mac in SEARCH_CACHE:
        cached = SEARCH_CACHE[target_mac]
        if now - cached["timestamp"] < CACHE_TTL_SECONDS:
            res_data = cached["data"].copy()
            res_data["source"] = "Cache (Optimized Memory)"
            return res_data
        else:
            del SEARCH_CACHE[target_mac]

    url = "https://api.wigle.net/api/v2/network/search"
    params = {
        "netid": target_mac,
        "resultsPerPage": 1,
        "latrange1": -90.0, "latrange2": 90.0,
        "longrange1": -180.0, "longrange2": 180.0
    }
    headers = {"Accept": "application/json"}
    
    try:
        if not WIGLE_USER or not WIGLE_TOKEN:
            return {"error": "WiGLE API credentials not configured on server backend."}
            
        response = requests.get(url, params=params, headers=headers, auth=(WIGLE_USER, WIGLE_TOKEN))
        
        if response.status_code == 429:
            return {"error": "WiGLE rate limit exceeded (429). Cooling down cache active."}
            
        if response.status_code != 200:
            return {"error": f"WiGLE API error: Status code {response.status_code}"}
            
        data = response.json()
        
        if data.get("success") and data.get("results") and len(data["results"]) > 0:
            result = data["results"][0]
            
            # 2. Dynamic Confidence & Precision Calculation
            obs_count = result.get("count", 1)
            if obs_count > 40:
                radius = 12
                confidence = "High (Dense Telemetry Cluster)"
            elif obs_count > 5:
                radius = 25
                confidence = "Medium-High (Standard Triangulation)"
            else:
                radius = 50
                confidence = "Low-Medium (Sparse Observation)"

            payload = {
                "bssid": result.get("netid"),
                "ssid": result.get("ssid", "Unknown Network"),
                "latitude": result.get("trilat"),
                "longitude": result.get("trilong"),
                "accuracy_radius_m": radius,
                "confidence": confidence,
                "observations": obs_count,
                "source": "WiGLE Live Database"
            }
            
            SEARCH_CACHE[target_mac] = {"timestamp": now, "data": payload}
            return payload
        else:
            return {"error": "Target BSSID not cataloged in WiGLE database."}
            
    except Exception as e:
        return {"error": f"Internal routing failure: {str(e)}"}

@app.post("/api/v1/triangulate-cluster")
async def triangulate_cluster(payload: MultiBSSIDRequest):
    """
    Performs advanced multi-point sensor fusion by querying multiple BSSIDs 
    and computing an RSSI-weighted geographic centroid.
    """
    if not WIGLE_USER or not WIGLE_TOKEN:
        return {"error": "WiGLE API credentials not configured on server backend."}

    url = "https://api.wigle.net/api/v2/network/search"
    headers = {"Accept": "application/json"}
    
    valid_points = []
    total_weight = 0

    for scan in payload.scans:
        clean_mac = sanitize_mac(scan.netid)
        params = {
            "netid": clean_mac,
            "resultsPerPage": 1,
            "latrange1": -90.0, "latrange2": 90.0,
            "longrange1": -180.0, "longrange2": 180.0
        }
        
        try:
            response = requests.get(url, params=params, headers=headers, auth=(WIGLE_USER, WIGLE_TOKEN))
            if response.status_code == 200:
                data = response.json()
                if data.get("success") and data.get("results"):
                    res = data["results"][0]
                    lat = res.get("trilat")
                    lon = res.get("trilong")
                    if lat and lon:
                        weight = max(1, 100 - abs(scan.rssi))
                        valid_points.append({"lat": lat, "lon": lon, "weight": weight})
                        total_weight += weight
        except Exception:
            continue

    if not valid_points:
        return {"error": "No valid coordinates resolved from the provided BSSID cluster."}

    # RSSI-weighted geographic centroid computation
    weighted_lat = sum(p["lat"] * p["weight"] for p in valid_points) / total_weight
    weighted_lon = sum(p["lon"] * p["weight"] for p in valid_points) / total_weight

    return {
        "cluster_size": len(valid_points),
        "latitude": weighted_lat,
        "longitude": weighted_lon,
        "accuracy_radius_m": max(5, 30 - (len(valid_points) * 5)),
        "confidence": f"High (Multi-Point Fusion Across {len(valid_points)} Nodes)",
        "source": "WiGLE Cluster Centroid Calculation"
    }

@app.get("/api/v1/locate-ip")
async def locate_ip(ip: str):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}")
        ip_data = res.json()
        if ip_data.get("status") == "success":
            return {
                "ip": ip_data.get("query"),
                "latitude": ip_data.get("lat"),
                "longitude": ip_data.get("lon"),
                "city": ip_data.get("city"),
                "country": ip_data.get("country"),
                "confidence": "Medium (Regional ISP Geolocation)",
                "accuracy_radius_m": 5000,
                "source": "IP-API Geo Lookup"
            }
        else:
            return {"error": "IP target resolution failed."}
    except Exception as e:
        return {"error": str(e)}
