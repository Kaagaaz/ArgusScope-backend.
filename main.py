import os
import time
import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="ArgusScope Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

WIGLE_USER = os.getenv("WIGLE_API_USER", "")
WIGLE_TOKEN = os.getenv("WIGLE_API_KEY", "")

# In-memory TTL cache to eliminate redundant calls and block 429 loops
SEARCH_CACHE = {}
CACHE_TTL_SECONDS = 600  # 10 minutes cache duration

def sanitize_mac(mac: str) -> str:
    """Normalizes MAC addresses into standard colon-separated lowercase format."""
    return mac.strip().lower().replace("-", ":")

@app.get("/")
def read_root():
    return {"status": "ArgusScope High-Precision Intelligence Engine Online"}

@app.get("/api/v1/locate-bssid")
async def locate_bssid(netid: str):
    target_mac = sanitize_mac(netid)
    
    # 1. Check Cache Layer
    now = time.time()
    if target_mac in SEARCH_CACHE:
        cached = SEARCH_CACHE[target_mac]
        if now - cached["timestamp"] < CACHE_TTL_SECONDS:
            res_data = cached["data"].copy()
            res_data["source"] = "Cache (Optimized)"
            return res_data
        else:
            del SEARCH_CACHE[target_mac]

    url = "https://api.wigle.net/api/v2/network/search"
    
    # 2. Provide fallback global search boundaries so WiGLE accepts the query parameter filter
    params = {
        "netid": target_mac,
        "resultsPerPage": 1,
        "latrange1": -90.0,
        "latrange2": 90.0,
        "longrange1": -180.0,
        "longrange2": 180.0
    }
    headers = {"Accept": "application/json"}
    
    try:
        if not WIGLE_USER or not WIGLE_TOKEN:
            return {"error": "WiGLE API credentials not configured on server backend."}
            
        response = requests.get(url, params=params, headers=headers, auth=(WIGLE_USER, WIGLE_TOKEN))
        
        if response.status_code == 429:
            return {"error": "WiGLE rate limit exceeded (429). Please wait a moment."}
            
        if response.status_code != 200:
            return {"error": f"WiGLE API error: Status code {response.status_code}"}
            
        data = response.json()
        
        if data.get("success") and data.get("results") and len(data["results"]) > 0:
            result = data["results"][0]
            
            # 3. Dynamic Precision & Confidence Evaluation
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
            
            # Store payload in cache
            SEARCH_CACHE[target_mac] = {"timestamp": now, "data": payload}
            return payload
        else:
            return {"error": "Target BSSID not cataloged in WiGLE database."}
            
    except Exception as e:
        return {"error": f"Internal routing failure: {str(e)}"}

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
