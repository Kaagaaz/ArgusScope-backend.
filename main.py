import os
import time
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import requests

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

# In-memory cache dictionary: { "target_key": {"timestamp": float, "data": dict} }
SEARCH_CACHE = {}
CACHE_TTL_SECONDS = 300  # Cache results for 5 minutes to prevent 429 rate limits

def sanitize_mac(mac: str) -> str:
    """Cleans and normalizes user-submitted BSSIDs/MAC addresses."""
    cleaned = mac.strip().lower().replace("-", ":")
    return cleaned

@app.get("/")
def read_root():
    return {"status": "ArgusScope Recon Engine Online - Advanced Telemetry Active"}

@app.get("/api/v1/locate-bssid")
async def locate_bssid(netid: str):
    target_mac = sanitize_mac(netid)
    
    # 1. Check In-Memory Cache first (Mitigates rate limits)
    now = time.time()
    if target_mac in SEARCH_CACHE:
        cached_entry = SEARCH_CACHE[target_mac]
        if now - cached_entry["timestamp"] < CACHE_TTL_SECONDS:
            response_data = cached_entry["data"].copy()
            response_data["confidence"] = "High (Cached Memory Match)"
            return response_data
        else:
            del SEARCH_CACHE[target_mac]

    url = "https://api.wigle.net/api/v2/network/search"
    params = {"netid": target_mac, "resultsPerPage": 1}
    headers = {"Accept": "application/json"}
    
    try:
        if not WIGLE_USER or not WIGLE_TOKEN:
            return {"error": "WiGLE API credentials not configured on server backend."}
            
        response = requests.get(url, params=params, headers=headers, auth=(WIGLE_USER, WIGLE_TOKEN))
        
        if response.status_code == 429:
            return {"error": "WiGLE rate limit hit (429). Serving from cool-down protection."}
            
        if response.status_code != 200:
            return {"error": f"WiGLE rejected request (Status {response.status_code})"}
            
        data = response.json()
        
        if data.get("success") and data.get("results") and len(data["results"]) > 0:
            result = data["results"][0]
            
            # 2. Dynamic Accuracy & Confidence Modeling
            # Evaluates observation count to gauge confidence and adjust radius dynamically
            obs_count = result.get("count", 1)
            if obs_count > 50:
                accuracy_radius = 10
                confidence_level = "Very High (Dense Crowdsourced Triangulation)"
            elif obs_count > 10:
                accuracy_radius = 25
                confidence_level = "High (Verified WiGLE Database Match)"
            else:
                accuracy_radius = 50
                confidence_level = "Medium (Sparse Observation Match)"

            payload = {
                "bssid": result.get("netid"),
                "ssid": result.get("ssid", "Unknown SSID"),
                "latitude": result.get("trilat"),
                "longitude": result.get("trilong"),
                "accuracy_radius_m": accuracy_radius,
                "confidence": confidence_level,
                "observations": obs_count
            }
            
            # Save into cache
            SEARCH_CACHE[target_mac] = {"timestamp": now, "data": payload}
            return payload
        else:
            return {"error": "BSSID not found in WiGLE database."}
            
    except Exception as e:
        print("Error:", str(e))
        return {"error": "Internal server error connecting to WiGLE."}

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
                "confidence": "Medium (Regional IP Geolocation)",
                "accuracy_radius_m": 5000
            }
        else:
            return {"error": "IP target resolution failed."}
    except Exception as e:
        return {"error": str(e)}
