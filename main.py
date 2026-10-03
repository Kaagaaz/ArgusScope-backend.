from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import socket
import os

app = FastAPI(title="ArgusScope WiGLE Recon Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Set these in your Render Environment Variables
WIGLE_API_NAME = os.getenv("WIGLE_API_NAME", "YOUR_WIGLE_AID")
WIGLE_API_SECRET = os.getenv("WIGLE_API_SECRET", "YOUR_WIGLE_SECRET")

@app.get("/")
def read_root():
    return {"status": "ArgusScope WiGLE Engine Active"}

# 1. WiGLE Wi-Fi BSSID Precision Lookup
@app.get("/api/v1/locate-bssid")
async def locate_bssid(netid: str):
    """
    Look up a Wi-Fi MAC Address (BSSID) via WiGLE.
    Format expected: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
    """
    clean_bssid = netid.strip().upper()
    url = f"https://api.wigle.net/api/v2/network/search?netid={clean_bssid}"
    
    auth = (WIGLE_API_NAME, WIGLE_API_SECRET)
    
    async with httpx.AsyncClient(timeout=6.0) as client:
        try:
            res = await client.get(url, auth=auth)
            data = res.json()
            
            if data.get("success") and data.get("resultCount", 0) > 0:
                net_info = data["results"][0]
                return {
                    "source": "WiGLE Global Wi-Fi Registry",
                    "bssid": clean_bssid,
                    "ssid": net_info.get("ssid", "Hidden/Unknown"),
                    "latitude": round(net_info["trilat"], 5),
                    "longitude": round(net_info["trilong"], 5),
                    "accuracy_radius_m": 25,
                    "confidence": "HIGH (Wi-Fi Physical Triangulation)",
                    "last_seen": net_info.get("lastupdt")
                }
            else:
                return {"error": "BSSID not found in WiGLE database"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

# 2. Multi-Source IP Fallback Endpoint
@app.get("/api/v1/locate-ip")
async def locate_ip(ip: str):
    target_ip = ip.strip()
    try:
        target_ip = socket.gethostbyname(target_ip)
    except Exception: pass

    async with httpx.AsyncClient(timeout=4.0) as client:
        try:
            r = await client.get(f"http://ip-api.com/json/{target_ip}?fields=status,country,city,lat,lon,org")
            d = r.json()
            if d.get("status") == "success":
                return {
                    "ip": target_ip,
                    "latitude": float(d["lat"]),
                    "longitude": float(d["lon"]),
                    "accuracy_radius_m": 8000,
                    "city": d.get("city", "Unknown"),
                    "country": d.get("country", "Unknown"),
                    "org": d.get("org", "Unknown ISP"),
                    "confidence": "REGIONAL (ISP Routing Gateway)"
                }
        except Exception: pass
            
    return {"error": "Target resolution failed"}
