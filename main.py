from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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

WIGLE_API_NAME = os.getenv("WIGLE_API_NAME", "AID6e5791df2387dceeda23c5bcfaf11417")
WIGLE_API_SECRET = os.getenv("WIGLE_API_SECRET", "461432f3d06b1726fdfb6298b0a0c60a")

@app.get("/")
def read_root():
    return {"status": "ArgusScope WiGLE Engine Online"}

@app.get("/api/v1/locate-bssid")
async def locate_bssid(netid: str):
    """
    Looks up Wi-Fi BSSID (MAC address) via WiGLE.
    Accepts formats: 00:11:22:33:44:55 or 00-11-22-33-44-55
    """
    clean_bssid = netid.strip().upper()
    url = f"https://api.wigle.net/api/v2/network/search?netid={clean_bssid}"
    
    auth = (WIGLE_API_NAME, WIGLE_API_SECRET)
    
    async with httpx.AsyncClient(timeout=8.0) as client:
        try:
            res = await client.get(url, auth=auth)
            data = res.json()
            
            if data.get("success") and data.get("resultCount", 0) > 0:
                net_info = data["results"][0]
                return {
                    "source": "WiGLE Global Wi-Fi Registry",
                    "bssid": clean_bssid,
                    "ssid": net_info.get("ssid") or "Hidden / Unnamed Network",
                    "latitude": round(float(net_info["trilat"]), 5),
                    "longitude": round(float(net_info["trilong"]), 5),
                    "accuracy_radius_m": 25,
                    "confidence": "HIGH (Physical Wi-Fi Triangulation)",
                    "last_updated": net_info.get("lastupdt")
                }
            else:
                return {"error": "BSSID not found in WiGLE database"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

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
                    "confidence": "REGIONAL (ISP Gateway)"
                }
        except Exception: pass
            
    return {"error": "Target resolution failed"}
