from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import httpx
import socket
import os

app = FastAPI(title="ArgusScope Recon & Google Triangulation Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Set GOOGLE_MAPS_API_KEY as an Environment Variable on Render
GOOGLE_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "YOUR_GOOGLE_MAPS_API_KEY")

class WifiAccessPoint(BaseModel):
    macAddress: str
    signalStrength: Optional[int] = None
    channel: Optional[int] = None

class GoogleGeolocatePayload(BaseModel):
    wifiAccessPoints: Optional[List[WifiAccessPoint]] = None
    considerIp: bool = True

@app.get("/")
def read_root():
    return {"status": "ArgusScope Recon & Google Engine Active"}

# Endpoint 1: High-Precision Google Wi-Fi / Cell Triangulation
@app.post("/api/v1/locate-google")
async def locate_google(payload: GoogleGeolocatePayload):
    if GOOGLE_API_KEY == "YOUR_GOOGLE_MAPS_API_KEY":
        raise HTTPException(status_code=500, detail="Google API Key not configured on backend.")

    url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={GOOGLE_API_KEY}"
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            res = await client.post(url, json=payload.dict(exclude_none=True))
            data = res.json()
            
            if "location" in data:
                return {
                    "source": "Google Geolocation Engine",
                    "latitude": round(data["location"]["lat"], 5),
                    "longitude": round(data["location"]["lng"], 5),
                    "accuracy_radius_m": data.get("accuracy", 50),
                    "confidence": "HIGH (Wi-Fi/Cellular Triangulation)" if payload.wifiAccessPoints else "MODERATE (IP Fallback)"
                }
            else:
                raise HTTPException(status_code=400, detail="Google API could not locate payload")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

# Endpoint 2: Multi-Source IP Consensus Fallback
@app.get("/api/v1/locate-ip")
async def locate_ip(ip: str):
    target_ip = ip.strip()
    try:
        target_ip = socket.gethostbyname(target_ip)
    except Exception:
        pass

    async with httpx.AsyncClient(timeout=4.0) as client:
        try:
            r = await client.get(f"http://ip-api.com/json/{target_ip}?fields=status,country,city,lat,lon,org")
            d = r.json()
            if d.get("status") == "success":
                return {
                    "ip": target_ip,
                    "latitude": float(d["lat"]),
                    "longitude": float(d["lon"]),
                    "accuracy_radius_m": 10000,
                    "city": d.get("city", "Unknown"),
                    "country": d.get("country", "Unknown"),
                    "org": d.get("org", "Unknown ISP"),
                    "confidence": "REGIONAL (ISP Routing Gateway)"
                }
        except Exception:
            pass
            
    return {"error": "Target resolution failed"}
