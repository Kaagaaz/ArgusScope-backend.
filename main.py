import os
import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="ArgusScope Backend")

# Enable CORS to allow requests from your frontend (GitHub Pages or local)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load WiGLE API credentials from Render environment variables
WIGLE_USER = os.getenv("WIGLE_API_USER", "")
WIGLE_TOKEN = os.getenv("WIGLE_API_KEY", "")

@app.get("/")
def read_root():
    return {"status": "ArgusScope Recon Engine Online"}

@app.get("/api/v1/locate-bssid")
async def locate_bssid(netid: str):
    url = f"https://api.wigle.net/api/v2/network/search?netid={netid}"
    headers = {"Accept": "application/json"}
    
    try:
        # Authenticate using HTTP Basic Auth (API Name as username, API Token as password)
        response = requests.get(url, headers=headers, auth=(WIGLE_USER, WIGLE_TOKEN))
        
        # DEBUG PRINT: This will show up directly in your Render Live Logs
        print("WiGLE Response Code:", response.status_code)
        print("WiGLE Response Text:", response.text)
        
        if response.status_code != 200:
            return {"error": f"WiGLE API failed with status {response.status_code}"}
            
        data = response.json()
        
        # Check if WiGLE returned valid results
        if data.get("success") and data.get("results") and len(data["results"]) > 0:
            result = data["results"][0]
            return {
                "bssid": result.get("netid"),
                "ssid": result.get("ssid", "Unknown SSID"),
                "latitude": result.get("trilat"),
                "longitude": result.get("trilong"),
                "accuracy_radius_m": 25,
                "confidence": "High (WiGLE Database Match)"
            }
        else:
            return {"error": "BSSID not found in WiGLE database."}
            
    except Exception as e:
        print("Exception during WiGLE request:", str(e))
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
                "confidence": "Medium (IP Geolocation)",
                "accuracy_radius_m": 5000
            }
        else:
            return {"error": "IP target resolution failed."}
    except Exception as e:
        return {"error": str(e)}
