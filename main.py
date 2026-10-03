from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx
import socket

app = FastAPI(title="ArgusScope API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"status": "ArgusScope API is live"}

@app.get("/api/v1/locate-ip")
async def locate_ip(ip: str):
    target_ip = ip.strip()

    # Resolve domain names (e.g. google.com) to IP addresses
    try:
        target_ip = socket.gethostbyname(target_ip)
    except Exception:
        pass

    async with httpx.AsyncClient(timeout=5.0) as client:
        # Primary lookup: ip-api.com
        try:
            res1 = await client.get(f"http://ip-api.com/json/{target_ip}")
            data1 = res1.json()
            if data1.get("status") == "success":
                return {
                    "ip": target_ip,
                    "latitude": data1.get("lat"),
                    "longitude": data1.get("lon"),
                    "city": data1.get("city"),
                    "country": data1.get("country"),
                    "org": data1.get("org")
                }
        except Exception:
            pass

        # Secondary lookup: ipinfo.io fallback
        try:
            res2 = await client.get(f"https://ipinfo.io/{target_ip}/json")
            data2 = res2.json()
            if "loc" in data2:
                lat, lon = map(float, data2["loc"].split(","))
                return {
                    "ip": target_ip,
                    "latitude": lat,
                    "longitude": lon,
                    "city": data2.get("city"),
                    "country": data2.get("country"),
                    "org": data2.get("org")
                }
        except Exception:
            pass

    return {"ip": target_ip, "error": "Unable to resolve target IP or domain"}
