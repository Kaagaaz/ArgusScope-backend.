from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image, ExifTags
import httpx
import io
import socket

app = FastAPI(title="ArgusScope API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def convert_to_decimal_degrees(value, ref):
    if not value:
        return None
    try:
        deg = float(value[0])
        minute = float(value[1])
        sec = float(value[2])
        decimal = deg + (minute / 60.0) + (sec / 3600.0)
        if ref in ['S', 'W']:
            decimal = -decimal
        return decimal
    except Exception:
        return None

@app.get("/")
def read_root():
    return {"status": "ArgusScope API is live"}

@app.post("/api/v1/extract-exif")
async def extract_exif(file: UploadFile = File(...)):
    try:
        image_bytes = await file.read()
        image = Image.open(io.BytesIO(image_bytes))
        exif = image._getexif()

        if not exif:
            return {"filename": file.filename, "latitude": None, "longitude": None, "message": "No EXIF data found"}

        gps_info = {}
        for tag, value in exif.items():
            tag_name = ExifTags.TAGS.get(tag, tag)
            if tag_name == 'GPSInfo':
                for gps_tag in value:
                    sub_tag = ExifTags.GPSTAGS.get(gps_tag, gps_tag)
                    gps_info[sub_tag] = value[gps_tag]

        lat_raw = gps_info.get('GPSLatitude')
        lat_ref = gps_info.get('GPSLatitudeRef')
        lng_raw = gps_info.get('GPSLongitude')
        lng_ref = gps_info.get('GPSLongitudeRef')

        if lat_raw and lat_ref and lng_raw and lng_ref:
            lat = convert_to_decimal_degrees(lat_raw, lat_ref)
            lng = convert_to_decimal_degrees(lng_raw, lng_ref)
            return {
                "filename": file.filename,
                "latitude": lat,
                "longitude": lng
            }

        return {"filename": file.filename, "latitude": None, "longitude": None, "message": "No GPS tags in EXIF"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image processing failed: {str(e)}")

@app.get("/api/v1/locate-ip")
async def locate_ip(ip: str):
    target_ip = ip.strip()

    # Resolve domain names to IP addresses if a hostname is provided
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

    return {"ip": target_ip, "error": "Unable to locate target IP or domain"}
