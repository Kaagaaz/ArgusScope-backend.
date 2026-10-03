from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image, ExifTags
import httpx
import io

app = FastAPI(title="ArgusScope API")

# Enable CORS so your GitHub Pages site can talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from any origin (e.g. your GitHub Pages site)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def convert_to_decimal_degrees(value, ref):
    """Converts EXIF degrees/minutes/seconds tuples to decimal degrees."""
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
    """Extracts GPS coordinates and metadata from an uploaded image."""
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
    """Fetches geolocation details for a given IP address."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"http://ip-api.com/json/{ip}")
            data = response.json()

            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "city": data.get("city"),
                    "country": data.get("country"),
                    "org": data.get("org")
                }
            return {"ip": ip, "error": "Unable to locate IP"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"IP lookup failed: {str(e)}")
