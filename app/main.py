from fastapi import FastAPI
from app.dashboard.routes import router as dashboard_router
from app.detector.api import router as detector_router

app = FastAPI(title="Phishing Detector")

# Register modules
app.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
app.include_router(detector_router, prefix="/detector", tags=["Detector"])

@app.get("/")
def home():
    return {
        "status": "running",
        "message": "Welcome to the Phishing Detector!"
    }

