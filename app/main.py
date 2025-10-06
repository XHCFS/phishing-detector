from fastapi import FastAPI
from app.dashboard.routes import router as dashboard_router
from app.email_checker.api import router as email_router

app = FastAPI(title="Email Screening Tool")

# Register modules
app.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
app.include_router(email_router, prefix="/email", tags=["Email Checker"])

@app.get("/")
def home():
    return {"status": "running", "message": "Welcome to the Email Screening Tool!"}

