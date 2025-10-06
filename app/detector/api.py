from fastapi import APIRouter
from app.email_checker.core import analyze_email

router = APIRouter()

@router.get("/check")
def check_email(email_id: str):
    result = analyze_email(email_id)
    return {"email_id": email_id, "result": result}

