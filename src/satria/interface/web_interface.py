"""
SATRIA AI Web Interface
Simple web interface for chat functionality
"""

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import os
from pathlib import Path

from satria.interface.chat_interface import chat_interface

# Setup templates
template_dir = Path(__file__).parent / "templates"
template_dir.mkdir(exist_ok=True)
templates = Jinja2Templates(directory=str(template_dir))

router = APIRouter(prefix="/interface", tags=["Web Interface"])

@router.get("/", response_class=HTMLResponse)
async def chat_home(request: Request):
    """Main chat interface"""
    return templates.TemplateResponse("chat.html", {
        "request": request,
        "title": "SATRIA AI Chat Interface"
    })

@router.post("/chat")
async def process_chat(user_input: str = Form(...)):
    """Process chat message"""
    try:
        response = await chat_interface.process_user_request(user_input)
        return {
            "success": True,
            "response": response.ai_response,
            "task_type": response.task_type.value,
            "team_role": response.team_role.value,
            "artifacts": response.artifacts,
            "timestamp": response.timestamp.isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "response": f"❌ Error processing request: {str(e)}"
        }

@router.get("/history")
async def get_chat_history():
    """Get chat history"""
    return {
        "success": True,
        "history": chat_interface.get_chat_history()
    }