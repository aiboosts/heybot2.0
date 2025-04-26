# 🚀 Standard Imports
import os
import subprocess
from datetime import datetime, timedelta
import httpx
import secrets
import logging

# 🚀 Third Party Imports
import gradio as gr
import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from gradio.routes import mount_gradio_app
from authlib.jose import jwt
from starlette.middleware.sessions import SessionMiddleware

# 🚀 Local Imports
from context_manager import save_context, load_context

logging.basicConfig(level=logging.DEBUG)

# 🔥 Configuration
SECRET_KEY = "mein-super-geheimer-key"
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "your-client-id.apps.googleusercontent.com")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "your-client-secret")
REDIRECT_URI = "https://ethical-rattler-chief.ngrok-free.app/auth/google/callback"

# 🔥 OAuth2 Schema
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Dummy user database
fake_users_db = {
    "test@example.com": {
        "username": "test@example.com",
        "password": "test123"
    }
}

# 🔥 Authentication functions
def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or user["password"] != password:
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=30)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    token = jwt.encode({"alg": "HS256"}, to_encode, SECRET_KEY)
    return token

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY)
        username: str = payload.get("sub")
        if username is None or username not in fake_users_db:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return fake_users_db[username]
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalid or expired")

# 🚀 FastAPI App
api = FastAPI()

# Session Middleware (needed for state management)
api.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="oauth_session"
)

# 🧠 Login Page
@api.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    token = request.cookies.get("access_token") or request.query_params.get("token")
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY)
            username: str = payload.get("sub")
            if username and username in fake_users_db:
                return RedirectResponse(url=f"/ui?token={token}", status_code=302)
        except Exception:
            pass

    return """
    <html>
        <head>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 flex items-center justify-center h-screen">
            <div class="bg-white p-8 rounded shadow-md w-96">
                <h2 class="text-2xl font-bold mb-6 text-center">🔒 Login</h2>
                <form action="/login" method="post" class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Email:</label>
                        <input type="text" name="username" class="mt-1 p-2 w-full border rounded" required>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Password:</label>
                        <input type="password" name="password" class="mt-1 p-2 w-full border rounded" required>
                    </div>
                    <div>
                        <button type="submit" class="w-full bg-blue-500 text-white py-2 rounded hover:bg-blue-600">Login</button>
                    </div>
                </form>
                <div class="mt-6 text-center">
                    <a href="/auth/google" class="inline-block bg-red-500 text-white py-2 px-4 rounded hover:bg-red-600">🔵 Sign in with Google</a>
                </div>
            </div>
        </body>
    </html>
    """

# ✏️ Username/Password Login
@api.post("/login")
async def login_post(username: str = Form(...), password: str = Form(...)):
    user = authenticate_user(username, password)
    if not user:
        return HTMLResponse(content="Login failed", status_code=401)
    access_token = create_access_token(data={"sub": user["username"]})
    response = RedirectResponse(url=f"/ui?token={access_token}", status_code=302)
    response.set_cookie("access_token", access_token, httponly=True)
    return response

# 🔐 Google OAuth Implementation
@api.get("/auth/google")
async def auth_google(request: Request):
    # Generate state and store in session
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    
    authorization_url = (
        f"https://accounts.google.com/o/oauth2/auth?"
        f"response_type=code&"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"scope=openid%20email%20profile&"
        f"state={state}"
    )
    return RedirectResponse(authorization_url)

@api.get("/auth/google/callback")
async def auth_google_callback(request: Request, code: str = None, state: str = None, error: str = None):
    # Verify state
    if not state or state != request.session.get("oauth_state"):
        raise HTTPException(status_code=400, detail="Invalid state")
    
    if error:
        raise HTTPException(status_code=400, detail=f"Google auth error: {error}")
    
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code missing")
    
    # Exchange code for token
    async with httpx.AsyncClient() as client:
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code"
        }
        
        response = await client.post(token_url, data=data)
        token_data = response.json()
        
        if "error" in token_data:
            raise HTTPException(status_code=400, detail=token_data["error"])
        
        # Get user info
        userinfo = await client.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {token_data['access_token']}"}
        )
        user_data = userinfo.json()
        
        # Create or update user
        email = user_data["email"]
        if email not in fake_users_db:
            fake_users_db[email] = {
                "username": email,
                "password": ""  # No password for OAuth users
            }
        
        # Create JWT token
        access_token = create_access_token(data={"sub": email})
        response = RedirectResponse(url="/ui", status_code=302)
        response.set_cookie("access_token", access_token, httponly=True)
        return response

# ✏️ Token Endpoint
@api.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect login data")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# ✏️ Refresh Token
@api.post("/refresh")
async def refresh_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY)
        username = payload.get("sub")
        if username is None or username not in fake_users_db:
            raise HTTPException(status_code=401, detail="Invalid token")
        new_token = create_access_token(data={"sub": username})
        return {"access_token": new_token, "token_type": "bearer"}
    except Exception:
        raise HTTPException(status_code=401, detail="Token invalid or expired")

# ✏️ Protected API
@api.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    return {"message": f"Welcome {current_user['username']}!"}

# ✏️ Context API
@api.get("/mcp/context")
def read_context():
    return load_context()

@api.post("/mcp/context")
def write_context(style: str, mode: str, language: str):
    return save_context(style, mode, language)

# ✏️ Token Check for Gradio
@api.get("/check-token")
async def check_token(request: Request):
    token = request.query_params.get("token")
    if not token:
        return RedirectResponse(url="/login")
    try:
        payload = jwt.decode(token, SECRET_KEY)
        username: str = payload.get("sub")
        if username is None or username not in fake_users_db:
            return RedirectResponse(url="/login")
    except Exception:
        return RedirectResponse(url="/login")
    return RedirectResponse(url=f"/ui?token={token}")

# 🧹 Logout
@api.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response

# 🧠 Gradio UI
with gr.Blocks() as mcp_ui:
    token_state = gr.State(value="")

    with gr.Row():
        gr.Markdown("## 🧠 Model Context Protocol Server\nManage global AI context")

    def extract_token(request: gr.Request):
        return request.query_params.get("token")

    mcp_ui.load(fn=extract_token, inputs=[], outputs=[token_state])

    with gr.Row():
        style = gr.Dropdown(["neutral", "sarcastic", "friendly"], value="neutral", label="Tone")
        mode = gr.Dropdown(["default", "devsecops"], value="default", label="Mode")
        language = gr.Dropdown(["de", "en"], value="de", label="Language")

    output = gr.JSON(label="Current Context")

    with gr.Row():
        set_btn = gr.Button("📝 Save Context")
        get_btn = gr.Button("🔍 Show Context")
        run_btn = gr.Button("🚀 Run Script")
        logout_btn = gr.Button("🚪 Logout")

    set_btn.click(fn=save_context, inputs=[style, mode, language], outputs=output)
    get_btn.click(fn=load_context, outputs=output)

    def run_script():
        script_path = os.path.join(os.path.dirname(__file__), '..', 'bazinga_cve_bot.py')
        process = subprocess.Popen(["python", script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return stdout.decode('utf-8') if process.returncode == 0 else stderr.decode('utf-8')

    run_btn.click(fn=run_script, outputs=gr.Textbox(label="Progress"))

    def do_logout():
        return RedirectResponse(url="/logout")
    logout_btn.click(fn=do_logout)

# Mount Gradio App
mount_gradio_app(app=api, blocks=mcp_ui, path="/ui")

if __name__ == "__main__":
    uvicorn.run(api, host="0.0.0.0", port=7861)