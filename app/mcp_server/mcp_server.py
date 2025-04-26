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
from fastapi import FastAPI, Depends, HTTPException, status, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from gradio.routes import mount_gradio_app
from authlib.integrations.starlette_client import OAuth
from authlib.jose import jwt
from starlette.middleware.sessions import SessionMiddleware

# 🚀 Local Imports
from context_manager import save_context, load_context

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 🔥 Configuration
SECRET_KEY = secrets.token_urlsafe(32)  # Better secret key generation
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "your-client-id.apps.googleusercontent.com")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "your-client-secret")
REDIRECT_URI = "http://ethical-rattler-chief.ngrok-free.app/auth/google/callback"  # Updated for local testing
COOKIE_SECURE = False # Set to True in production with HTTPS
SAME_SITE = "lax"  

# 🔥 OAuth2 Schema
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Initialize OAuth
oauth = OAuth()
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'redirect_uri': REDIRECT_URI
    },
)

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
    try:
        # Prepare claims
        to_encode = data.copy()
        expire = datetime.utcnow() + expires_delta
        to_encode.update({"exp": expire})
        
        # Create token
        token = jwt.encode(
            {'alg': 'HS256'},
            to_encode,
            SECRET_KEY
        )
        
        # Ensure we return a string
        if isinstance(token, bytes):
            token = token.decode('utf-8')
            
        return token
    except Exception as e:
        logger.error(f"Token creation failed: {str(e)}")
        raise ValueError("Failed to create token")

def decode_token(token: str):
    try:
        if not token or len(token.split('.')) != 3:
            raise ValueError("Invalid token format")
            
        claims = jwt.decode(token, SECRET_KEY)
        
        if not isinstance(claims, dict):
            raise ValueError("Invalid token claims")
            
        if "sub" not in claims:
            raise ValueError("Missing subject in token")
            
        # Check expiration
        if "exp" in claims:
            if datetime.utcnow() > datetime.fromtimestamp(claims["exp"]):
                raise ValueError("Token expired")
                
        return claims
    except Exception as e:
        logger.error(f"Token validation failed: {str(e)}")
        raise ValueError(f"Invalid token: {str(e)}")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        claims = decode_token(token)
        username: str = claims.get("sub")
        if username is None or username not in fake_users_db:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"}
            )
        return fake_users_db[username]
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"}
        )

# 🚀 FastAPI App
api = FastAPI()

# Middleware
api.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
api.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# 🧠 Login Page
@api.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    token = request.cookies.get("access_token") or request.query_params.get("token")
    if token:
        try:
            payload = decode_token(token)
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

@api.post("/login", response_class=RedirectResponse)
async def login_post(username: str = Form(...), password: str = Form(...)):
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    try:
        access_token = create_access_token(data={"sub": user["username"]})
        
        response = RedirectResponse(
            url=f"/ui?token={access_token}", 
            status_code=status.HTTP_303_SEE_OTHER
        )
        
        response.set_cookie(
            "access_token",
            access_token,
            httponly=True,
            secure=True,  # Must be True
            samesite="lax",
            domain=".ngrok-free.app"  # Important for ngrok
        )
        
        return response
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication error")

@api.get("/auth/google")
async def auth_google(request: Request):
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    return await oauth.google.authorize_redirect(
        request, 
        REDIRECT_URI,
        state=state
    )

@api.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        
        if not user_info or 'email' not in user_info:
            raise HTTPException(status_code=400, detail="Failed to fetch user info")
        
        email = user_info['email']
        if email not in fake_users_db:
            fake_users_db[email] = {"username": email, "password": ""}
        
        access_token = create_access_token(data={"sub": email})
        response = RedirectResponse(url="/ui", status_code=302)
        response.set_cookie(
            "access_token",
            access_token,
            httponly=True,
            secure=True,  # Must be True
            samesite="lax",
            domain=".ngrok-free.app"
        )
        return response
    except Exception as e:
        logger.error(f"Google OAuth failed: {str(e)}")
        raise HTTPException(status_code=500, detail="OAuth processing error")

# ✏️ Token Endpoint
@api.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect login data")
    return {
        "access_token": create_access_token(data={"sub": user["username"]}),
        "token_type": "bearer"
    }

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

# 🧹 Logout
@api.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    request.session.clear()
    return response

# 🧠 Gradio UI
with gr.Blocks() as mcp_ui:
    token_state = gr.State(value="")

    def get_token(request: gr.Request):
        try:
            token = (
                request.query_params.get("token") or
                request.cookies.get("access_token") or
                (request.headers.get("authorization") or "").replace("Bearer ", "")
            )
            
            if not token:
                raise ValueError("No token provided")
                
            claims = decode_token(token)
            if not claims.get("sub"):
                raise ValueError("Invalid token content")
                
            return token
            
        except ValueError as e:
            if hasattr(request, "cookies"):
                request.cookies.pop("access_token", None)
            raise gr.Error(f"Authentication failed: {str(e)}")
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            raise gr.Error("Authentication system error")

    mcp_ui.load(fn=get_token, inputs=[], outputs=[token_state], show_progress=False)

    with gr.Row():
        gr.Markdown("## 🧠 Model Context Protocol Server")

    with gr.Row():
        style = gr.Dropdown(["neutral", "sarkastisch", "eingebildet", "freundlich"], value="neutral", label="Ton / Stil")
        mode = gr.Dropdown(["default", "devsecops", "alert-only", "humor", "juristisch"], value="default", label="Modus")
        language = gr.Dropdown(["de", "en"], value="de", label="Sprache")

    with gr.Row():
        auth_status = gr.HTML("""<div id="auth-status" class="p-4 border rounded-lg"></div>""")

    output = gr.JSON(label="Current Context")

    with gr.Row():
        set_btn = gr.Button("📝 Save Context")
        get_btn = gr.Button("🔍 Show Context")
        run_btn = gr.Button("🚀 Run Script")
        logout_btn = gr.Button("🚪 Logout")

    def update_auth_status(token):
        if not token:
            return """<div class="p-4 border rounded-lg bg-red-50">
                <a href="/login" class="text-red-500 hover:text-red-700">❌ Please login</a>
                </div>"""
        try:
            payload = decode_token(token)
            return f"""<div class="p-4 border rounded-lg bg-green-50">
                <span class="text-green-600">✅ Authenticated as: {payload['sub']}</span>
                </div>"""
        except ValueError as e:
            return f"""<div class="p-4 border rounded-lg bg-red-50">
                <a href="/login" class="text-red-500 hover:text-red-700">❌ {str(e)} (Click to login)</a>
                </div>"""

    mcp_ui.load(fn=update_auth_status, inputs=[token_state], outputs=[auth_status])
            # Update the UI when token changes
    token_state.change(
        fn=update_auth_status,
        inputs=[token_state],
        outputs=[auth_status]
    )

    set_btn.click(fn=save_context, inputs=[style, mode, language], outputs=output)
    get_btn.click(fn=load_context, outputs=output)

    script_output = gr.Textbox(label="Script Output", lines=10, interactive=False)
    
    def run_script():
        try:
            # Get the absolute path to the script
            script_path = os.path.abspath("bazinga_cve_bot.py")
            
            # Check if the script exists
            if not os.path.exists(script_path):
                return f"Error: Script not found at {script_path}"
            
            # Run the script with proper error handling
            result = subprocess.run(
                ["python", script_path],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Return combined output
            output = f"=== STDOUT ===\n{result.stdout}\n"
            if result.stderr:
                output += f"\n=== STDERR ===\n{result.stderr}\n"
            return output
            
        except subprocess.CalledProcessError as e:
            return f"Script failed with error:\nExit code: {e.returncode}\n\n{e.stderr}"
        except Exception as e:
            return f"Unexpected error: {str(e)}"
        
    run_btn.click(
        fn=run_script,
        outputs=script_output
    )
    
    def logout_handler():
        # Instead of returning a RedirectResponse, we'll use JavaScript to redirect
        return """
        <script>
            window.location.href = '/logout';
        </script>
        """

    logout_btn.click(
        fn=None,  # No Python function needed
        inputs=None,
        outputs=None,
        js="""
        function() {
            fetch('/logout', {method: 'GET', credentials: 'include'})
                .then(() => window.location.href = '/login');
            return [];
        }
        """
    )

    gr.HTML("""
    <script>
        document.addEventListener("DOMContentLoaded", function() {
            setInterval(() => {
                fetch('/protected', {credentials: 'include'})
                    .catch(() => window.location.href = '/login')
            }, 300000);
        });
    </script>
    """)

# Mount Gradio App
mount_gradio_app(app=api, blocks=mcp_ui, path="/ui")

if __name__ == "__main__":
    uvicorn.run(api, host="0.0.0.0", port=7861)