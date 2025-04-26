import os
import subprocess
import gradio as gr
from fastapi import FastAPI, Depends, HTTPException, status, Form, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse
from gradio.routes import mount_gradio_app
from authlib.jose import jwt
import uvicorn
from context_manager import save_context, load_context
from datetime import datetime, timedelta

# 🔥 Geheimer Schlüssel (in Produktion besser als ENV-Variable)
SECRET_KEY = "mein-super-geheimer-key"

# 🔥 OAuth2-Schema
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Dummy-User-Datenbank
fake_users_db = {
    "test@example.com": {
        "username": "test@example.com",
        "password": "test123"
    }
}

# 🔥 Funktionen für Authentifizierung
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
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ungültiges Token")
        return fake_users_db[username]
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token ungültig oder abgelaufen")

# 🚀 FastAPI App
api = FastAPI()

# ✨ Schöneres Login-Formular (TailwindCSS)
@api.get("/login", response_class=HTMLResponse)
async def login_form():
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
                        <label class="block text-sm font-medium text-gray-700">Passwort:</label>
                        <input type="password" name="password" class="mt-1 p-2 w-full border rounded" required>
                    </div>
                    <div>
                        <button type="submit" class="w-full bg-blue-500 text-white py-2 rounded hover:bg-blue-600">Login</button>
                    </div>
                </form>
            </div>
        </body>
    </html>
    """

@api.post("/login")
async def login_post(username: str = Form(...), password: str = Form(...)):
    user = authenticate_user(username, password)
    if not user:
        return HTMLResponse(content="Login fehlgeschlagen.", status_code=401)
    access_token = create_access_token(data={"sub": user["username"]})
    response = RedirectResponse(url=f"/ui?token={access_token}", status_code=302)
    return response

# ✏️ Token-Endpoint (für API-Clients)
@api.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Falsche Login-Daten")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# 🛡️ Bonus: Refresh-Token (simple Variante)
@api.post("/refresh")
async def refresh_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY)
        username = payload.get("sub")
        if username is None or username not in fake_users_db:
            raise HTTPException(status_code=401, detail="Ungültiges Token")
        # Neues Token erstellen
        new_token = create_access_token(data={"sub": username})
        return {"access_token": new_token, "token_type": "bearer"}
    except Exception:
        raise HTTPException(status_code=401, detail="Token ungültig oder abgelaufen")

# ✏️ Geschützte API
@api.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    return {"message": f"Willkommen {current_user['username']}!"}

# ✏️ Context-API
@api.get("/mcp/context")
def read_context():
    return load_context()

@api.post("/mcp/context")
def write_context(style: str, mode: str, language: str):
    return save_context(style, mode, language)

# ✏️ Check-Token für Gradio-UI Absicherung
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

# 🧹 Bonus: Logout
@api.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response

# 🧠 Gradio-UI
with gr.Blocks() as mcp_ui:
    token_state = gr.State(value="")

    with gr.Row():
        gr.Markdown("## 🧠 Model Context Protocol Server\nVerwalte globalen AI-Kontext für HeyBot & Co.")

    # Token aus der URL beim Laden extrahieren
    def extract_token(request: gr.Request):
        token = request.query_params.get("token")
        return token

    mcp_ui.load(fn=extract_token, inputs=[], outputs=[token_state])

    with gr.Row():
        style = gr.Dropdown(["neutral", "sarkastisch", "eingebildet", "freundlich"], value="neutral", label="Ton / Stil")
        mode = gr.Dropdown(["default", "devsecops", "alert-only", "humor", "juristisch"], value="default", label="Modus")
        language = gr.Dropdown(["de", "en"], value="de", label="Sprache")

    output = gr.JSON(label="Aktueller Kontext")

    with gr.Row():
        set_btn = gr.Button("📝 Kontext speichern")
        get_btn = gr.Button("🔍 Kontext anzeigen")
        run_btn = gr.Button("🚀 Bazinga Skript ausführen")
        logout_btn = gr.Button("🚪 Logout")

    set_btn.click(fn=save_context, inputs=[style, mode, language], outputs=output)
    get_btn.click(fn=load_context, outputs=output)

    def run_script():
        script_path = os.path.join(os.path.dirname(__file__), '..', 'bazinga_cve_bot.py')
        process = subprocess.Popen(["python", script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            return stdout.decode('utf-8')
        else:
            return stderr.decode('utf-8')

    run_btn.click(fn=run_script, outputs=gr.Textbox(label="Progress"))

    # 🧹 Logout-Button
    def do_logout():
        return RedirectResponse(url="/logout")
    logout_btn.click(fn=do_logout)

# 🎯 Gradio App mounten
mount_gradio_app(app=api, blocks=mcp_ui, path="/ui")

# 🚀 Main
if __name__ == "__main__":
    uvicorn.run(api, host="0.0.0.0", port=7861)
