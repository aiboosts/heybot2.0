import os
import subprocess
import gradio as gr
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from gradio.routes import mount_gradio_app
from authlib.jose import jwt
import uvicorn
from context_manager import save_context, load_context
from datetime import datetime, timedelta

# 🔥 Geheime JWT-Key (solltest du später sicher speichern, z.B. ENV-Variable!)
SECRET_KEY = "mein-super-geheimer-key"

# 🔥 OAuth2-Schema
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Dummy-Datenbank für User
fake_users_db = {
    "test@example.com": {
        "username": "test@example.com",
        "password": "test123"  # Passwort wäre normalerweise gehasht!
    }
}

# 🔥 Funktionen für Auth
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
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Ungültiges Token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return fake_users_db[username]
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token ungültig oder abgelaufen",
            headers={"WWW-Authenticate": "Bearer"},
        )

# 🚀 FastAPI + REST-Endpunkte
api = FastAPI()

# ✏️ Token-Endpoint
@api.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Falsche Login-Daten")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# ✏️ Gesicherter Beispiel-Endpunkt
@api.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    return {"message": f"Willkommen {current_user['username']}!"}

# ✏️ MCP-Endpunkte (offen, oder später auth sichern)
@api.get("/mcp/context")
def read_context():
    return load_context()

@api.post("/mcp/context")
def write_context(style: str, mode: str, language: str):
    return save_context(style, mode, language)

# 🧠 Gradio-UI
with gr.Blocks() as mcp_ui:
    gr.Markdown("## 🧠 Model Context Protocol Server\nVerwalte globalen AI-Kontext für HeyBot & Co.")

    with gr.Row():
        style = gr.Dropdown(["neutral", "sarkastisch", "eingebildet", "freundlich"], value="neutral", label="Ton / Stil")
        mode = gr.Dropdown(["default", "devsecops", "alert-only", "humor", "juristisch"], value="default", label="Modus")
        language = gr.Dropdown(["de", "en"], value="de", label="Sprache")

    output = gr.JSON(label="Aktueller Kontext")

    with gr.Row():
        set_btn = gr.Button("📝 Kontext speichern")
        get_btn = gr.Button("🔍 Kontext anzeigen")
        run_btn = gr.Button("🚀 Bazinga Skript ausführen")

    set_btn.click(fn=save_context, inputs=[style, mode, language], outputs=output)
    get_btn.click(fn=load_context, outputs=output)

    def run_script():
        """Führt das bazinga.py Skript manuell aus und gibt die Ausgabe zurück."""
        script_path = os.path.join(os.path.dirname(__file__), '..', 'bazinga_cve_bot.py')
        process = subprocess.Popen(["python", script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            return stdout.decode('utf-8')
        else:
            return stderr.decode('utf-8')

    run_btn.click(fn=run_script, outputs=gr.Textbox(label="Progress"))

# 🎯 Gradio mounten
mount_gradio_app(app=api, blocks=mcp_ui, path="/ui")

# 🚀 Main
if __name__ == "__main__":
    uvicorn.run(api, host="0.0.0.0", port=7861)
