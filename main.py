import os
import shutil
import uuid
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional

from fastapi import (Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile, status)
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine, select

SECRET_KEY = "kalsfkbasf78gfsadubjbJBigfiuoqabfiasob98BUOBdOP*ASdfgbaqeiofg bsdjvdsh98sdfbvsbf89s8fbsdbHY66"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
STORAGE_PATH = "storage"
DATABASE_FILE = "appcenter.db"
DATABASE_URL = f"sqlite:///{DATABASE_FILE}"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserRole(str, Enum):
    COMMON = "COMMON"
    TESTER = "TESTER"
    ADMIN = "ADMIN"
    ROOT = "ROOT"

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str
    role: UserRole = Field(default=UserRole.COMMON)

class Application(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    platform: str
    description: Optional[str] = None
    versions: List["Version"] = Relationship(back_populates="application")

class Version(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    version_string: str
    status: str
    release_notes: Optional[str] = None
    file_path: str = Field(unique=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    app_id: int = Field(foreign_key="application.id")
    application: Application = Relationship(back_populates="versions")
    shared_links: List["SharedLink"] = Relationship(back_populates="version")

class SharedLink(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token: str = Field(unique=True, index=True)
    version_id: int = Field(foreign_key="version.id")
    expires_at: datetime
    is_active: bool = True
    version: Version = Relationship(back_populates="shared_links")

engine = create_engine(DATABASE_URL)

def create_db_and_tables():
    if not os.path.exists(STORAGE_PATH): 
        os.makedirs(STORAGE_PATH)
    SQLModel.metadata.create_all(engine)

def initialize_root_user():
    with Session(engine) as session:
        if not session.exec(select(User).where(User.username == "root")).first():
            session.add(User(username="root", hashed_password=pwd_context.hash("root"), role=UserRole.ROOT))
            session.commit()

# ✅ NUEVA FORMA: Lifespan Events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    create_db_and_tables()
    initialize_root_user()
    print("🚀 App Center iniciado correctamente")
    yield
    # Shutdown
    print("🛑 App Center apagándose...")

# App con lifespan
app = FastAPI(title="App Center con RBAC", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")
templates.env.add_extension('jinja2.ext.do')

def get_session():
    with Session(engine) as session: 
        yield session

def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({**data, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(request: Request, session: Session = Depends(get_session)):
    token = request.cookies.get("access_token")
    if not token: return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return session.exec(select(User).where(User.username == payload.get("sub"))).first()
    except JWTError: return None

def require_role(allowed_roles: List[UserRole]):
    async def role_checker(user: User = Depends(get_current_user)):
        if not user or user.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado.")
        return user
    return role_checker

@app.get("/", include_in_schema=False)
def root_redirect(user: User = Depends(get_current_user)):
    if not user: return RedirectResponse("/login")
    if user.role in [UserRole.ROOT, UserRole.ADMIN]: return RedirectResponse("/admin")
    return RedirectResponse("/dashboard")

@app.get("/login", include_in_schema=False)
def login_form(request: Request): 
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", include_in_schema=False)
async def login_post(request: Request, session: Session = Depends(get_session)):
    form = await request.form()
    user = session.exec(select(User).where(User.username == form.get("username"))).first()
    if not user or not pwd_context.verify(form.get("password"), user.hashed_password):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Credenciales incorrectas"}, status_code=401)
    token = create_access_token(data={"sub": user.username})
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="access_token", value=token, httponly=True)
    return response

@app.get("/logout", include_in_schema=False)
def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token")
    return response

@app.get("/dashboard", include_in_schema=False)
async def user_dashboard(request: Request, user: User = Depends(require_role([UserRole.TESTER, UserRole.COMMON])), session: Session = Depends(get_session)):
    apps = session.exec(select(Application).order_by(Application.name)).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "applications": apps})

@app.get("/admin", include_in_schema=False)
async def admin_panel(request: Request, user: User = Depends(require_role([UserRole.ADMIN, UserRole.ROOT])), session: Session = Depends(get_session)):
    apps = session.exec(select(Application).order_by(Application.name)).all()
    return templates.TemplateResponse("admin.html", {"request": request, "user": user, "applications": apps, "msg": request.query_params.get("msg"), "error": request.query_params.get("error")})

@app.post("/admin/upload", include_in_schema=False)
async def handle_upload(request: Request, user: User = Depends(require_role([UserRole.ROOT])), session: Session = Depends(get_session)):
    form = await request.form()
    app_name, platform, version_string, file = form.get("app_name"), form.get("platform"), form.get("version_string"), form.get("file")
    if not all([app_name, platform, version_string, file.filename]):
        return RedirectResponse(url="/admin?error=Faltan campos obligatorios", status_code=status.HTTP_303_SEE_OTHER)
    app_db = session.exec(select(Application).where(Application.name == app_name)).first()
    if not app_db:
        app_db = Application(name=app_name, platform=platform, description=form.get("description"))
        session.add(app_db); session.commit(); session.refresh(app_db)
    file_path = os.path.join(STORAGE_PATH, f"{uuid.uuid4()}_{file.filename}")
    with open(file_path, "wb") as buffer: shutil.copyfileobj(file.file, buffer)
    new_version = Version(version_string=version_string, status=form.get("status"), release_notes=form.get("release_notes"), file_path=file_path, app_id=app_db.id)
    session.add(new_version); session.commit()
    return RedirectResponse(url="/admin?msg=Versión subida con éxito", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/admin/versions/{version_id}/delete", include_in_schema=False)
async def delete_version(version_id: int, user: User = Depends(require_role([UserRole.ROOT])), session: Session = Depends(get_session)):
    version = session.get(Version, version_id)
    if version:
        if os.path.exists(version.file_path): os.remove(version.file_path)
        session.delete(version); session.commit()
    return RedirectResponse(url="/admin?msg=Versión eliminada", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/admin/versions/{version_id}/share", include_in_schema=False)
async def share_version_link(request: Request, version_id: int, user: User = Depends(require_role([UserRole.ADMIN, UserRole.ROOT])), session: Session = Depends(get_session)):
    link = SharedLink(token=secrets.token_urlsafe(16), version_id=version_id, expires_at=datetime.utcnow() + timedelta(hours=24))
    session.add(link); session.commit()
    share_url = f"{request.base_url}shared-download/{link.token}"
    return RedirectResponse(url=f"/admin?msg=Enlace para compartir: {share_url}", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/admin/users", include_in_schema=False)
async def user_management_page(request: Request, user: User = Depends(require_role([UserRole.ROOT])), session: Session = Depends(get_session)):
    users = session.exec(select(User).order_by(User.username)).all()
    return templates.TemplateResponse("user_management.html", {"request": request, "user": user, "users": users, "roles": list(UserRole), "msg": request.query_params.get("msg"), "error": request.query_params.get("error")})

@app.post("/admin/users/create", include_in_schema=False)
async def create_user(request: Request, user: User = Depends(require_role([UserRole.ROOT])), session: Session = Depends(get_session)):
    form = await request.form()
    username, password, role = form.get("username"), form.get("password"), form.get("role")
    if not all([username, password, role]):
        return RedirectResponse(url="/admin/users?error=Todos los campos son obligatorios", status_code=status.HTTP_303_SEE_OTHER)
    if session.exec(select(User).where(User.username == username)).first():
        return RedirectResponse(url=f"/admin/users?error=El usuario '{username}' ya existe", status_code=status.HTTP_303_SEE_OTHER)
    new_user = User(username=username, hashed_password=pwd_context.hash(password), role=UserRole(role))
    session.add(new_user); session.commit()
    return RedirectResponse(url="/admin/users?msg=Usuario creado con éxito", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/admin/users/{user_id}/delete", include_in_schema=False)
async def delete_user(user_id: int, user: User = Depends(require_role([UserRole.ROOT])), session: Session = Depends(get_session)):
    user_to_delete = session.get(User, user_id)
    if user_to_delete and user_to_delete.role != UserRole.ROOT:
        session.delete(user_to_delete); session.commit()
    return RedirectResponse(url="/admin/users?msg=Usuario eliminado", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/shared-download/{token}", include_in_schema=False)
async def shared_download_page(token: str, request: Request, session: Session = Depends(get_session)):
    link = session.exec(select(SharedLink).where(SharedLink.token == token, SharedLink.is_active == True, SharedLink.expires_at > datetime.utcnow())).first()
    return templates.TemplateResponse("shared_download.html", {"request": request, "version": link.version if link else None, "token": token})

@app.get("/download-by-token/{token}", include_in_schema=False)
async def process_shared_download(token: str, session: Session = Depends(get_session)):
    link = session.exec(select(SharedLink).where(SharedLink.token == token, SharedLink.is_active == True, SharedLink.expires_at > datetime.utcnow())).first()
    if not link: raise HTTPException(status.HTTP_404_NOT_FOUND, "Enlace no válido o expirado.")
    version = link.version
    link.is_active = False
    session.add(link); session.commit()
    return FileResponse(path=version.file_path, filename=os.path.basename(version.file_path))

@app.get("/download/{version_id}", include_in_schema=False)
def authenticated_download(version_id: int, user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    if not user: raise HTTPException(status.HTTP_403_FORBIDDEN)
    version = session.get(Version, version_id)
    if not version or not os.path.exists(version.file_path): raise HTTPException(status.HTTP_404_NOT_FOUND)
    can_download = ((user.role in [UserRole.ROOT, UserRole.ADMIN]) or (user.role == UserRole.TESTER and version.status in ['release', 'beta']))
    if not can_download: raise HTTPException(status.HTTP_403_FORBIDDEN, "No tienes permiso para descargar esta versión.")
    return FileResponse(path=version.file_path, filename=os.path.basename(version.file_path))
 
if __name__ == "__main__":
    import uvicorn
    # ✅ SOLUCIÓN AL PUERTO: Cambiar puerto o buscar uno libre
    try:
        uvicorn.run(app, host="127.0.0.1", port=8002)
    except Exception as e:
        print(f"❌ Error en puerto 8002: {e}")
        print("🔄 Intentando con puerto 8001...")
        try:
            uvicorn.run(app, host="127.0.0.1", port=8001)
        except Exception as e:
            print(f"❌ Error en puerto 8001: {e}")
            print("🔄 Intentando con puerto 3000...")
            uvicorn.run(app, host="127.0.0.1", port=3000)