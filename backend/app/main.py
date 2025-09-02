from fastapi import FastAPI, Depends, HTTPException, status, File,UploadFile
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
import os

from schemas import user,groups,files
from api import auth
from db.session import engine, get_db
from db import models

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Signup
@app.post("/signup", response_model=user.UserOut)
def signup(user: user.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = auth.hash_password(user.password)
    new_user = models.User(username=user.username, email=user.email, password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# Login
@app.post("/login", response_model=user.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = auth.create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

# Get current user
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    from jose import jwt, JWTError
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(models.User).filter(models.User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.get("/me", response_model=user.UserOut)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user



# ✅ Create group
@app.post("/groups", response_model=groups.GroupOut)
def create_group(group: groups.GroupCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    existing = db.query(models.Group).filter(models.Group.name == group.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Group already exists")
    
    new_group = models.Group(name=group.name)
    new_group.members.append(current_user)  # creator auto-joins
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    return {
        "id": new_group.id,
        "name": new_group.name,
        "members": [m.username for m in new_group.members]
    }

# ✅ Join group
@app.post("/groups/{group_id}/join")
def join_group(group_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    if current_user in group.members:
        raise HTTPException(status_code=400, detail="Already a member")

    group.members.append(current_user)
    db.commit()
    return {"message": f"User {current_user.username} joined group {group.name}"}

# ✅ View group (only members can see)
@app.get("/groups/{group_id}", response_model=groups.GroupOut)
def view_group(group_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    if current_user not in group.members:
        raise HTTPException(status_code=403, detail="Not a member of this group")

    return {
        "id": group.id,
        "name": group.name,
        "members": [m.username for m in group.members]
    }



UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/groups/{group_id}/files", response_model=files.FileOut)
def upload_file(
    group_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    if current_user not in group.members:
        raise HTTPException(status_code=403, detail="Not a member of this group")

    # save file locally
    file_location = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_location, "wb") as f:
        f.write(file.file.read())

    # store metadata in DB
    new_file = models.File(
        filename=file.filename,
        filepath=file_location,
        uploader_id=current_user.id,
        group_id=group.id,
    )
    db.add(new_file)
    db.commit()
    db.refresh(new_file)

    return new_file

@app.get("/groups/{group_id}/files", response_model=list[files.FileOut])
def list_files(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    if current_user not in group.members:
        raise HTTPException(status_code=403, detail="Not a member of this group")

    return group.files

from fastapi.responses import FileResponse

@app.get("/files/{file_id}")
def download_file(
    file_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    file = db.query(models.File).filter(models.File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    # permission check
    group = db.query(models.Group).filter(models.Group.id == file.group_id).first()
    if current_user not in group.members:
        raise HTTPException(status_code=403, detail="Not allowed")

    return FileResponse(file.filepath, filename=file.filename)

@app.delete("/files/{file_id}")
def delete_file(
    file_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    file = db.query(models.File).filter(models.File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    if file.uploader_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own files")

    # delete file from disk
    if os.path.exists(file.filepath):
        os.remove(file.filepath)

    db.delete(file)
    db.commit()
    return {"message": "File deleted successfully"}
