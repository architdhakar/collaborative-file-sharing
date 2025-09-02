from pydantic import BaseModel
from typing import Optional

class FileOut(BaseModel):
    id: int
    filename: str
    uploader_id: int
    group_id: int

    class Config:
        orm_mode = True
