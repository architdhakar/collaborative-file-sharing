from typing import List
from pydantic import BaseModel

class GroupBase(BaseModel):
    name: str

class GroupCreate(GroupBase):
    pass

class GroupOut(GroupBase):
    id: int
    members: List[str] = []   # we will return usernames

    class Config:
        orm_mode = True
