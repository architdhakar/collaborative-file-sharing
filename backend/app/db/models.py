from sqlalchemy import Column, Integer, String,Table,ForeignKey
from sqlalchemy.orm import relationship
from db.session import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)

# Model for Group creation
# Association table for many-to-many
user_groups = Table(
    "user_groups",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("group_id", Integer, ForeignKey("groups.id"), primary_key=True),
)

class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True)

    members = relationship("User", secondary=user_groups, back_populates="groups")


User.groups = relationship("Group", secondary=user_groups, back_populates="members")

# Model for files
class File(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    filepath = Column(String(500), nullable=False)  # where file is stored
    uploader_id = Column(Integer, ForeignKey("users.id"))
    group_id = Column(Integer, ForeignKey("groups.id"))

    uploader = relationship("User", back_populates="files")
    group = relationship("Group", back_populates="files")

# add reverse relations
User.files = relationship("File", back_populates="uploader")
Group.files = relationship("File", back_populates="group")
