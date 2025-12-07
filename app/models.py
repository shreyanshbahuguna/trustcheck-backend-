from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.session import Base

class Artifact(Base):
    __tablename__ = "artifacts"
    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, index=True)  # company/domain/email/phone
    value = Column(String, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # FIX: "metadata" is a reserved SQLAlchemy keyword → renamed
    artifact_metadata = Column(JSON, default={})

    evidences = relationship("Evidence", back_populates="artifact", cascade="all, delete-orphan")
    scores = relationship("RiskScore", back_populates="artifact", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidences"
    id = Column(Integer, primary_key=True, index=True)
    artifact_id = Column(Integer, ForeignKey("artifacts.id", ondelete="CASCADE"))
    source = Column(String)
    title = Column(String)
    url = Column(String)
    summary = Column(Text)
    captured_at = Column(DateTime(timezone=True), server_default=func.now())

    artifact = relationship("Artifact", back_populates="evidences")


class RiskScore(Base):
    __tablename__ = "risk_scores"
    id = Column(Integer, primary_key=True, index=True)
    artifact_id = Column(Integer, ForeignKey("artifacts.id", ondelete="CASCADE"))
    score = Column(Integer, index=True)
    label = Column(String)
    reasons = Column(JSON, default=list)
    computed_at = Column(DateTime(timezone=True), server_default=func.now())

    artifact = relationship("Artifact", back_populates="scores")


class UserReport(Base):
    __tablename__ = "user_reports"
    id = Column(Integer, primary_key=True, index=True)
    artifact_type = Column(String)
    artifact_value = Column(String)
    description = Column(Text)
    contact = Column(String, nullable=True)
    status = Column(String, default="pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
