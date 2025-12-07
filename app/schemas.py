from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Any
from datetime import datetime


# --------------------- Evidence ---------------------

class EvidenceOut(BaseModel):
    id: int
    source: str
    title: Optional[str]
    url: Optional[HttpUrl]
    summary: Optional[str]
    captured_at: datetime

    class Config:
        orm_mode = True


# --------------------- Reason ---------------------

class Reason(BaseModel):
    rule_id: str
    points: int
    message: str
    evidence_ids: Optional[List[int]] = []


# --------------------- Risk Score ---------------------

class RiskScoreOut(BaseModel):
    id: int
    score: int
    label: str
    reasons: List[Reason]
    computed_at: datetime

    class Config:
        orm_mode = True


# --------------------- Artifact ---------------------

class ArtifactOut(BaseModel):
    id: int
    type: str
    value: str
    metadata: Optional[Any]
    created_at: datetime
    evidences: List[EvidenceOut] = []
    scores: List[RiskScoreOut] = []

    class Config:
        orm_mode = True


# --------------------- Verify Request ---------------------

class VerifyRequest(BaseModel):
    query: str
    type: Optional[str] = "auto"
    context_text: Optional[str] = None


# --------------------- Verify Response ---------------------

class VerifyResponse(BaseModel):
    label: str
    score: int
    reasons: List[Reason]
    evidences: List[EvidenceOut]
    artifact: ArtifactOut
