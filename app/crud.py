from sqlalchemy.orm import Session
from app import models
from typing import Dict, Any, List

def get_artifact_by_value(db: Session, value: str):
    return db.query(models.Artifact).filter(models.Artifact.value == value).first()

def create_artifact(db: Session, type_: str, value: str, metadata: Dict[str, Any] = None):
    obj = models.Artifact(type=type_, value=value, metadata=metadata or {})
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj

def add_evidence(db: Session, artifact: models.Artifact, source: str, title: str = None, url: str = None, summary: str = None):
    ev = models.Evidence(artifact_id=artifact.id, source=source, title=title, url=url, summary=summary)
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev

def add_riskscore(db: Session, artifact: models.Artifact, score: int, label: str, reasons: List[Dict]):
    rs = models.RiskScore(artifact_id=artifact.id, score=score, label=label, reasons=reasons)
    db.add(rs)
    db.commit()
    db.refresh(rs)
    return rs

def create_user_report(db: Session, artifact_type: str, artifact_value: str, description: str, contact: str = None):
    r = models.UserReport(artifact_type=artifact_type, artifact_value=artifact_value, description=description, contact=contact)
    db.add(r)
    db.commit()
    db.refresh(r)
    return r
