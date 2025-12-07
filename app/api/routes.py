from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas import VerifyRequest
from app import crud
from app.services.orchestrator import run_verification   # ✅ FIX: required import

router = APIRouter()


# -------------------------------------------------------------------------
# VERIFY ENDPOINT
# -------------------------------------------------------------------------

@router.post("/api/verify")
def verify(payload: VerifyRequest, db: Session = Depends(get_db)):

    # Run the verification engine
    try:
        result = run_verification(payload.query, payload.type or "auto")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")

    # Create OR get existing artifact
    art = crud.get_artifact_by_value(db, result["artifact_value"])
    if not art:
        art = crud.create_artifact(
            db,
            result["artifact_type"],
            result["artifact_value"],
            metadata=result.get("metadata")
        )

    # Persist evidences
    evidence_records = []
    for ev in result.get("evidences", []):
        try:
            saved = crud.add_evidence(
                db,
                art,
                source=ev.get("source"),
                title=ev.get("title"),
                url=None,
                summary=str(ev.get("data"))
            )
            evidence_records.append(saved)
        except Exception:
            pass  # skip failed evidence inserts

    # Persist risk score
    scoring = result["scoring"]
    crud.add_riskscore(
        db,
        art,
        score=scoring["score"],
        label=scoring["label"],
        reasons=scoring["reasons"]
    )

    # Reload with relations
    db_art = crud.get_artifact_by_value(db, art.value)

    # ---------------- CLEAN OUTPUT ----------------

    # Reasons
    reasons_out = [
        {
            "rule_id": r["rule_id"],
            "points": r["points"],
            "message": r["message"],
            "evidence_ids": []
        }
        for r in scoring["reasons"]
    ]

    # Evidences
    evidences_out = [
        {
            "id": e.id,
            "source": e.source,
            "title": e.title,
            "url": e.url,
            "summary": e.summary,
            "captured_at": e.captured_at.isoformat()
        }
        for e in evidence_records
    ]

    # Scores
    scores_out = [
        {
            "id": s.id,
            "score": s.score,
            "label": s.label,
            "reasons": reasons_out,
            "computed_at": s.computed_at.isoformat()
        }
        for s in db_art.scores
    ]

    return {
        "label": scoring["label"],
        "score": scoring["score"],
        "reasons": reasons_out,
        "evidences": evidences_out,
        "artifact": {
            "id": db_art.id,
            "type": db_art.type,
            "value": db_art.value,
            "metadata": {},
            "created_at": db_art.created_at.isoformat(),
            "evidences": evidences_out,
            "scores": scores_out
        }
    }


# -------------------------------------------------------------------------
# GET ARTIFACT DETAILS
# -------------------------------------------------------------------------

@router.get("/api/artifacts/{artifact_id}")
def get_artifact(artifact_id: int, db: Session = Depends(get_db)):

    from app.models import Artifact

    art = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not art:
        raise HTTPException(status_code=404, detail="Artifact not found")

    evidences_out = [
        {
            "id": e.id,
            "source": e.source,
            "title": e.title,
            "url": e.url,
            "summary": e.summary,
            "captured_at": e.captured_at.isoformat()
        }
        for e in art.evidences
    ]

    scores_out = [
        {
            "id": s.id,
            "score": s.score,
            "label": s.label,
            "reasons": [],
            "computed_at": s.computed_at.isoformat()
        }
        for s in art.scores
    ]

    return {
        "id": art.id,
        "type": art.type,
        "value": art.value,
        "metadata": {},
        "created_at": art.created_at.isoformat(),
        "evidences": evidences_out,
        "scores": scores_out
    }


# -------------------------------------------------------------------------
# REPORT SCAM ENDPOINT (NO CHANGE IN ORIGINALITY)
# -------------------------------------------------------------------------

@router.post("/api/report")
def report(payload: dict, db: Session = Depends(get_db)):

    artifact_type = payload.get("artifact_type")
    artifact_value = payload.get("artifact_value")
    description = payload.get("description")
    contact = payload.get("contact", "")  # ✅ FIX: safe default

    if not artifact_type or not artifact_value or not description:
        raise HTTPException(
            status_code=400,
            detail="artifact_type, artifact_value and description required"
        )

    rep = crud.create_user_report(
        db,
        artifact_type,
        artifact_value,
        description,
        contact
    )

    return {"id": rep.id, "status": rep.status}
