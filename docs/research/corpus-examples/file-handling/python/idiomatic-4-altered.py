# idiomatic-4-altered.py
# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" -- derived from vulnerable-4-altered.py's own real
# structure. Same FastAPI route, hardened: the declared content_type is
# checked against an explicit allowlist AND the actual file bytes are
# sniffed with python-magic to confirm the real type matches, and the
# stored filename is generated server-side from a UUID plus the
# allowlisted extension -- never derived from the client-supplied
# original name.
import uuid

import magic
from fastapi import APIRouter, HTTPException, UploadFile

router = APIRouter()
UPLOAD_DIR = "/srv/app/public/uploads"

ALLOWED_TYPES = {
    "application/pdf": ".pdf",
    "image/png": ".png",
    "image/jpeg": ".jpg",
}


@router.post("/upload/profile-doc")
async def upload_profile_doc(file: UploadFile):
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(status_code=415, detail="unsupported content type")

    contents = await file.read()
    sniffed = magic.from_buffer(contents, mime=True)
    if sniffed != file.content_type:
        raise HTTPException(status_code=415, detail="file content does not match declared type")

    ext = ALLOWED_TYPES[file.content_type]
    safe_name = f"{uuid.uuid4().hex}{ext}"
    dest = f"{UPLOAD_DIR}/{safe_name}"
    with open(dest, "wb") as f:
        f.write(contents)
    return {"status": "uploaded", "path": dest}
