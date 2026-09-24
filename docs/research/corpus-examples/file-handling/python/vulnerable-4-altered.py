# vulnerable-4-altered.py
# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics". A distinct upload idiom from this file's Flask/werkzeug
# pair (vulnerable-1.py/idiomatic-1.py): a FastAPI route. Unrestricted
# upload: the client-declared content_type is never checked, and the
# file is written to disk using the client-supplied original filename
# verbatim.
from fastapi import APIRouter, UploadFile

router = APIRouter()
UPLOAD_DIR = "/srv/app/public/uploads"


@router.post("/upload/profile-doc")
async def upload_profile_doc(file: UploadFile):
    contents = await file.read()
    dest = f"{UPLOAD_DIR}/{file.filename}"
    with open(dest, "wb") as f:
        f.write(contents)
    return {"status": "uploaded", "path": dest}
