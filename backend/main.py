from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dns_lookup import lookup_dns
from propagation import check_propagation
from validation import validate_email_security
from reverse import reverse_lookup

app = FastAPI(title="DNS Diagnostic Tool API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class DomainRequest(BaseModel):
    domain: str

class PropagationRequest(BaseModel):
    domain: str
    record_type: str = "A"

class EmailSecurityRequest(BaseModel):
    domain: str

class ReverseRequest(BaseModel):
    ip: str

@app.get("/")
def root():
    return {"status": "DNS Tool API running"}

@app.post("/api/lookup")
def dns_lookup(req: DomainRequest):
    try:
        return lookup_dns(req.domain)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/propagation")
def dns_propagation(req: PropagationRequest):
    try:
        return check_propagation(req.domain, req.record_type)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/email-security")
def email_security(req: EmailSecurityRequest):
    try:
        return validate_email_security(req.domain)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/reverse")
def ptr_lookup(req: ReverseRequest):
    try:
        return reverse_lookup(req.ip)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
