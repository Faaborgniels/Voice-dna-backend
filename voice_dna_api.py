
from dataclasses import asdict, is_dataclass

from typing import Any, Dict

from fastapi import FastAPI, HTTPException

from pydantic import BaseModel, Field

from voice_dna_engine import (

    VoiceDNASchemaValidator,

    AdversarialTextSanitizer,

    StylometricAnalyzer,

    DraftComplianceLinter,

    PromptContractCompiler,

    ForensicIdiolectAnalyzer,

    ProvenanceHashChain,

)

app = FastAPI(

    title="Voice DNA Engine v3 API",

    version="3.0.0",

    description="API wrapper for the Voice DNA Engine v3",

)

def serialise(value: Any) -> Any:

    if is_dataclass(value):

        return asdict(value)

    if isinstance(value, dict):

        return {k: serialise(v) for k, v in value.items()}

    if isinstance(value, (list, tuple)):

        return [serialise(v) for v in value]

    return value

class DNARequest(BaseModel):

    dna: Dict[str, Any]

class TextRequest(BaseModel):

    text: str = Field(min_length=1)

class AnalyseRequest(TextRequest):

    word_count_method: str = "UNICODE_WORD_BOUNDARIES"

class SanitizeRequest(TextRequest):

    firewall_mode: str = "QUARANTINE_AND_HALT"

class DraftDNARequest(BaseModel):

    draft: str = Field(min_length=1)

    dna: Dict[str, Any]

    channel: str = "LINKEDIN_POST"

class CompileRequest(BaseModel):

    dna: Dict[str, Any]

    channel: str = "LINKEDIN_POST"

@app.get("/")

def root():

    return {

        "service": "Voice DNA Engine v3",

        "status": "online",

        "version": "3.0.0",

    }

@app.get("/health")

def health():

    return {"status": "ok"}

@app.post("/validate")

def validate(req: DNARequest):

    try:

        ok, issues = VoiceDNASchemaValidator().validate(req.dna)

        return {"valid": ok, "issues": serialise(issues)}

    except Exception as exc:

        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/sanitize")

def sanitize(req: SanitizeRequest):

    try:

        result = AdversarialTextSanitizer.sanitize(

            req.text, req.firewall_mode

        )

        return serialise(result)

    except Exception as exc:

        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/analyse")

def analyse(req: AnalyseRequest):

    try:

        result = StylometricAnalyzer.analyze(

            req.text, req.word_count_method

        )

        return serialise(result)

    except Exception as exc:

        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/lint")

def lint(req: DraftDNARequest):

    try:

        result = DraftComplianceLinter.lint(

            req.draft, req.channel, req.dna

        )

        return serialise(result)

    except Exception as exc:

        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/compile-prompt")

def compile_prompt(req: CompileRequest):

    try:

        prompt = PromptContractCompiler.compile(

            req.dna, req.channel

        )

        return {"prompt": prompt}

    except Exception as exc:

        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/attribute")

def attribute(req: DraftDNARequest):

    try:

        result = ForensicIdiolectAnalyzer.attribute(

            req.draft, req.dna

        )

        return serialise(result)

    except Exception as exc:

        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/verify-chain")

def verify_chain(req: DNARequest):

    try:

        ok, issues = ProvenanceHashChain.verify(req.dna)

        return {

            "verified": ok,

            "issues": serialise(issues),

            "chain_root": ProvenanceHashChain.chain_root(req.dna),

        }

    except Exception as exc:

        raise HTTPException(status_code=400, detail=str(exc))

