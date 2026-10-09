"""
models.py
---------
Pydantic modelleri. Caido köprüsünden gelen ham veriyi doğrulamak
ve API çıktısını tutarlı hale getirmek için kullanılır.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class IncomingRequest(BaseModel):
    """Caido -> Python köprüsünden FastAPI'ye gelen ham istek modeli."""

    method: str = Field(..., min_length=3, max_length=10)
    url: str = Field(..., min_length=1)
    host: str = Field(..., min_length=1)
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = ""
    status_code: Optional[int] = None
    response_size: Optional[int] = None
    source_program: Optional[str] = None  # örn: "whatnot", "bumba"

    @field_validator("method")
    @classmethod
    def normalize_method(cls, v: str) -> str:
        return v.strip().upper()

    @field_validator("url")
    @classmethod
    def strip_url(cls, v: str) -> str:
        return v.strip()


class RequestRecord(BaseModel):
    """Veritabanından okunurken / API'den dışarı verilirken kullanılan model."""

    id: int
    dedup_hash: str
    method: str
    url: str
    host: str
    status_code: Optional[int]
    response_size: Optional[int]
    is_static: bool
    contains_secret: bool
    secret_matches: Optional[str]
    triage_status: str
    ai_verdict: Optional[str]
    ai_reasoning: Optional[str]
    source_program: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class IngestResponse(BaseModel):
    """Ingest endpoint'inin döndürdüğü sonuç — bot/köprü bunu loglar."""

    status: str  # "created" | "duplicate" | "rejected_static"
    id: Optional[int] = None
    dedup_hash: str
    message: str
