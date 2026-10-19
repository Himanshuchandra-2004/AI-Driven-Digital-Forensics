"""
Pydantic schemas for request/response validation.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field


# ---- Auth ----
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field("", max_length=200)


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ---- Cases ----
class CaseCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=300)
    description: str = Field("", max_length=5000)


class CaseUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=300)
    description: Optional[str] = Field(None, max_length=5000)
    status: Optional[str] = None
    severity: Optional[str] = None


class CaseResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    description: Optional[str]
    status: str
    severity: Optional[str]
    evidence_count: int
    threat_count: int
    anomaly_count: int
    created_at: datetime
    updated_at: datetime
    investigator: Optional[str] = None

    class Config:
        from_attributes = True


# ---- Analysis ----
class AnalysisRunResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    status: str
    source_file: Optional[str]
    source_type: str
    total_records: int
    suspicious_records: int
    anomaly_count: int
    threat_count: int
    preprocessing_time: Optional[float]
    feature_extraction_time: Optional[float]
    inference_time: Optional[float]
    total_time: Optional[float]
    error_message: Optional[str]
    metrics: Optional[Dict[str, Any]]
    started_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


# ---- Threats ----
class ThreatDetectionResponse(BaseModel):
    id: uuid.UUID
    network_event_id: uuid.UUID
    case_id: uuid.UUID
    predicted_class: str
    confidence: Optional[float]
    class_probabilities: Optional[Dict[str, float]]
    severity: Optional[str]
    detected_at: datetime
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    class Config:
        from_attributes = True


# ---- Anomalies ----
class AnomalyResponse(BaseModel):
    id: uuid.UUID
    network_event_id: uuid.UUID
    case_id: uuid.UUID
    anomaly_score: float
    risk_score: float
    is_anomaly: bool
    severity: Optional[str]
    detected_at: datetime
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    class Config:
        from_attributes = True


# ---- Evidence ----
class EvidenceResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    evidence_type: str
    predicted_threat: Optional[str]
    anomaly_score: Optional[float]
    classification_confidence: Optional[float]
    severity: Optional[str]
    risk_score: Optional[float]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    source_file: Optional[str]
    evidence_hash: Optional[str]
    previous_hash: Optional[str]
    status: str
    extraction_timestamp: datetime
    metadata_json: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True


class EvidenceVerifyResponse(BaseModel):
    evidence_id: uuid.UUID
    integrity_verified: bool
    stored_hash: Optional[str]
    calculated_hash: Optional[str]
    message: str


# ---- Incidents ----
class IncidentResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    name: str
    description: Optional[str]
    severity: Optional[str]
    risk_score: Optional[float]
    event_count: int
    involved_ips: Optional[Dict[str, Any]]
    threat_categories: Optional[List[str]]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    created_at: datetime
    evidence_ids: Optional[List[uuid.UUID]] = None

    class Config:
        from_attributes = True


# ---- Chain of Custody ----
class ChainOfCustodyResponse(BaseModel):
    id: uuid.UUID
    evidence_id: uuid.UUID
    user_id: uuid.UUID
    username: Optional[str] = None
    action: str
    description: Optional[str]
    integrity_hash: Optional[str]
    timestamp: datetime

    class Config:
        from_attributes = True


# ---- Reports ----
class ReportResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    user_id: uuid.UUID
    report_type: str
    file_path: Optional[str]
    generated_at: datetime

    class Config:
        from_attributes = True


class ReportGenerateRequest(BaseModel):
    report_type: str = Field("pdf", pattern="^(pdf|json|csv)$")


# ---- Model Versions ----
class ModelVersionResponse(BaseModel):
    id: uuid.UUID
    algorithm: str
    version: str
    dataset_name: Optional[str]
    features: Optional[List[str]]
    metrics: Optional[Dict[str, Any]]
    parameters: Optional[Dict[str, Any]]
    model_path: Optional[str]
    status: str
    trained_at: datetime

    class Config:
        from_attributes = True


# ---- Dashboard ----
class DashboardStats(BaseModel):
    total_cases: int = 0
    active_cases: int = 0
    total_evidence: int = 0
    total_threats: int = 0
    total_anomalies: int = 0
    critical_incidents: int = 0
    high_incidents: int = 0
    threat_distribution: Dict[str, int] = {}
    severity_distribution: Dict[str, int] = {}
    top_source_ips: List[Dict[str, Any]] = []
    top_dest_ips: List[Dict[str, Any]] = []
    recent_cases: List[CaseResponse] = []


# ---- Pagination ----
class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    total_pages: int
