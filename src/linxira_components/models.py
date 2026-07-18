from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Callable
from uuid import UUID, uuid4

from .catalog import Catalog, ID_RE, PACKAGE_RE
from .errors import CatalogDriftError, DigestError, InvalidTransitionError, ValidationError
from .jsonio import document_digest


PLAN_SCHEMA = "org.linxira.components.request-plan.v1"
CONFIRMATION_SCHEMA = "org.linxira.components.confirmation.v1"
RECEIPT_SCHEMA = "org.linxira.components.receipt.v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_uuid(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a UUID string")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValidationError(f"{field_name} must be a UUID string") from exc
    if str(parsed) != value:
        raise ValidationError(f"{field_name} must use canonical UUID form")
    return value


def _validate_timestamp(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not UTC_TIMESTAMP_RE.fullmatch(value):
        raise ValidationError(f"{field_name} must be a canonical UTC timestamp")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValidationError(f"invalid {field_name}") from exc
    return value


def _exact_fields(document: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ValidationError(f"{context} must be an object")
    missing = expected - set(document)
    unknown = set(document) - expected
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing {', '.join(sorted(missing))}")
        if unknown:
            details.append(f"unknown {', '.join(sorted(unknown))}")
        raise ValidationError(f"invalid {context} fields: {'; '.join(details)}")
    return document


def create_request_plan(
    catalog: Catalog,
    profile_ids: list[str] | tuple[str, ...],
    architecture: str,
    *,
    clock: Clock = utc_now,
    id_factory: Callable[[], Any] = uuid4,
) -> dict[str, Any]:
    if architecture != catalog.architecture:
        raise ValidationError("plan architecture differs from the validated catalog architecture")
    selected = catalog.select(profile_ids)
    document: dict[str, Any] = {
        "schemaVersion": PLAN_SCHEMA,
        "id": str(id_factory()),
        "createdAt": format_utc(clock()),
        "catalogSha256": catalog.sha256,
        "architecture": architecture,
        "profileIds": sorted({profile.id for profile in selected}),
        "directPackageTargets": sorted({package for profile in selected for package in profile.packages}),
        "networkRequired": any(profile.network_required for profile in selected),
        "systemUpgradeRequired": False,
    }
    document["digest"] = document_digest(document)
    return document


def validate_request_plan(document: Any, *, catalog_sha256: str | None = None) -> dict[str, Any]:
    expected = {
        "schemaVersion", "id", "createdAt", "catalogSha256", "architecture",
        "profileIds", "directPackageTargets", "networkRequired",
        "systemUpgradeRequired", "digest",
    }
    plan = _exact_fields(document, expected, "request plan")
    if plan["schemaVersion"] != PLAN_SCHEMA:
        raise ValidationError("unsupported request plan schemaVersion")
    _validate_uuid(plan["id"], "request plan id")
    _validate_timestamp(plan["createdAt"], "createdAt")
    for field_name in ("catalogSha256", "digest"):
        if not isinstance(plan[field_name], str) or not SHA256_RE.fullmatch(plan[field_name]):
            raise ValidationError(f"{field_name} must be a lowercase SHA-256 digest")
    if not isinstance(plan["architecture"], str) or not plan["architecture"]:
        raise ValidationError("architecture must be a non-empty string")
    for field_name in ("profileIds", "directPackageTargets"):
        values = plan[field_name]
        if not isinstance(values, list) or not values or not all(isinstance(item, str) and item for item in values):
            raise ValidationError(f"{field_name} must be a non-empty string array")
        if values != sorted(set(values)):
            raise ValidationError(f"{field_name} must be de-duplicated and stably sorted")
    if not all(ID_RE.fullmatch(value) for value in plan["profileIds"]):
        raise ValidationError("profileIds contains an invalid profile ID")
    if not all(PACKAGE_RE.fullmatch(value) for value in plan["directPackageTargets"]):
        raise ValidationError("directPackageTargets contains an invalid package name")
    for field_name in ("networkRequired", "systemUpgradeRequired"):
        if not isinstance(plan[field_name], bool):
            raise ValidationError(f"{field_name} must be boolean")
    expected_digest = document_digest(plan)
    if plan["digest"] != expected_digest:
        raise DigestError("request plan digest does not match its canonical content")
    if catalog_sha256 is not None and plan["catalogSha256"] != catalog_sha256:
        raise CatalogDriftError("catalog changed after the request plan was created")
    return plan


def create_confirmation(
    plan: dict[str, Any],
    catalog: Catalog,
    *,
    clock: Clock = utc_now,
    id_factory: Callable[[], Any] = uuid4,
) -> dict[str, Any]:
    validated = validate_request_plan(plan, catalog_sha256=catalog.sha256)
    if validated["architecture"] != catalog.architecture:
        raise ValidationError("request plan architecture differs from the validated catalog architecture")
    selected = catalog.select(validated["profileIds"])
    expected_packages = sorted({package for profile in selected for package in profile.packages})
    if validated["directPackageTargets"] != expected_packages:
        raise ValidationError("request plan package targets do not match its catalog profiles")
    if validated["networkRequired"] != any(profile.network_required for profile in selected):
        raise ValidationError("request plan network flag does not match its catalog profiles")
    if validated["systemUpgradeRequired"] is not False:
        raise ValidationError("Phase 1 plans cannot require a system upgrade")
    document: dict[str, Any] = {
        "schemaVersion": CONFIRMATION_SCHEMA,
        "id": str(id_factory()),
        "confirmedAt": format_utc(clock()),
        "requestPlanId": validated["id"],
        "planDigest": validated["digest"],
        "catalogSha256": catalog.sha256,
    }
    document["digest"] = document_digest(document)
    return document


ALLOWED_TRANSITIONS = {
    "planned": frozenset({"confirmed", "stale"}),
    "confirmed": frozenset({"applying", "stale", "interrupted"}),
    "applying": frozenset({"succeeded", "failed", "stale", "interrupted"}),
    "succeeded": frozenset(),
    "failed": frozenset(),
    "stale": frozenset(),
    "interrupted": frozenset(),
}


@dataclass
class Receipt:
    request_plan_id: str
    plan_digest: str
    id: str = field(default_factory=lambda: str(uuid4()))
    status: str = "planned"
    created_at: str = field(default_factory=lambda: format_utc(utc_now()))
    updated_at: str | None = None
    message: str | None = None

    def __post_init__(self) -> None:
        _validate_uuid(self.id, "receipt id")
        _validate_uuid(self.request_plan_id, "requestPlanId")
        if self.status not in ALLOWED_TRANSITIONS:
            raise ValidationError(f"invalid receipt status: {self.status!r}")
        if not SHA256_RE.fullmatch(self.plan_digest):
            raise ValidationError("planDigest must be a lowercase SHA-256 digest")
        _validate_timestamp(self.created_at, "createdAt")
        if self.updated_at is not None:
            _validate_timestamp(self.updated_at, "updatedAt")

    def transition(self, new_status: str, *, message: str | None = None, clock: Clock = utc_now) -> None:
        if new_status not in ALLOWED_TRANSITIONS.get(self.status, frozenset()):
            raise InvalidTransitionError(f"illegal receipt transition: {self.status} -> {new_status}")
        self.status = new_status
        self.updated_at = format_utc(clock())
        self.message = message

    def to_document(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "schemaVersion": RECEIPT_SCHEMA,
            "id": self.id,
            "requestPlanId": self.request_plan_id,
            "planDigest": self.plan_digest,
            "status": self.status,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "message": self.message,
        }
        document["digest"] = document_digest(document)
        return document
