from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
import re
from typing import Any

from .errors import CatalogError, UnknownProfileError, ValidationError
from .jsonio import loads_strict, sha256_bytes


ID_RE = re.compile(r"^[a-z0-9-]+$")
PACKAGE_RE = re.compile(r"^[a-z0-9@._+-]+$")
RELEASE_RE = re.compile(r"^[0-9]{4}\.[0-9]{2}$")
ARCHITECTURE_RE = re.compile(r"^[A-Za-z0-9_+-]+$")


@dataclass(frozen=True)
class Profile:
    id: str
    names: dict[str, str]
    description: dict[str, str]
    packages: tuple[str, ...]
    architectures: tuple[str, ...]
    network_required: bool
    order: int


@dataclass(frozen=True)
class Application:
    id: str
    names: dict[str, str]
    packages: tuple[str, ...]
    architectures: tuple[str, ...]
    network_required: bool
    order: int


@dataclass(frozen=True)
class Catalog:
    path: Path
    sha256: str
    release: str
    architecture: str
    profiles: tuple[Profile, ...]
    applications: tuple[Application, ...]

    def by_id(self) -> dict[str, Profile]:
        return {profile.id: profile for profile in self.profiles}

    def select(self, profile_ids: list[str] | tuple[str, ...]) -> tuple[Profile, ...]:
        profiles = self.by_id()
        unknown = sorted(set(profile_ids) - profiles.keys())
        if unknown:
            raise UnknownProfileError(f"unknown profile(s): {', '.join(unknown)}")
        return tuple(profiles[profile_id] for profile_id in sorted(set(profile_ids)))

    def applications_by_id(self) -> dict[str, Application]:
        return {application.id: application for application in self.applications}

    def select_applications(self, application_ids: list[str] | tuple[str, ...]) -> tuple[Application, ...]:
        applications = self.applications_by_id()
        unknown = sorted(set(application_ids) - applications.keys())
        if unknown:
            raise UnknownProfileError(f"unknown or unreviewed application(s): {', '.join(unknown)}")
        return tuple(applications[application_id] for application_id in sorted(set(application_ids)))


def _object(
    value: Any,
    context: str,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogError(f"{context} must be an object")
    keys = set(value)
    missing = required - keys
    unknown = keys - required - (optional or set())
    if missing:
        raise CatalogError(f"{context} missing field(s): {', '.join(sorted(missing))}")
    if unknown:
        raise CatalogError(f"{context} has unknown field(s): {', '.join(sorted(unknown))}")
    return value


def _array(value: Any, context: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "a non-empty" if nonempty else "an"
        raise CatalogError(f"{context} must be {qualifier} array")
    return value


def _string(value: Any, context: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or (pattern and not pattern.fullmatch(value)):
        raise CatalogError(f"invalid {context}: {value!r}")
    return value


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise CatalogError(f"{context} must be boolean")
    return value


def _unique_strings(value: Any, context: str, *, pattern: re.Pattern[str] | None = None) -> list[str]:
    items = _array(value, context, nonempty=True)
    strings = [_string(item, f"{context} item", pattern) for item in items]
    if len(strings) != len(set(strings)):
        raise CatalogError(f"{context} must contain unique values")
    return strings


def _localized(value: Any, context: str) -> dict[str, str]:
    localized = _object(value, context, {"en", "zh_CN"}, set(value) - {"en", "zh_CN"} if isinstance(value, dict) else set())
    for language, text in localized.items():
        _string(text, f"{context}.{language}")
    return dict(localized)


def _iso_date(value: Any, context: str) -> str:
    text = _string(value, context)
    try:
        date.fromisoformat(text)
    except ValueError as exc:
        raise CatalogError(f"invalid {context}: {text!r}") from exc
    return text


def _unique_ids(items: list[dict[str, Any]], context: str) -> None:
    ids = [item["id"] for item in items]
    if len(ids) != len(set(ids)):
        raise CatalogError(f"duplicate {context} ID")


def load_catalog(path: str | Path, architecture: str) -> Catalog:
    catalog_path = Path(path)
    try:
        raw = catalog_path.read_bytes()
    except OSError as exc:
        raise CatalogError(f"cannot read catalog {catalog_path}: {exc}") from exc
    try:
        root = loads_strict(raw, source=str(catalog_path))
    except ValidationError as exc:
        raise CatalogError(str(exc)) from exc

    root = _object(
        root,
        "catalog",
        {"catalogVersion", "release", "reviewed", "sources", "categories", "profiles"},
        {"$schema", "applications", "desktopBundles"},
    )
    if root["catalogVersion"] != 2 or isinstance(root["catalogVersion"], bool):
        raise CatalogError("catalogVersion must be integer 2")
    if "$schema" in root:
        _string(root["$schema"], "catalog.$schema")
    release = _string(root["release"], "catalog.release", RELEASE_RE)
    _iso_date(root["reviewed"], "catalog.reviewed")

    sources: list[dict[str, Any]] = []
    for index, item in enumerate(_array(root["sources"], "catalog.sources", nonempty=True)):
        source = _object(item, f"source[{index}]", {"id", "kind", "trust", "name"})
        _string(source["id"], f"source[{index}].id", ID_RE)
        if source["kind"] not in {
            "pacman", "aur", "flatpak", "pypi", "npm", "conda",
            "cargo", "go", "oci", "container",
        }:
            raise CatalogError(f"invalid source[{index}].kind")
        if source["trust"] not in {"distribution", "verified-third-party", "user-opt-in"}:
            raise CatalogError(f"invalid source[{index}].trust")
        _localized(source["name"], f"source[{index}].name")
        sources.append(source)
    _unique_ids(sources, "source")
    source_ids = {source["id"] for source in sources}
    arch_sources = {source["id"] for source in sources if source["id"] == "arch" and source["kind"] == "pacman"}

    categories: list[dict[str, Any]] = []
    for index, item in enumerate(_array(root["categories"], "catalog.categories")):
        category = _object(item, f"category[{index}]", {"id", "name"})
        _string(category["id"], f"category[{index}].id", ID_RE)
        _localized(category["name"], f"category[{index}].name")
        categories.append(category)
    _unique_ids(categories, "category")
    category_ids = {category["id"] for category in categories}

    applications: list[Application] = []
    raw_applications: list[dict[str, Any]] = []
    application_fields = {
        "id", "name", "description", "categories", "source", "packages",
        "installer", "availability", "review", "presentation",
    }
    for index, item in enumerate(_array(root.get("applications", []), "catalog.applications")):
        context = f"application[{index}]"
        application = _object(item, context, application_fields)
        application_id = _string(application["id"], f"{context}.id", ID_RE)
        names = _localized(application["name"], f"{context}.name")
        _localized(application["description"], f"{context}.description")
        categories_for_application = _unique_strings(application["categories"], f"{context}.categories")
        missing_categories = set(categories_for_application) - category_ids
        if missing_categories:
            raise CatalogError(f"{context} references unknown categories: {', '.join(sorted(missing_categories))}")
        source = _string(application["source"], f"{context}.source", ID_RE)
        if source not in source_ids:
            raise CatalogError(f"{context} references unknown source: {source}")
        packages = _unique_strings(application["packages"], f"{context}.packages", pattern=PACKAGE_RE)
        installer = _boolean(application["installer"], f"{context}.installer")
        availability = _object(application["availability"], f"{context}.availability", {"architectures", "networkRequired"})
        architectures = _unique_strings(
            availability["architectures"],
            f"{context}.availability.architectures",
            pattern=ARCHITECTURE_RE,
        )
        network_required = _boolean(availability["networkRequired"], f"{context}.availability.networkRequired")
        review = _object(application["review"], f"{context}.review", {"status", "date"})
        if review["status"] not in {"reviewed", "needs-vm-test", "source-review"}:
            raise CatalogError(f"invalid {context}.review.status")
        _iso_date(review["date"], f"{context}.review.date")
        presentation = _object(application["presentation"], f"{context}.presentation", {"recommended", "defaultSelected", "order"})
        _boolean(presentation["recommended"], f"{context}.presentation.recommended")
        _boolean(presentation["defaultSelected"], f"{context}.presentation.defaultSelected")
        order = presentation["order"]
        if not isinstance(order, int) or isinstance(order, bool) or order < 0:
            raise CatalogError(f"{context}.presentation.order must be a non-negative integer")
        raw_applications.append(application)
        if installer and source in arch_sources and review["status"] == "reviewed" and architecture in architectures:
            applications.append(Application(application_id, names, tuple(packages), tuple(architectures), network_required, order))
    _unique_ids(raw_applications, "application")

    profiles: list[Profile] = []
    raw_profiles: list[dict[str, Any]] = []
    profile_fields = {
        "id", "name", "description", "categories", "source", "packages",
        "installer", "availability", "review", "presentation",
    }
    for index, item in enumerate(_array(root["profiles"], "catalog.profiles")):
        context = f"profile[{index}]"
        profile = _object(item, context, profile_fields, {"applications"})
        profile_id = _string(profile["id"], f"{context}.id", ID_RE)
        names = _localized(profile["name"], f"{context}.name")
        description = _localized(profile["description"], f"{context}.description")
        categories_for_profile = _unique_strings(profile["categories"], f"{context}.categories")
        missing_categories = set(categories_for_profile) - category_ids
        if missing_categories:
            raise CatalogError(f"{context} references unknown categories: {', '.join(sorted(missing_categories))}")
        source = _string(profile["source"], f"{context}.source", ID_RE)
        if source not in source_ids:
            raise CatalogError(f"{context} references unknown source: {source}")
        if source not in arch_sources:
            raise CatalogError(f"{context} source must be the pacman arch source")
        packages = _unique_strings(profile["packages"], f"{context}.packages", pattern=PACKAGE_RE)
        if "applications" in profile:
            _unique_strings(profile["applications"], f"{context}.applications", pattern=ID_RE)
        _boolean(profile["installer"], f"{context}.installer")

        availability = _object(profile["availability"], f"{context}.availability", {"architectures", "networkRequired"})
        architectures = _unique_strings(
            availability["architectures"],
            f"{context}.availability.architectures",
            pattern=ARCHITECTURE_RE,
        )
        if architecture not in architectures:
            raise CatalogError(f"{context} is not available for architecture {architecture!r}")
        network_required = _boolean(availability["networkRequired"], f"{context}.availability.networkRequired")

        review = _object(profile["review"], f"{context}.review", {"status", "date"})
        if review["status"] != "reviewed":
            raise CatalogError(f"{context}.review.status must be 'reviewed'")
        _iso_date(review["date"], f"{context}.review.date")

        presentation = _object(profile["presentation"], f"{context}.presentation", {"recommended", "order"})
        _boolean(presentation["recommended"], f"{context}.presentation.recommended")
        order = presentation["order"]
        if not isinstance(order, int) or isinstance(order, bool) or order < 0:
            raise CatalogError(f"{context}.presentation.order must be a non-negative integer")

        raw_profiles.append(profile)
        profiles.append(Profile(profile_id, names, description, tuple(packages), tuple(architectures), network_required, order))
    _unique_ids(raw_profiles, "profile")
    return Catalog(catalog_path, sha256_bytes(raw), release, architecture, tuple(profiles), tuple(applications))
