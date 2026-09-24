"""
Phase 6 — Model artifact registry and trusted-only loading.

Security contract
-----------------
Model artifacts are produced exclusively by the controlled training
pipeline.  Before loading any artifact, ALL of the following checks
must pass:

  1. SHA-256 hash matches the registry metadata entry.
  2. model_version matches.
  3. feature_schema_version matches.
  4. label_schema_version matches.
  5. python_version is compatible.
  6. Required library versions are compatible.

If ANY check fails:
  - Raise ModelArtifactSecurityError.
  - The caller must fall back to deterministic risk-v1.

Security justification
----------------------
joblib uses pickle internally.  Loading an untrusted pickle can execute
arbitrary code.  Therefore:
  - Only artifacts from THIS pipeline are loaded.
  - SHA-256 is used to verify integrity (not to "make pickle safe").
  - There is no "safe-load flag" — the trust derives from pipeline
    provenance, not from the file format.
  - Arbitrary user-supplied model artifacts are NEVER loaded.

Registry format (JSON)
----------------------
{
  "model_version": "0.1.0",
  "feature_schema_version": "1.0.0",
  "label_schema_version": "1.0.0",
  "sha256": "<64-char hex>",
  "python_version": "3.14",
  "library_versions": {
      "scikit-learn": "1.5.2",
      "numpy": "2.0.2",
      "joblib": "1.4.2"
  },
  "trained_at_utc": "<ISO-8601>",
  "artifact_path": "<relative path>",
  "notes": ""
}
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ModelArtifactSecurityError(Exception):
    """Raised when a model artifact fails any pre-load security check."""


@dataclass
class ModelRegistryEntry:
    """Metadata for one registered model artifact."""

    model_version: str
    feature_schema_version: str
    label_schema_version: str
    sha256: str
    python_version: str                      # e.g. "3.14"
    library_versions: dict[str, str]         # e.g. {"scikit-learn": "1.5.2"}
    trained_at_utc: str
    artifact_path: str
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ModelRegistryEntry":
        return cls(
            model_version=d["model_version"],
            feature_schema_version=d["feature_schema_version"],
            label_schema_version=d["label_schema_version"],
            sha256=d["sha256"],
            python_version=d["python_version"],
            library_versions=d.get("library_versions", {}),
            trained_at_utc=d["trained_at_utc"],
            artifact_path=d["artifact_path"],
            notes=d.get("notes", ""),
        )


def compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 of a file, reading in 64 KiB blocks."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def _current_python_major_minor() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def _get_installed_version(package: str) -> str | None:
    """Return the installed version of a package, or None if not importable."""
    try:
        import importlib.metadata
        return importlib.metadata.version(package)
    except Exception:
        return None


def validate_artifact(
    artifact_path: Path,
    registry_entry: ModelRegistryEntry,
    expected_model_version: str,
    expected_feature_schema_version: str,
    expected_label_schema_version: str,
) -> None:
    """
    Run all pre-load security checks on a model artifact.

    Raises ModelArtifactSecurityError on any mismatch.

    Parameters
    ----------
    artifact_path:
        Absolute path to the joblib artifact file.
    registry_entry:
        The trusted registry metadata record for this artifact.
    expected_model_version, expected_feature_schema_version,
    expected_label_schema_version:
        Values to verify against.
    """
    if not artifact_path.exists():
        raise ModelArtifactSecurityError(
            f"Artifact file not found: {artifact_path}"
        )

    # 1. SHA-256 integrity check.
    actual_sha256 = compute_file_sha256(artifact_path)
    if actual_sha256 != registry_entry.sha256:
        raise ModelArtifactSecurityError(
            f"SHA-256 mismatch for {artifact_path}. "
            f"Expected {registry_entry.sha256!r}, "
            f"got {actual_sha256!r}. Artifact may be corrupted or tampered."
        )

    # 2. model_version check.
    if registry_entry.model_version != expected_model_version:
        raise ModelArtifactSecurityError(
            f"model_version mismatch: registry has {registry_entry.model_version!r}, "
            f"expected {expected_model_version!r}."
        )

    # 3. feature_schema_version check.
    if registry_entry.feature_schema_version != expected_feature_schema_version:
        raise ModelArtifactSecurityError(
            f"feature_schema_version mismatch: registry has "
            f"{registry_entry.feature_schema_version!r}, "
            f"expected {expected_feature_schema_version!r}."
        )

    # 4. label_schema_version check.
    if registry_entry.label_schema_version != expected_label_schema_version:
        raise ModelArtifactSecurityError(
            f"label_schema_version mismatch: registry has "
            f"{registry_entry.label_schema_version!r}, "
            f"expected {expected_label_schema_version!r}."
        )

    # 5. Python runtime compatibility check.
    current_py = _current_python_major_minor()
    registry_py = registry_entry.python_version
    if current_py != registry_py:
        raise ModelArtifactSecurityError(
            f"Python version mismatch: artifact was trained on Python "
            f"{registry_py!r}, current runtime is {current_py!r}. "
            "Re-train or run on the matching Python version."
        )

    # 6. Library version checks.
    for lib_name, expected_ver in registry_entry.library_versions.items():
        installed = _get_installed_version(lib_name)
        if installed is None:
            raise ModelArtifactSecurityError(
                f"Required library {lib_name!r} is not installed."
            )
        if installed != expected_ver:
            raise ModelArtifactSecurityError(
                f"Library version mismatch for {lib_name!r}: "
                f"registry expects {expected_ver!r}, installed is {installed!r}. "
                "Re-train or install the exact matching version."
            )


def trusted_load(
    artifact_path: Path,
    registry_entry: ModelRegistryEntry,
    expected_model_version: str,
    expected_feature_schema_version: str,
    expected_label_schema_version: str,
) -> Any:
    """
    Load a joblib model artifact from the trusted pipeline ONLY after all
    security checks pass.

    This function will NEVER load arbitrary user-supplied files.

    Parameters
    ----------
    artifact_path:
        Path to the joblib artifact produced by ml.trainer.
    registry_entry:
        Registry metadata entry for this artifact.
    expected_model_version, expected_feature_schema_version,
    expected_label_schema_version:
        Versions to verify.

    Returns
    -------
    Any
        The deserialised scikit-learn model object.

    Raises
    ------
    ModelArtifactSecurityError
        If any security check fails.
    """
    import joblib  # noqa: PLC0415

    validate_artifact(
        artifact_path=artifact_path,
        registry_entry=registry_entry,
        expected_model_version=expected_model_version,
        expected_feature_schema_version=expected_feature_schema_version,
        expected_label_schema_version=expected_label_schema_version,
    )
    return joblib.load(artifact_path)


def load_registry_entry(registry_path: Path) -> ModelRegistryEntry:
    """
    Load the registry JSON and return a ModelRegistryEntry.

    Parameters
    ----------
    registry_path:
        Path to the ``ml_model_registry.json`` file.

    Returns
    -------
    ModelRegistryEntry

    Raises
    ------
    FileNotFoundError, json.JSONDecodeError, KeyError
        On malformed or missing registry files.
    """
    with open(registry_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return ModelRegistryEntry.from_dict(data)


def save_registry_entry(entry: ModelRegistryEntry, registry_path: Path) -> None:
    """Serialise a ModelRegistryEntry to JSON at the given path."""
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    with open(registry_path, "w", encoding="utf-8") as fh:
        json.dump(entry.to_dict(), fh, indent=2, default=str)
