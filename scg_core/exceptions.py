"""Core exception hierarchy for Supply Chain Guardian (SCG).

This module defines the foundational exception architecture conformant to
IEEE Std 830-1998 and RFC 2119. All downstream modules, pipelines, and parallel
tracks within SCG inherit from and raise these typed exceptions to guarantee
resilient failure handling without introducing unhandled runtime crashes.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


class SCGError(Exception):
    """Base exception class for all Supply Chain Guardian (SCG) errors.

    Accepts an optional error message and structured contextual metadata.
    Serializes details cleanly in `__str__` for observability and logging.

    Attributes:
        message: Human-readable explanation of the error.
        details: Structured context dictionary for diagnostics and debugging.
    """

    def __init__(
        self,
        message: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initializes the SCG base error with an optional message and structured details.

        Args:
            message: Human-readable error description. Defaults to empty string.
            details: Optional dictionary containing contextual debugging metadata.
        """
        super().__init__(message)
        self.message: str = message
        self.details: Dict[str, Any] = dict(details) if details is not None else {}

    def __str__(self) -> str:
        """Returns a string representation of the exception, formatting structured details cleanly.

        Returns:
            Formatted string combining message and JSON-serialized details.
        """
        if self.details:
            try:
                serialized = json.dumps(self.details, default=str, sort_keys=True)
            except Exception:
                serialized = str(self.details)
            if self.message:
                return f"{self.message} | Context: {serialized}"
            return f"Context: {serialized}"
        return self.message

    def __repr__(self) -> str:
        """Returns the unambiguous string representation of the exception.

        Returns:
            Formal representation showing class name, message, and details.
        """
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, details={self.details!r})"
        )


class ManifestParseError(SCGError):
    """Raised when parsing a package dependency manifest fails.

    Applicable manifests include `package.json`, `package-lock.json`,
    `requirements.txt`, and `poetry.lock`.

    Attributes:
        manifest_path: Optional file path of the manifest that triggered the error.
    """

    def __init__(
        self,
        message: str = "Failed to parse dependency manifest.",
        manifest_path: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initializes ManifestParseError with manifest location and contextual details.

        Args:
            message: Human-readable error description.
            manifest_path: Optional path to the invalid or unparseable manifest file.
            details: Optional dictionary containing contextual debugging metadata.
        """
        merged_details: Dict[str, Any] = dict(details) if details is not None else {}
        if manifest_path is not None:
            merged_details.setdefault("manifest_path", manifest_path)
        super().__init__(message=message, details=merged_details)
        self.manifest_path: Optional[str] = manifest_path

    def __repr__(self) -> str:
        """Returns the unambiguous string representation of the exception.

        Returns:
            Formal representation including manifest_path.
        """
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"manifest_path={self.manifest_path!r}, "
            f"details={self.details!r})"
        )


class GraphCycleError(SCGError):
    """Raised when an unresolvable circular dependency is detected in NetworkX processing.

    Attributes:
        cycle: Optional ordered sequence of package nodes participating in the cycle.
    """

    def __init__(
        self,
        message: str = "Unresolvable circular dependency cycle detected in graph.",
        cycle: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initializes GraphCycleError with the detected cycle nodes and contextual details.

        Args:
            message: Human-readable error description.
            cycle: Optional list of package identifiers forming the circular dependency.
            details: Optional dictionary containing contextual debugging metadata.
        """
        merged_details: Dict[str, Any] = dict(details) if details is not None else {}
        if cycle is not None:
            merged_details.setdefault("cycle", cycle)
        super().__init__(message=message, details=merged_details)
        self.cycle: Optional[List[str]] = cycle

    def __repr__(self) -> str:
        """Returns the unambiguous string representation of the exception.

        Returns:
            Formal representation including cycle nodes.
        """
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"cycle={self.cycle!r}, "
            f"details={self.details!r})"
        )


class SBOMGenerationError(SCGError):
    """Raised when CycloneDX CLI or subprocesses exit non-zero or output corrupted JSON.

    Attributes:
        exit_code: Optional exit code returned by the CycloneDX generator subprocess.
    """

    def __init__(
        self,
        message: str = "CycloneDX SBOM generation failed or output invalid content.",
        exit_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initializes SBOMGenerationError with subprocess status and contextual details.

        Args:
            message: Human-readable error description.
            exit_code: Optional integer return code from the generator process.
            details: Optional dictionary containing contextual debugging metadata.
        """
        merged_details: Dict[str, Any] = dict(details) if details is not None else {}
        if exit_code is not None:
            merged_details.setdefault("exit_code", exit_code)
        super().__init__(message=message, details=merged_details)
        self.exit_code: Optional[int] = exit_code

    def __repr__(self) -> str:
        """Returns the unambiguous string representation of the exception.

        Returns:
            Formal representation including exit_code.
        """
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"exit_code={self.exit_code!r}, "
            f"details={self.details!r})"
        )


class EnrichmentAPIError(SCGError):
    """Raised when upstream vulnerability or health APIs return 5xx or invalid schemas.

    Supported upstream sources include OSV, OpenSSF Scorecard, and package registries.

    Attributes:
        status_code: Optional HTTP status code returned by the remote API.
        endpoint: Optional URL or name of the upstream service endpoint.
    """

    def __init__(
        self,
        message: str = "Upstream enrichment API returned a server error or invalid schema.",
        status_code: Optional[int] = None,
        endpoint: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initializes EnrichmentAPIError with HTTP status, endpoint, and contextual details.

        Args:
            message: Human-readable error description.
            status_code: Optional HTTP status code returned by the upstream service.
            endpoint: Optional upstream API endpoint identifier or URL.
            details: Optional dictionary containing contextual debugging metadata.
        """
        merged_details: Dict[str, Any] = dict(details) if details is not None else {}
        if status_code is not None:
            merged_details.setdefault("status_code", status_code)
        if endpoint is not None:
            merged_details.setdefault("endpoint", endpoint)
        super().__init__(message=message, details=merged_details)
        self.status_code: Optional[int] = status_code
        self.endpoint: Optional[str] = endpoint

    def __repr__(self) -> str:
        """Returns the unambiguous string representation of the exception.

        Returns:
            Formal representation including status_code and endpoint.
        """
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"status_code={self.status_code!r}, "
            f"endpoint={self.endpoint!r}, "
            f"details={self.details!r})"
        )


class RateLimitExceededError(SCGError):
    """Raised when external API rate limits are hit (HTTP 429).

    Attributes:
        retry_after: Optional number of seconds to wait before retrying the request.
    """

    def __init__(
        self,
        message: str = "Upstream API rate limit exceeded (HTTP 429).",
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initializes RateLimitExceededError with retry delay and contextual details.

        Args:
            message: Human-readable error description.
            retry_after: Optional integer specifying seconds to wait before retrying.
            details: Optional dictionary containing contextual debugging metadata.
        """
        merged_details: Dict[str, Any] = dict(details) if details is not None else {}
        if retry_after is not None:
            merged_details.setdefault("retry_after", retry_after)
        super().__init__(message=message, details=merged_details)
        self.retry_after: Optional[int] = retry_after

    def __repr__(self) -> str:
        """Returns the unambiguous string representation of the exception.

        Returns:
            Formal representation including retry_after duration.
        """
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"retry_after={self.retry_after!r}, "
            f"details={self.details!r})"
        )


class ASTParseError(SCGError):
    """Raised when a source file (.py, .js, .ts) contains unrecoverable syntax errors during reachability extraction.

    Attributes:
        file_path: Optional path of the source code file where parsing failed.
        line_number: Optional line number where syntax parsing aborted.
    """

    def __init__(
        self,
        message: str = "Unrecoverable syntax error encountered during AST parsing.",
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initializes ASTParseError with source location and contextual details.

        Args:
            message: Human-readable error description.
            file_path: Optional path to the source file that failed parsing.
            line_number: Optional line number where syntax parsing failed.
            details: Optional dictionary containing contextual debugging metadata.
        """
        merged_details: Dict[str, Any] = dict(details) if details is not None else {}
        if file_path is not None:
            merged_details.setdefault("file_path", file_path)
        if line_number is not None:
            merged_details.setdefault("line_number", line_number)
        super().__init__(message=message, details=merged_details)
        self.file_path: Optional[str] = file_path
        self.line_number: Optional[int] = line_number

    def __repr__(self) -> str:
        """Returns the unambiguous string representation of the exception.

        Returns:
            Formal representation including file_path and line_number.
        """
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"file_path={self.file_path!r}, "
            f"line_number={self.line_number!r}, "
            f"details={self.details!r})"
        )


class ScoringPolicyError(SCGError):
    """Raised when a repository .scgrc.json contains invalid schema rules or conflicting weights.

    Attributes:
        config_path: Optional path to the invalid configuration file.
    """

    def __init__(
        self,
        message: str = "Invalid scoring policy configuration or conflicting weights.",
        config_path: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initializes ScoringPolicyError with config location and contextual details.

        Args:
            message: Human-readable error description.
            config_path: Optional path to the configuration file that failed validation.
            details: Optional dictionary containing contextual debugging metadata.
        """
        merged_details: Dict[str, Any] = dict(details) if details is not None else {}
        if config_path is not None:
            merged_details.setdefault("config_path", config_path)
        super().__init__(message=message, details=merged_details)
        self.config_path: Optional[str] = config_path

    def __repr__(self) -> str:
        """Returns the unambiguous string representation of the exception.

        Returns:
            Formal representation including config_path.
        """
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"config_path={self.config_path!r}, "
            f"details={self.details!r})"
        )


class RemediationExecutionError(SCGError):
    """Raised when package manager resolution fails in the ephemeral Docker sandbox.

    Attributes:
        exit_code: Process exit code returned by the sandbox container execution.
        stderr: Standard error output captured from the sandbox execution.
    """

    def __init__(
        self,
        message: str = "Package manager resolution failed in sandbox.",
        exit_code: int = 1,
        stderr: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initializes RemediationExecutionError with exit code, stderr, and contextual details.

        Args:
            message: Human-readable error description.
            exit_code: Integer exit status from the ephemeral sandbox process.
            stderr: Captured standard error output string.
            details: Optional dictionary containing contextual debugging metadata.
        """
        merged_details: Dict[str, Any] = dict(details) if details is not None else {}
        merged_details.setdefault("exit_code", exit_code)
        merged_details.setdefault("stderr", stderr)
        super().__init__(message=message, details=merged_details)
        self.exit_code: int = exit_code
        self.stderr: str = stderr

    def __repr__(self) -> str:
        """Returns the unambiguous string representation of the exception.

        Returns:
            Formal representation including exit_code and stderr.
        """
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"exit_code={self.exit_code!r}, "
            f"stderr={self.stderr!r}, "
            f"details={self.details!r})"
        )


if __name__ == "__main__":
    import sys

    print("Executing verification harness for scg_core/exceptions.py...")

    # 1. ManifestParseError Verification
    try:
        raise ManifestParseError(
            message="Failed to parse package-lock.json at root",
            manifest_path="package-lock.json",
            details={"parser": "npm-lockfile-v2", "line": 42},
        )
    except ManifestParseError as exc:
        assert isinstance(exc, SCGError), "ManifestParseError must inherit from SCGError"
        assert exc.manifest_path == "package-lock.json", "manifest_path attribute mismatch"
        assert exc.details.get("line") == 42, "details attribute mismatch"
        assert "package-lock.json" in str(exc), "str(exc) must contain contextual details"
        print("✓ [1/8] ManifestParseError verified successfully.")

    # 2. GraphCycleError Verification
    try:
        cycle_path = ["pkg-a@1.0.0", "pkg-b@2.1.0", "pkg-a@1.0.0"]
        raise GraphCycleError(
            message="Detected circular dependency loop",
            cycle=cycle_path,
            details={"algorithm": "simple_cycles", "subgraph_size": 12},
        )
    except GraphCycleError as exc:
        assert isinstance(exc, SCGError), "GraphCycleError must inherit from SCGError"
        assert exc.cycle == cycle_path, "cycle attribute mismatch"
        assert exc.details.get("subgraph_size") == 12, "details attribute mismatch"
        assert "pkg-a@1.0.0" in str(exc), "str(exc) must serialize cycle in details"
        print("✓ [2/8] GraphCycleError verified successfully.")

    # 3. SBOMGenerationError Verification
    try:
        raise SBOMGenerationError(
            message="cyclonedx-py subprocess exited with error",
            exit_code=127,
            details={"command": "cyclonedx-py requirements requirements.txt"},
        )
    except SBOMGenerationError as exc:
        assert isinstance(exc, SCGError), "SBOMGenerationError must inherit from SCGError"
        assert exc.exit_code == 127, "exit_code attribute mismatch"
        assert "requirements.txt" in str(exc), "str(exc) must contain details"
        print("✓ [3/8] SBOMGenerationError verified successfully.")

    # 4. EnrichmentAPIError Verification
    try:
        raise EnrichmentAPIError(
            message="OSV API returned HTTP 503 Service Unavailable",
            status_code=503,
            endpoint="https://api.osv.dev/v1/query",
            details={"package": "lodash", "ecosystem": "npm"},
        )
    except EnrichmentAPIError as exc:
        assert isinstance(exc, SCGError), "EnrichmentAPIError must inherit from SCGError"
        assert exc.status_code == 503, "status_code attribute mismatch"
        assert exc.endpoint == "https://api.osv.dev/v1/query", "endpoint attribute mismatch"
        assert exc.details.get("package") == "lodash", "details attribute mismatch"
        assert "503" in str(exc), "str(exc) must contain status code"
        print("✓ [4/8] EnrichmentAPIError verified successfully.")

    # 5. RateLimitExceededError Verification
    try:
        raise RateLimitExceededError(
            message="GitHub API rate limit exhausted",
            retry_after=60,
            details={"rate_limit_reset_epoch": 1726740000},
        )
    except RateLimitExceededError as exc:
        assert isinstance(exc, SCGError), "RateLimitExceededError must inherit from SCGError"
        assert exc.retry_after == 60, "retry_after attribute mismatch"
        assert exc.details.get("retry_after") == 60, "details must record retry_after"
        assert "60" in str(exc), "str(exc) must serialize retry_after"
        print("✓ [5/8] RateLimitExceededError verified successfully.")

    # 6. ASTParseError Verification
    try:
        raise ASTParseError(
            message="Syntax error encountered while parsing TypeScript source",
            file_path="src/index.ts",
            line_number=105,
            details={"parser": "tree-sitter-typescript"},
        )
    except ASTParseError as exc:
        assert isinstance(exc, SCGError), "ASTParseError must inherit from SCGError"
        assert exc.file_path == "src/index.ts", "file_path attribute mismatch"
        assert exc.line_number == 105, "line_number attribute mismatch"
        assert exc.details.get("line_number") == 105, "details must record line_number"
        assert "src/index.ts" in str(exc), "str(exc) must contain file path"
        print("✓ [6/8] ASTParseError verified successfully.")

    # 7. ScoringPolicyError Verification
    try:
        raise ScoringPolicyError(
            message="Invalid weights configuration: weights must sum to 1.0",
            config_path=".scgrc.json",
            details={"vulnerability_weight": 0.8, "reachability_weight": 0.5},
        )
    except ScoringPolicyError as exc:
        assert isinstance(exc, SCGError), "ScoringPolicyError must inherit from SCGError"
        assert exc.config_path == ".scgrc.json", "config_path attribute mismatch"
        assert exc.details.get("config_path") == ".scgrc.json", "details must contain config_path"
        assert ".scgrc.json" in str(exc), "str(exc) must format details"
        print("✓ [7/8] ScoringPolicyError verified successfully.")

    # 8. RemediationExecutionError Verification
    try:
        raise RemediationExecutionError(
            message="npm install failed within ephemeral Docker sandbox",
            exit_code=1,
            stderr="npm ERR! ERESOLVE unable to resolve dependency tree",
            details={"sandbox_id": "scg-sandbox-8f92a", "target_package": "express@4.18.2"},
        )
    except RemediationExecutionError as exc:
        assert isinstance(exc, SCGError), "RemediationExecutionError must inherit from SCGError"
        assert exc.exit_code == 1, "exit_code attribute mismatch"
        assert "ERESOLVE" in exc.stderr, "stderr attribute mismatch"
        assert exc.details.get("exit_code") == 1, "details must record exit_code"
        assert "ERESOLVE" in str(exc), "str(exc) must serialize stderr"
        print("✓ [8/8] RemediationExecutionError verified successfully.")

    print("\nAll 8 SCG exception types verified successfully with preserved attributes.")
