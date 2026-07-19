class ComponentsError(Exception):
    """Base class for expected, user-facing errors."""

    code = "COMPONENTS_ERROR"


class ValidationError(ComponentsError):
    code = "VALIDATION_ERROR"


class CatalogError(ValidationError):
    code = "INVALID_CATALOG"


class UnknownProfileError(ValidationError):
    code = "UNKNOWN_PROFILE"


class DigestError(ValidationError):
    code = "DIGEST_MISMATCH"


class CatalogDriftError(ValidationError):
    code = "CATALOG_DRIFT"


class UnsafePathError(ComponentsError):
    code = "UNSAFE_PATH"


class InvalidTransitionError(ValidationError):
    code = "INVALID_STATE_TRANSITION"


class NotImplementedTransactionError(ComponentsError):
    code = "NOT_IMPLEMENTED"


class TransactionError(ComponentsError):
    code = "TRANSACTION_FAILED"
