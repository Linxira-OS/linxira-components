from __future__ import annotations

from typing import NoReturn

from .errors import NotImplementedTransactionError


def apply_transaction(*_args: object, **_kwargs: object) -> NoReturn:
    raise NotImplementedTransactionError(
        "Phase 1 does not implement package transactions; no command was executed"
    )
