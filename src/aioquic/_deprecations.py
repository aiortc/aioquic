import functools
import inspect
import warnings
from collections.abc import Callable
from typing import Any, TypeVar, cast

F = TypeVar("F", bound=Callable[..., Any])


def deprecate_positional_argument(name: str) -> Callable[[F], F]:
    """
    Let the decorated function accept its keyword-only argument `name`
    positionally, with a deprecation warning.

    The decorated function must declare `name` as its first keyword-only
    argument.
    """

    def decorator(func: F) -> F:
        positional_count = sum(
            parameter.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
            for parameter in inspect.signature(func).parameters.values()
        )

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if len(args) == positional_count + 1 and name not in kwargs:
                warnings.warn(
                    f"Passing {name} as a positional argument is deprecated, "
                    "pass it as a keyword argument instead",
                    DeprecationWarning,
                    stacklevel=2,
                )
                return func(*args[:-1], **{name: args[-1]}, **kwargs)
            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator
