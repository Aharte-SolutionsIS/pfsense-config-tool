"""
Decorators for CLI commands to handle late binding and avoid circular imports.
"""

import functools
from typing import Callable, Any


# Global references that will be set by main.py
_pass_context: Callable = None
_PfSenseContext: type = None


def set_context_decorator(pass_context_func: Callable, context_class: type):
    """Set the global context decorator and class references."""
    global _pass_context, _PfSenseContext
    _pass_context = pass_context_func
    _PfSenseContext = context_class


def pass_context(func: Callable) -> Callable:
    """Pass context decorator that handles late binding."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if _pass_context is None:
            raise RuntimeError("Context decorator not initialized. Call set_context_decorator first.")
        return _pass_context(func)(*args, **kwargs)
    
    # Return the original function wrapped with the actual decorator when available
    def get_decorated():
        if _pass_context is not None:
            return _pass_context(func)
        return wrapper
    
    # Set a special attribute so we can replace it later
    wrapper._original_func = func
    wrapper._get_decorated = get_decorated
    
    return wrapper


def get_context_type():
    """Get the PfSense context type."""
    return _PfSenseContext