"""OpenAI/Anthropic schema generation for TrustChain tools.

Supports:
- Simple types (str, int, float, bool)
- Pydantic V2 BaseModel arguments
- Optional types, List, Dict
- Field descriptions from Pydantic Field()

Usage:
    from pydantic import BaseModel, Field

    class SearchParams(BaseModel):
        query: str = Field(..., description="Search query")
        limit: int = Field(10, le=100)

    @tc.tool("search")
    def search(params: SearchParams) -> list:
        ...

    schema = tc.get_tool_schema("search")  # Full JSON schema!
"""

import inspect
from typing import Any, Callable, Dict, List, Optional, Union, get_type_hints

# Check for Pydantic V2
try:
    from pydantic import BaseModel

    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    BaseModel = None

# Python type to JSON schema type mapping
TYPE_MAP = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
    type(None): "null",
}


def is_pydantic_model(obj: Any) -> bool:
    """Check if obj is a Pydantic BaseModel class."""
    if not HAS_PYDANTIC:
        return False
    try:
        return isinstance(obj, type) and issubclass(obj, BaseModel)
    except TypeError:
        return False


def pydantic_to_json_schema(model: type) -> Dict[str, Any]:
    """Convert Pydantic model to JSON schema."""
    if hasattr(model, "model_json_schema"):
        # Pydantic V2
        schema = model.model_json_schema()
        # Remove $defs if present (inline definitions)
        schema.pop("$defs", None)
        schema.pop("definitions", None)
        return schema
    elif hasattr(model, "schema"):
        # Pydantic V1 fallback
        return model.schema()
    return {"type": "object", "properties": {}}


def python_type_to_json(py_type: Any) -> Union[str, Dict[str, Any]]:
    """Convert Python type to JSON schema type or full schema."""
    # Check if it's a Pydantic model
    if is_pydantic_model(py_type):
        return pydantic_to_json_schema(py_type)

    if py_type in TYPE_MAP:
        return TYPE_MAP[py_type]

    # Handle Optional, List, Dict, Union
    origin = getattr(py_type, "__origin__", None)
    args = getattr(py_type, "__args__", ())

    if origin is list or origin is List:
        if args:
            item_type = python_type_to_json(args[0])
            if isinstance(item_type, str):
                return {"type": "array", "items": {"type": item_type}}
            return {"type": "array", "items": item_type}
        return "array"

    if origin is dict or origin is Dict:
        return "object"

    if origin is Union:
        # Check for Optional (Union[X, None])
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1:
            return python_type_to_json(non_none[0])
        # Multiple types - use first non-None
        if non_none:
            return python_type_to_json(non_none[0])

    return "string"  # Default fallback


def generate_function_schema(
    func: Callable,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate OpenAI-compatible function schema from a Python function.

    Supports Pydantic BaseModel arguments for complex types.

    Args:
        func: The function to generate schema for
        name: Override function name
        description: Override description (defaults to docstring)

    Returns:
        OpenAI function schema dict
    """
    func_name = name or func.__name__
    func_doc = description or (func.__doc__ or "").strip().split("\n")[0]

    # Get type hints
    try:
        hints = get_type_hints(func)
    except Exception:
        hints = {}

    # Get signature for defaults
    sig = inspect.signature(func)

    properties = {}
    required = []

    for param_name, param in sig.parameters.items():
        if param_name in ("self", "cls"):
            continue

        param_type = hints.get(param_name, str)

        # Check if it's a Pydantic model
        if is_pydantic_model(param_type):
            # Use model's full schema as properties
            model_schema = pydantic_to_json_schema(param_type)
            # If single Pydantic param, flatten its properties
            if len(sig.parameters) == 1 or (
                len(sig.parameters) == 2 and "self" in sig.parameters
            ):
                return {
                    "type": "function",
                    "function": {
                        "name": func_name,
                        "description": func_doc,
                        "parameters": model_schema,
                    },
                }
            # Otherwise nest under param name
            properties[param_name] = model_schema
            required.append(param_name)
        else:
            json_type = python_type_to_json(param_type)

            if isinstance(json_type, dict):
                prop = json_type
            else:
                prop = {"type": json_type}

            # Add default if present
            if param.default is not inspect.Parameter.empty:
                prop["default"] = param.default
            else:
                required.append(param_name)

            properties[param_name] = prop

    return {
        "type": "function",
        "function": {
            "name": func_name,
            "description": func_doc,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


def generate_anthropic_schema(
    func: Callable,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate Anthropic-compatible tool schema.

    Anthropic uses 'input_schema' instead of 'parameters'.
    """
    openai_schema = generate_function_schema(func, name, description)
    func_def = openai_schema["function"]

    return {
        "name": func_def["name"],
        "description": func_def["description"],
        "input_schema": func_def["parameters"],
    }
