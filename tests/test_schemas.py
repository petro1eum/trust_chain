"""Tests for trustchain/v2/schemas.py - OpenAI/Anthropic schema generation."""

import pytest
from typing import Optional, List
from pydantic import BaseModel, Field

from trustchain.v2.schemas import (
    generate_function_schema,
    generate_anthropic_schema,
    python_type_to_json,
    is_pydantic_model,
    pydantic_to_json_schema,
)


class TestPythonTypeToJson:
    """Test Python type to JSON type conversion."""

    def test_basic_types(self):
        assert python_type_to_json(str) == "string"
        assert python_type_to_json(int) == "integer"
        assert python_type_to_json(float) == "number"
        assert python_type_to_json(bool) == "boolean"
        assert python_type_to_json(list) == "array"
        assert python_type_to_json(dict) == "object"

    def test_none_type(self):
        assert python_type_to_json(type(None)) == "null"

    def test_unknown_type(self):
        class CustomClass:
            pass

        assert python_type_to_json(CustomClass) == "string"


class TestGenerateFunctionSchema:
    """Test OpenAI function schema generation."""

    def test_simple_function(self):
        def greet(name: str) -> str:
            """Greet a person."""
            return f"Hello, {name}"

        schema = generate_function_schema(greet)

        assert schema["type"] == "function"
        assert schema["function"]["name"] == "greet"
        assert schema["function"]["description"] == "Greet a person."
        assert "name" in schema["function"]["parameters"]["properties"]
        assert (
            schema["function"]["parameters"]["properties"]["name"]["type"] == "string"
        )
        assert "name" in schema["function"]["parameters"]["required"]

    def test_function_with_defaults(self):
        def search(query: str, limit: int = 10) -> list:
            """Search for items."""
            return []

        schema = generate_function_schema(search)

        props = schema["function"]["parameters"]["properties"]
        assert "query" in props
        assert "limit" in props
        assert "query" in schema["function"]["parameters"]["required"]
        assert "limit" not in schema["function"]["parameters"]["required"]

    def test_function_with_multiple_types(self):
        def process(text: str, count: int, ratio: float, active: bool) -> dict:
            """Process data."""
            return {}

        schema = generate_function_schema(process)

        props = schema["function"]["parameters"]["properties"]
        assert props["text"]["type"] == "string"
        assert props["count"]["type"] == "integer"
        assert props["ratio"]["type"] == "number"
        assert props["active"]["type"] == "boolean"

    def test_function_without_docstring(self):
        def nodoc(x: int) -> int:
            return x

        schema = generate_function_schema(nodoc)

        assert schema["function"]["description"] == ""

    def test_custom_name(self):
        def internal_func(x: int) -> int:
            return x

        schema = generate_function_schema(internal_func, name="public_name")

        assert schema["function"]["name"] == "public_name"


class TestPydanticIntegration:
    """Test Pydantic model schema generation."""

    def test_is_pydantic_model(self):
        class MyModel(BaseModel):
            name: str

        assert is_pydantic_model(MyModel) is True
        assert is_pydantic_model(str) is False
        assert is_pydantic_model(dict) is False

    def test_pydantic_to_json_schema(self):
        class User(BaseModel):
            name: str
            age: int

        schema = pydantic_to_json_schema(User)

        assert "properties" in schema
        assert "name" in schema["properties"]
        assert "age" in schema["properties"]

    def test_pydantic_with_field_descriptions(self):
        class SearchParams(BaseModel):
            query: str = Field(..., description="Search query string")
            limit: int = Field(10, le=100, description="Max results")

        schema = pydantic_to_json_schema(SearchParams)

        assert schema["properties"]["query"]["description"] == "Search query string"
        assert schema["properties"]["limit"]["description"] == "Max results"

    def test_function_with_pydantic_model(self):
        class InputModel(BaseModel):
            text: str
            count: int = 5

        def process(data: InputModel) -> dict:
            """Process input data."""
            return {}

        schema = generate_function_schema(process)

        # Should flatten the model properties
        assert "properties" in schema["function"]["parameters"]


class TestAnthropicSchema:
    """Test Anthropic schema generation."""

    def test_basic_anthropic_schema(self):
        def calculate(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        schema = generate_anthropic_schema(calculate)

        assert schema["name"] == "calculate"
        assert schema["description"] == "Add two numbers."
        assert "input_schema" in schema
        assert "a" in schema["input_schema"]["properties"]
        assert "b" in schema["input_schema"]["properties"]

    def test_anthropic_with_custom_name(self):
        def internal(x: int) -> int:
            return x

        schema = generate_anthropic_schema(internal, name="external")

        assert schema["name"] == "external"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_function_no_params(self):
        def no_params() -> str:
            """Return hello."""
            return "hello"

        schema = generate_function_schema(no_params)

        assert schema["function"]["parameters"]["properties"] == {}
        assert schema["function"]["parameters"]["required"] == []

    def test_function_with_self(self):
        class MyClass:
            def method(self, value: int) -> int:
                """Process value."""
                return value * 2

        obj = MyClass()
        schema = generate_function_schema(obj.method)

        # self should not be in properties
        assert "self" not in schema["function"]["parameters"]["properties"]

    def test_optional_parameter(self):
        def func(name: str, age: Optional[int] = None) -> dict:
            """Get user."""
            return {"name": name, "age": age}

        schema = generate_function_schema(func)

        assert "name" in schema["function"]["parameters"]["required"]
        assert "age" not in schema["function"]["parameters"]["required"]
