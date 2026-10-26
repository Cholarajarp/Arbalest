"""Regression tests for the bundle validation failure seen in live Ultra testing."""

import json
from unittest.mock import AsyncMock

import pytest

from engine.agents.polyglot_translator import CodeGenerationError, PolyglotTranslator


def bundle(entrypoint="executors.py"):
    return {
        "language": "python",
        "entrypoint": entrypoint,
        "files": [{"path": "executors.py", "content": "def run_shell(args):\n    return 0\n"}],
        "build_instructions": ["python -m compileall executors.py"],
        "test_instructions": ["python executors.py"],
    }


@pytest.mark.asyncio
async def test_missing_entrypoint_repair_receives_the_actual_validation_error():
    provider = AsyncMock()
    provider.generate_structured.return_value = json.dumps(bundle())
    translator = PolyglotTranslator(provider=provider)
    result = await translator._parse_response(json.dumps(bundle("routes.py")))
    assert result.entrypoint == "executors.py"
    request = provider.generate_structured.call_args.args[0]
    assert "entrypoint must reference a generated file" in request.instructions
    assert json.loads(request.input_text)["entrypoint"] == "routes.py"
    provider.generate_structured.assert_awaited_once()


@pytest.mark.asyncio
async def test_valid_bundle_needs_no_repair():
    provider = AsyncMock()
    result = await PolyglotTranslator(provider=provider)._parse_response(json.dumps(bundle()))
    assert result.entrypoint == "executors.py"
    provider.generate_structured.assert_not_awaited()


@pytest.mark.asyncio
async def test_fenced_valid_bundle_is_accepted():
    provider = AsyncMock()
    text = "```json\n" + json.dumps(bundle()) + "\n```"
    result = await PolyglotTranslator(provider=provider)._parse_response(text)
    assert result.entrypoint == "executors.py"
    provider.generate_structured.assert_not_awaited()


@pytest.mark.asyncio
async def test_invalid_repair_is_rejected_not_silently_fixed():
    provider = AsyncMock()
    provider.generate_structured.return_value = json.dumps(bundle("still-missing.py"))
    with pytest.raises(CodeGenerationError):
        await PolyglotTranslator(provider=provider)._parse_response(json.dumps(bundle("routes.py")))
    provider.generate_structured.assert_awaited_once()


def test_python_hash_comment_braces_are_not_delimiter_errors():
    """`#` comments and docstrings containing braces are valid Python."""
    from engine.agents.polyglot_translator import (
        CodeLanguage, GeneratedCodeBundle, GeneratedFile, validate_generated_bundle,
    )

    content = 'def f():\n    """Returns {"ok": ..."""\n    # payload: {"x": 1\n    return {"ok": 1}\n'
    bundle = GeneratedCodeBundle(
        language=CodeLanguage.PYTHON, entrypoint="app.py",
        files=[GeneratedFile(path="app.py", content="x = 1\n"), GeneratedFile(path="test_app.py", content=content)],
        build_instructions=["none"], test_instructions=["none"],
    )
    validate_generated_bundle(bundle, CodeLanguage.PYTHON)


def test_python_syntax_errors_are_still_rejected():
    import pytest

    from engine.agents.polyglot_translator import (
        CodeGenerationError, CodeLanguage, GeneratedCodeBundle, GeneratedFile, validate_generated_bundle,
    )

    bundle = GeneratedCodeBundle(
        language=CodeLanguage.PYTHON, entrypoint="app.py",
        files=[GeneratedFile(path="app.py", content='x = {"a": 1\n')],
        build_instructions=["none"], test_instructions=["none"],
    )
    with pytest.raises(CodeGenerationError, match="SyntaxError"):
        validate_generated_bundle(bundle, CodeLanguage.PYTHON)
