from typing import Any, Type


def structured_invoke(model: Any, schema: Type, messages: list, provider: str | None = None):
    """Invoke a model with structured output in a provider-tolerant way.

    - Tries function/tool-calling first (works well for OpenAI/Gemini/Anthropic in LC).
    - Falls back to default method if provider-specific path errors.
    - Raises original error if both attempts fail.
    """
    method_pref = None
    if provider:
        pv = str(provider).lower()
        # Prefer tool/function-calling pathway across major providers
        if pv in ("openai", "anthropic", "gemini"):
            method_pref = "function_calling"
    try:
        if method_pref:
            chain = model.with_structured_output(schema, method=method_pref)
        else:
            chain = model.with_structured_output(schema)
        return chain.invoke(messages)
    except Exception:
        # Fallback attempt without method hint (or with generic)
        try:
            chain = model.with_structured_output(schema)
            return chain.invoke(messages)
        except Exception as e:
            raise e

