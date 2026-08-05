import os


def ai_review(code_snippet: str, filename: str) -> str:
    """
    Optional AI-assisted security review.

    This function is safe to call even if the OpenAI SDK is not installed
    or no API key is configured. In those cases it returns a helpful
    explanatory message instead of raising an error.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return (
            "AI analysis disabled: set the OPENAI_API_KEY environment variable "
            "to enable AI-powered security review."
        )

    try:
        from openai import OpenAI  # type: ignore
    except ImportError:
        return (
            "AI analysis unavailable: the 'openai' package is not installed. "
            "Install it with 'pip install openai' to enable AI review."
        )

    client = OpenAI(api_key=api_key)

    prompt = f"""
You are a security expert.

Analyze the following code snippet from {filename}.

Explain:
1. whether it is actually vulnerable
2. what the real risk is
3. how to fix it safely

Code:
{code_snippet}
"""

    try:
        response = client.responses.create(
            model="gpt-5.3-codex",
            input=prompt,
        )

        try:
            return response.output_text  # type: ignore[attr-defined]
        except Exception:
            return str(response)

    except Exception as e:
        return f"AI analysis unavailable: {e}"
