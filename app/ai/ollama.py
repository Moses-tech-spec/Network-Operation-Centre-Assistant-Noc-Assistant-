import requests

OLLAMA_URL = "http://172.20.0.1:11434/api/generate"
MODEL = "qwen2.5:1.5b"


def _call_ollama(prompt: str, timeout: int):
    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_ctx": 4096,
            },
            "keep_alive": "30m",
        },
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()["response"]


def ask_llm(prompt: str):
    """
    Calls the local LLM with resilience: retries once on timeout,
    and if that also fails, returns a clear degraded-mode message
    instead of raising and crashing the whole request.
    """

    try:
        return _call_ollama(prompt, timeout=150)

    except requests.exceptions.ReadTimeout:
        try:
            return _call_ollama(prompt, timeout=150)
        except Exception:
            return (
                "The AI reasoning engine (Ollama) timed out twice while "
                "processing this request. The underlying data was retrieved "
                "successfully, but no natural-language summary could be "
                "generated. Please try again, or check Ollama's health/load "
                "on the server."
            )

    except requests.exceptions.ConnectionError:
        return (
            "Could not reach the AI reasoning engine (Ollama) — it may be "
            "down or unreachable. The underlying network data was retrieved "
            "successfully, but no natural-language summary could be generated."
        )

    except Exception as e:
        return f"An unexpected error occurred while generating the AI response: {str(e)}"
