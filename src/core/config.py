"""
Lab 11 — Configuration & API Key Setup
"""
import os


LEGACY_MODEL_ALIASES = {
    "openai/gpt-4o-mini": "openai/gpt-4.1-mini",
    "gpt-4o-mini": "gpt-4.1-mini",
}


def _normalize_model_name(model_name: str) -> str:
    """Map deprecated model aliases to currently available model ids."""
    return LEGACY_MODEL_ALIASES.get(model_name, model_name)


DEFAULT_LLM_MODEL = _normalize_model_name(os.getenv("ADK_MODEL", "openai/gpt-4.1-mini"))
DEFAULT_JUDGE_MODEL = _normalize_model_name(os.getenv("JUDGE_MODEL", DEFAULT_LLM_MODEL))
DEFAULT_REDTEAM_MODEL = _normalize_model_name(os.getenv("REDTEAM_MODEL", DEFAULT_LLM_MODEL))


def _strip_provider_prefix(model_name: str) -> str:
    """Convert provider/model to model for systems that require bare model id."""
    if "/" in model_name:
        return model_name.split("/", 1)[1]
    return model_name


def get_llm_model() -> str:
    """Get the primary ADK model string."""
    return DEFAULT_LLM_MODEL


def get_judge_model() -> str:
    """Get model string for LLM-as-judge."""
    return DEFAULT_JUDGE_MODEL


def get_redteam_model() -> str:
    """Get model string for automated red teaming."""
    return DEFAULT_REDTEAM_MODEL


def get_nemo_model_config() -> tuple[str, str]:
    """Get NeMo engine/model pair.

    Defaults are aligned with the main model provider.
    """
    default_engine = "openai" if get_llm_model().startswith("openai/") else "google_genai"
    engine = os.getenv("NEMO_ENGINE", default_engine)
    model = os.getenv("NEMO_MODEL", _strip_provider_prefix(get_llm_model()))
    return engine, model


def setup_api_key():
    """Load API key for the configured provider from environment or prompt."""
    model_name = get_llm_model()
    use_openai = model_name.startswith("openai/")

    if use_openai:
        if "OPENAI_API_KEY" not in os.environ:
            os.environ["OPENAI_API_KEY"] = input("Enter OpenAI API Key: ").strip()
        print(f"API key loaded for model: {model_name}")
        return

    if "GOOGLE_API_KEY" not in os.environ:
        os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ").strip()
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print(f"API key loaded for model: {model_name}")


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
