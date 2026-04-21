import json
import logging
import os
import sys
from typing import Any, Dict, Optional

from openai import OpenAI

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("soc_middleware")


def load_api_client() -> OpenAI:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    return OpenAI(api_key=api_key)


def load_alert_from_file(file_path: str) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_relevant_fields(alert: Dict[str, Any]) -> Dict[str, Any]:
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    location = alert.get("location", "unknown")
    full_log = alert.get("full_log", "unknown")

    return {
        "rule_id": rule.get("id", "unknown"),
        "rule_description": rule.get("description", "unknown"),
        "rule_level": rule.get("level", "unknown"),
        "agent_name": agent.get("name", "unknown"),
        "agent_id": agent.get("id", "unknown"),
        "location": location,
        "srcip": data.get("srcip", data.get("src_ip", "unknown")),
        "dstip": data.get("dstip", data.get("dst_ip", "unknown")),
        "username": data.get("username", data.get("user", "unknown")),
        "event_count": data.get("count", "unknown"),
        "summary_log": truncate_text(full_log, 500),
    }


def truncate_text(value: Any, max_length: int) -> str:
    if value is None:
        return "unknown"
    text = str(value)
    if len(text) <= max_length:
        return text
    return text[:max_length] + "...[truncated]"


def sanitize_for_external_use(fields: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = dict(fields)

    if sanitized.get("srcip") not in [None, "unknown"]:
        sanitized["srcip"] = "[redacted-ip]"
    if sanitized.get("dstip") not in [None, "unknown"]:
        sanitized["dstip"] = "[redacted-ip]"
    if sanitized.get("username") not in [None, "unknown"]:
        sanitized["username"] = "[redacted-user]"
    if sanitized.get("agent_name") not in [None, "unknown"]:
        sanitized["agent_name"] = "[redacted-agent]"
    if sanitized.get("location") not in [None, "unknown"]:
        sanitized["location"] = "[redacted-location]"

    return sanitized


def build_prompt(alert_summary: Dict[str, Any]) -> str:
    return f"""
You are assisting with SOC alert triage.

Review this sanitized alert summary:
{json.dumps(alert_summary, indent=2)}

Return your result in JSON with these keys:
- classification: benign, suspicious, or malicious
- severity: low, medium, or high
- rationale: brief explanation
- recommended_action: ignore, monitor, or escalate
""".strip()


def query_ai_triage(client: OpenAI, prompt: str, model: str = "gpt-4.1-mini") -> str:
    response = client.responses.create(
        model=model,
        input=prompt
    )
    return response.output_text.strip()


def safe_parse_ai_json(ai_text: str) -> Dict[str, Any]:
    try:
        return json.loads(ai_text)
    except json.JSONDecodeError:
        logger.warning("AI output was not valid JSON. Returning raw response.")
        return {
            "classification": "unknown",
            "severity": "unknown",
            "rationale": ai_text,
            "recommended_action": "review"
        }


def determine_action(ai_result: Dict[str, Any]) -> str:
    severity = str(ai_result.get("severity", "unknown")).lower()
    classification = str(ai_result.get("classification", "unknown")).lower()

    if severity == "high" or classification == "malicious":
        return "escalate"
    if severity == "medium" or classification == "suspicious":
        return "monitor"
    if severity == "low" or classification == "benign":
        return "low_priority"
    return "review"


def process_alert(raw_alert: Dict[str, Any]) -> Dict[str, Any]:
    extracted = extract_relevant_fields(raw_alert)
    sanitized = sanitize_for_external_use(extracted)
    prompt = build_prompt(sanitized)

    client = load_api_client()
    ai_text = query_ai_triage(client, prompt)
    ai_result = safe_parse_ai_json(ai_text)
    action = determine_action(ai_result)

    return {
        "sanitized_alert": sanitized,
        "ai_result": ai_result,
        "action": action
    }


def print_result(result: Dict[str, Any]) -> None:
    print(json.dumps(result, indent=2))


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python custom_discord.py <alert_file.json>")
        sys.exit(1)

    alert_file = sys.argv[1]

    try:
        raw_alert = load_alert_from_file(alert_file)
        result = process_alert(raw_alert)
        print_result(result)

    except FileNotFoundError:
        logger.exception("Alert file not found: %s", alert_file)
        sys.exit(1)
    except Exception as exc:
        logger.exception("Middleware execution failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
