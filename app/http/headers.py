from starlette.responses import Response

POLICY_VERSION_HEADER = "X-Guardrail-Policy-Version"

def attach_guardrail_headers(response: Response, *, policy_version: str | None) -> None:
    if policy_version:
        response.headers.setdefault(POLICY_VERSION_HEADER, policy_version)
