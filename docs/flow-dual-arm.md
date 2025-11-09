# Clarify-First Dual-Arm Flow

The clarify-first runtime splits enforcement into two isolated "arms" so degradation in one stage
never compromises safety:

```mermaid
sequenceDiagram
    participant Client
    participant Ingress
    participant Model
    participant Egress

    Client->>Ingress: Request (text/image/audio)
    Ingress->>Ingress: Sanitize + detect confusables
    Ingress->>Ingress: Evaluate policies
    alt Clarify or Block
        Ingress-->>Client: 4xx with decision headers
    else Allow
        Ingress->>Model: Forward sanitized payload
        Model-->>Ingress: Output
        Ingress->>Egress: Pass context + output
        alt Egress Clarify/Block
            Egress-->>Client: Safe response (execute_locked)
        else Allow
            Egress-->>Client: Response + headers
        end
    end
```

- **Ingress arm** applies Unicode normalization, confusable detection, and policy evaluation before
  the model executes. Failures return `block_input_only` decisions with incident IDs.
- **Egress arm** verifies the model output independently. Failures trigger `execute_locked`
  responses that withhold or transform the payload.
- **Headers**: every response carries `X-Guardrail-Decision-*`, `X-Guardrail-Mode-*`, and
  `X-Guardrail-Incident-ID` so downstream systems can observe guardrail posture.
