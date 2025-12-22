const promptInput = document.getElementById("prompt");
const sendButton = document.getElementById("send");
const decisionEl = document.getElementById("decision");
const statusEl = document.getElementById("status");
const headersEl = document.getElementById("headers");
const assistantEl = document.getElementById("assistant");
const jsonEl = document.getElementById("json");
const presetButtons = document.querySelectorAll(".preset");

const DECISION_HEADERS = [
  "x-guardrail-decision",
  "x-guardrail-mode",
  "x-guardrail-incident-id",
  "x-guardrail-policy-version",
  "x-request-id",
  "x-guardrail-reason-hints",
  "x-guardrail-ingress-action",
  "x-guardrail-egress-action",
  "x-guardrail-ingress-redactions",
  "x-guardrail-rule-ids",
];

const setDecisionBadge = (decision) => {
  const normalized = (decision || "").toLowerCase();
  decisionEl.textContent = decision || "–";
  decisionEl.dataset.decision = normalized || "unknown";
};

const setStatus = (status) => {
  statusEl.textContent = status || "–";
};

const setAssistantMessage = (message) => {
  assistantEl.textContent = message || "(none)";
};

const formatHeaders = (headers) => {
  const lines = [];
  const seen = new Set();
  DECISION_HEADERS.forEach((key) => {
    if (headers.has(key)) {
      lines.push(`${key}: ${headers.get(key)}`);
      seen.add(key);
    }
  });
  Array.from(headers.keys())
    .filter((key) => key.startsWith("x-guardrail-") && !seen.has(key))
    .forEach((key) => {
      lines.push(`${key}: ${headers.get(key)}`);
    });
  if (!lines.length) {
    return "(no decision headers on response)";
  }
  return lines.join("\n");
};

const requestEvaluation = async (prompt) => {
  const response = await fetch("/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "guardrail-demo",
      messages: [{ role: "user", content: prompt }],
      metadata: {
        user_id: "student-ui",
        project: "student",
        scenario: "ui",
      },
    }),
  });

  let data = null;
  let rawText = "";
  try {
    data = await response.json();
  } catch (error) {
    rawText = await response.text();
  }

  const decisionHeader = response.headers.get("x-guardrail-decision") || "";
  const decision =
    decisionHeader || (data && (data.decision || data.action)) || "";
  setDecisionBadge(decision);
  setStatus(`${response.status} ${response.statusText}`.trim());
  headersEl.textContent = formatHeaders(response.headers);
  setAssistantMessage(data?.choices?.[0]?.message?.content || "");

  if (data) {
    jsonEl.textContent = JSON.stringify(data, null, 2);
  } else if (rawText) {
    jsonEl.textContent = rawText;
  } else {
    jsonEl.textContent = "(no JSON body returned)";
  }
};

const requestHealthCheck = async () => {
  const response = await fetch("/health");
  let data = null;
  let rawText = "";
  try {
    data = await response.json();
  } catch (error) {
    rawText = await response.text();
  }

  setDecisionBadge("");
  setStatus(`${response.status} ${response.statusText}`.trim());
  headersEl.textContent = formatHeaders(response.headers);
  setAssistantMessage("");

  if (data) {
    jsonEl.textContent = JSON.stringify(data, null, 2);
  } else if (rawText) {
    jsonEl.textContent = rawText;
  } else {
    jsonEl.textContent = "(no JSON body returned)";
  }
};

const setLoading = (isLoading) => {
  sendButton.disabled = isLoading;
  sendButton.textContent = isLoading ? "Sending..." : "Send";
};

sendButton.addEventListener("click", async () => {
  const prompt = (promptInput.value || "").trim();
  if (!prompt) {
    promptInput.focus();
    return;
  }
  setLoading(true);
  setDecisionBadge("");
  setStatus("Pending...");
  headersEl.textContent = "";
  assistantEl.textContent = "";
  jsonEl.textContent = "";
  try {
    await requestEvaluation(prompt);
  } catch (error) {
    setStatus("Request failed");
    setDecisionBadge("error");
    headersEl.textContent = "";
    setAssistantMessage("");
    jsonEl.textContent = error ? String(error) : "Unknown error";
  } finally {
    setLoading(false);
  }
});

presetButtons.forEach((button) => {
  button.addEventListener("click", async () => {
    if (button.dataset.action === "health") {
      setLoading(true);
      setDecisionBadge("");
      setStatus("Pending...");
      headersEl.textContent = "";
      assistantEl.textContent = "";
      jsonEl.textContent = "";
      try {
        await requestHealthCheck();
      } catch (error) {
        setStatus("Request failed");
        setDecisionBadge("error");
        headersEl.textContent = "";
        setAssistantMessage("");
        jsonEl.textContent = error ? String(error) : "Unknown error";
      } finally {
        setLoading(false);
      }
      return;
    }

    promptInput.value = button.dataset.value || "";
    promptInput.focus();
  });
});
