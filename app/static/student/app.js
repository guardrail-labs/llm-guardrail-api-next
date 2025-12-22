const promptInput = document.getElementById("prompt");
const sendButton = document.getElementById("send");
const decisionEl = document.getElementById("decision");
const statusEl = document.getElementById("status");
const headersEl = document.getElementById("headers");
const jsonEl = document.getElementById("json");
const presetButtons = document.querySelectorAll(".preset");

const DECISION_HEADERS = [
  "x-guardrail-decision",
  "x-guardrail-mode",
  "x-guardrail-incident-id",
  "x-guardrail-rule-ids",
  "x-guardrail-policy-version",
  "x-request-id",
];

const setDecisionBadge = (decision) => {
  const normalized = (decision || "").toLowerCase();
  decisionEl.textContent = decision || "–";
  decisionEl.dataset.decision = normalized || "unknown";
};

const setStatus = (status) => {
  statusEl.textContent = status || "–";
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
  const response = await fetch("/guardrail/evaluate", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ text: prompt }),
  });

  let data = null;
  let rawText = "";
  try {
    data = await response.json();
  } catch (error) {
    rawText = await response.text();
  }

  const decision =
    (data && (data.decision || data.action)) ||
    response.headers.get("x-guardrail-decision") ||
    "";
  setDecisionBadge(decision);
  setStatus(`${response.status} ${response.statusText}`.trim());
  headersEl.textContent = formatHeaders(response.headers);

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
  jsonEl.textContent = "";
  try {
    await requestEvaluation(prompt);
  } catch (error) {
    setStatus("Request failed");
    setDecisionBadge("error");
    headersEl.textContent = "";
    jsonEl.textContent = error ? String(error) : "Unknown error";
  } finally {
    setLoading(false);
  }
});

presetButtons.forEach((button) => {
  button.addEventListener("click", () => {
    promptInput.value = button.dataset.value || "";
    promptInput.focus();
  });
});
