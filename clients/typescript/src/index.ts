export type Scope = string | string[] | undefined;

export interface CursorPage<T> {
  items?: T[];
  limit?: number;
  dir?: string;
  next_cursor?: string | null;
  prev_cursor?: string | null;
  [key: string]: unknown;
}

export interface DecisionItem {
  id?: string;
  ts?: string;
  tenant?: string;
  bot?: string;
  outcome?: string;
  [key: string]: unknown;
}

export interface AdjudicationItem {
  id?: string;
  ts?: string;
  tenant?: string;
  bot?: string;
  outcome?: string;
  rule_id?: string;
  request_id?: string;
  [key: string]: unknown;
}

export interface GuardrailListOptions {
  tenant?: Scope;
  bot?: Scope;
  limit?: number;
  cursor?: string;
  dir?: "fwd" | "rev" | "next" | "prev";
  [key: string]: unknown;
}

export class GuardrailClient {
  constructor(
    private baseUrl: string,
    private token?: string,
    private timeoutMs = 10000
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  private async get(path: string, params: Record<string, unknown> = {}) {
    const url = new URL(this.baseUrl + path);
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        value.forEach((entry) => url.searchParams.append(key, String(entry)));
      } else {
        url.searchParams.set(key, String(value));
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(url.toString(), {
        method: "GET",
        headers: this.token ? { Authorization: `Bearer ${this.token}` } : undefined,
        signal: controller.signal
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response;
    } finally {
      clearTimeout(timer);
    }
  }

  async healthz(): Promise<Record<string, unknown>> {
    return (await this.get("/healthz")).json();
  }

  async readyz(): Promise<Record<string, unknown>> {
    return (await this.get("/readyz")).json();
  }

  async listDecisions(options: GuardrailListOptions = {}): Promise<CursorPage<DecisionItem>> {
    const { tenant, bot, limit = 50, cursor, dir = "fwd", ...rest } = options;
    return (
      await this.get("/admin/api/decisions", { tenant, bot, limit, cursor, dir, ...rest })
    ).json();
  }

  async listAdjudications(options: GuardrailListOptions = {}): Promise<CursorPage<AdjudicationItem>> {
    const { tenant, bot, limit = 50, cursor, dir = "fwd", ...rest } = options;
    return (
      await this.get("/admin/api/adjudications", { tenant, bot, limit, cursor, dir, ...rest })
    ).json();
  }

  async exportDecisions(options: { tenant?: string; bot?: string } = {}): Promise<string> {
    // Server expects /admin/api/decisions/export with ?format=jsonl
    const response = await this.get("/admin/api/decisions/export", { ...options, format: "jsonl" });
    return response.text();
  }

  async exportAdjudications(options: { tenant?: string; bot?: string } = {}): Promise<string> {
    // Server exposes NDJSON at /admin/api/adjudications/export.ndjson
    const response = await this.get("/admin/api/adjudications/export.ndjson", options);
    return response.text();
  }
}
