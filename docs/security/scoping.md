# Scoping and RBAC

Guardrail API enforces access control at the tenant and bot scope levels. Operators should provision service tokens with the minimal scope required for their automation and monitoring workloads.

## RBAC model

- **Admin tokens** bypass tenant/bot filtering but retain full audit logging.
- **Scoped service tokens** inherit a static allow-list of `(tenant, bot)` pairs that map to an internal role. They may be configured for strict or permissive behavior.
- **UI operators** authenticate via the admin experience and assume the admin scope for investigative tasks.

## Scoped tokens

Scoped tokens created in **strict mode** must provide explicit `tenant` and `bot` query parameters on list and export endpoints. When missing, the API rejects the call with `400`.

When configured for **permissive mode**, scoped tokens may omit filters. The API constrains visibility by applying the token scope before executing the query.

## Autoconstraint flag

Setting `SCOPE_AUTOCONSTRAIN_ENABLED=true` enables automatic scoping for list-style endpoints. The server enforces the token scope at runtime and surfaces the resolved scope in response headers.

- List endpoints auto-constrain to caller scope (single or multi) and set:
  - `X-Guardrail-Scope-Tenant`
  - `X-Guardrail-Scope-Bot`
- Export endpoints require **single** tenant/bot; ambiguous multi-scope → **400**.

The resolved scope values are surfaced for observability. Clients should avoid relying on them for authorization decisions.

## Effective scope headers

Every list request returning paginated results includes the effective scope headers when autoconstraint is enabled. For multi-scope tokens, the header values contain comma-separated tenants and bots in lexical order. Admin tokens omit the headers because they see all data.

## Export behavior

Export endpoints (NDJSON decisions/adjudications) require that scoped tokens resolve to a single `(tenant, bot)` pair. Multi-scope tokens must specify filters that select exactly one scope. Requests that resolve to zero or multiple scopes return `400` with a descriptive error payload.

## Scoped data exports

- **Decisions export** – limited to a single scope, includes autoconstraint metadata when present.
- **Adjudications export** – matches the decision export restrictions and fails closed if the underlying decision scope is missing.

## Auditing considerations

All scoping decisions are written to the audit log, including the effective scope and whether autoconstraint adjusted the query. Use these entries to validate token provisioning during security reviews.
