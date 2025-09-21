# Retention cleanup runbook

Use this checklist before deleting historical decisions and adjudications.

1. **Confirm scope** – capture the tenant/bot filters (or note global) and the cutoff timestamp in
   epoch milliseconds.
2. **Preview counts** – call `POST /admin/api/retention/preview` and record the counts for
   decisions/adjudications. Share with stakeholders for approval.
3. **Coordinate downtime** – ensure dependent reporting/analytics consumers are aware of the purge
   window and that exports/backups are complete.
4. **Execute carefully** – send `POST /admin/api/retention/execute` with `confirm="DELETE"`, the
   CSRF token, and a `max_delete` that stays within the agreed batch size (default 50k).
5. **Verify metrics** – check `guardrail_retention_deleted_total` and `guardrail_retention_preview_total`
   to ensure the operations were recorded.
6. **Audit trail** – confirm the `admin.retention.execute` audit event exists for the request ID and
   archive the event payload alongside the change ticket.
7. **Post-checks** – spot check that recent decisions/adjudications remain accessible and that
   observability alerts are quiet.
