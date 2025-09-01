def export_family_breakdown_lines() -> List[str]:
    """
    Returns Prometheus text lines for:
      - guardrail_decisions_family_tenant_total{tenant, family}
      - guardrail_decisions_family_bot_total{tenant, bot, family}
    """
    lines: List[str] = []

    # tenant level
    t_totals = get_family_tenant_totals()
    if t_totals:
        lines.append(
            "# HELP guardrail_decisions_family_tenant_total "
            "Decisions by family per tenant."
        )
        lines.append("# TYPE guardrail_decisions_family_tenant_total counter")
        for (tenant, fam), v in sorted(t_totals.items()):
            metric = (
                "guardrail_decisions_family_tenant_total"
                f'{{tenant="{tenant}",family="{fam}"}} {v}'
            )
            lines.append(metric)

    # bot level
    b_totals = get_family_bot_totals()
    if b_totals:
        lines.append(
            "# HELP guardrail_decisions_family_bot_total "
            "Decisions by family per bot."
        )
        lines.append("# TYPE guardrail_decisions_family_bot_total counter")
        for (tenant, bot, fam), v in sorted(b_totals.items()):
            metric = (
                "guardrail_decisions_family_bot_total"
                f'{{tenant="{tenant}",bot="{bot}",family="{fam}"}} {v}'
            )
            lines.append(metric)

    return lines
