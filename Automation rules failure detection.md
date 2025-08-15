SentinelHealth
| where Status == "Failure"
| where OperationName == "Automation rule run"
| extend
    AutomationRuleName = SentinelResourceName,
    TriggeringIncidentTitle = tostring(parse_json(ExtendedProperties).IncidentTitle),
    TriggeringIncidentNumber = tostring(parse_json(ExtendedProperties).IncidentNumber),
    AutomationRuleId = tostring(parse_json(ExtendedProperties).RuleId),
    ExecutionStatus = tostring(Status),
    FailureReason = tostring(parse_json(ExtendedProperties).FailureReason),
    ResultDescription = tostring(parse_json(ExtendedProperties).ResultDescription),
    OperationName = tostring(OperationName)
| project
    TimeGenerated,
    AutomationRuleName,
    TriggeringIncidentTitle,
    TriggeringIncidentNumber,
    AutomationRuleId,
    ExecutionStatus,
    FailureReason,
    ResultDescription,
    OperationName,
    WorkspaceId,
    TenantId
