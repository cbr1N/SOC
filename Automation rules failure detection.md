# Automation Rule Failures in Microsoft Sentinel

## Overview

This query identifies failed executions of Automation Rules in Microsoft Sentinel.

---

## The Query

```kusto
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
| project-reorder
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
```
---

## What the Query Does

1. Filters for events in SentinelHealth where:
   - Status == "Failure" → only failed runs  
   - OperationName == "Automation rule run" → only automation rule executions  

2. Extracts useful context:
   - AutomationRuleName → the name of the failing automation rule  
   - TriggeringIncidentTitle / TriggeringIncidentNumber → the incident that triggered the automation rule  
   - AutomationRuleId → the internal ID for tracking  
   - FailureReason / ResultDescription → details on why the run failed  

3. Projects key fields into a clean output table for investigation  
 
