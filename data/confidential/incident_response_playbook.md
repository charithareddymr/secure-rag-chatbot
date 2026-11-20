# Northwind Labs: Incident Response Playbook (CONFIDENTIAL)

> Fictional sample data created for this demo project. Northwind Labs is not a real company.

## Severity levels

SEV-1: Confirmed breach of customer data or production outage caused by an attack. Page the on-call security lead immediately and open a bridge call within 15 minutes.

SEV-2: Active exploitation attempt or compromised internal account with no confirmed data loss. Respond within 1 hour.

SEV-3: Suspicious activity or a vulnerability report needing triage. Respond within 1 business day.

## First steps for a SEV-1

Contain first: disable the affected accounts and revoke their sessions and API tokens. Isolate affected hosts from the network but do not power them off, so memory evidence is preserved.

Preserve evidence: snapshot affected cloud instances and export CloudTrail and application logs for the incident window to the forensics bucket.

Communicate: the incident commander posts updates every 30 minutes in the private incident channel. Only the legal team contacts customers or regulators.

## Internal contacts

Security on-call rotation: see the internal paging tool, service "sec-oncall".
Forensics evidence bucket: `nwl-forensics-evidence` (write-only for responders).
