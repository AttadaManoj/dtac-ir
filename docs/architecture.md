# DTAC-IR Architecture & Threat Model

## Threat Model

### Assets Being Protected
- Network infrastructure (switches, routers, servers)
- End-user devices (workstations, IoT)
- Sensitive data flows (auth traffic, internal APIs)

### Threat Actors
| Actor | Capability | Intent |
|-------|-----------|--------|
| External attacker | Moderate | Data exfiltration, ransomware |
| Insider threat | High (network access) | Data theft, sabotage |
| Compromised device | Low | Lateral movement, C2 comms |

### Attack Scenarios Detected
1. **Reconnaissance** — Port scanning before targeted attack
2. **DoS/DDoS** — SYN flood exhausting connection tables
3. **Data Exfiltration** — DNS tunnelling to bypass egress filters
4. **Credential Attack** — Brute force against SSH/RDP
5. **MITM** — ARP spoofing to intercept traffic

### Out of Scope (v1.0)
- Encrypted traffic analysis (TLS inspection requires separate setup)
- Zero-day exploit detection (ML handles unknown patterns partially)
- Physical security

## Data Flow

```
Network Interface
     │
     ▼
[Scapy Capture] ──── raw packets ────▶ [Feature Extractor]
                                              │
                                    packet feature vector
                                              │
                              ┌───────────────┼───────────────┐
                              ▼               ▼               ▼
                       [Rule Engine]    [ML Classifier]  [Flow Stats]
                              │               │
                        rule_triggered   predicted_class
                              │               │
                              └───────┬───────┘
                                      ▼
                              [Alert Generator]
                                      │
                          ┌───────────┼────────────┐
                          ▼           ▼             ▼
                   [Trust Engine] [DB Writer] [WebSocket Broadcast]
                          │
                   trust score update
                          │
                   [Response Engine]
                   (block / quarantine / alert)
```

## API Design Decisions

### Why async SQLAlchemy?
Packet capture generates bursts of DB writes. Async prevents the capture thread from blocking on slow DB inserts.

### Why Redis?
Alert fan-out to multiple WebSocket clients and future distributed deployment. Also used for rate-limiting API endpoints.

### Why WebSocket over polling?
Security dashboards need < 1s latency on critical alerts. Polling at 1-second intervals generates 60 HTTP requests/minute per dashboard tab under normal conditions.

## Security Considerations

1. **DTAC-IR itself is a high-value target** — it sees all traffic. Secure the API with auth tokens.
2. **Packet capture requires root** — run the capture component as a separate minimal process, not the full API.
3. **Auto-blocking is off by default** — false positives can cause outages. Require analyst approval in production.
4. **ML model can be poisoned** — if you retrain on live traffic, validate data integrity first.
