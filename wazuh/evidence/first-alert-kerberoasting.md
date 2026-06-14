# 🔔 Evidencia — Primera alerta real en Wazuh: Kerberoasting (honeypot `svc_sql`)

**Fecha:** 2026-06-14 · **Lab:** `corp.local` · **SIEM:** Wazuh 4.13.1 (manager `10.10.10.20`, aislado en LAB-Net)

## Ciclo end-to-end demostrado

1. **Ataque** — en `DC01` como `CORP\Administrator`, solicitud de TGS para el SPN señuelo de `svc_sql`
   (truco sin herramientas, igual que en el [Proyecto 3](../../projects/03-detection-engineering/)):
   ```powershell
   Add-Type -AssemblyName System.IdentityModel
   New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken `
       -ArgumentList 'MSSQLSvc/sql01.corp.local:1433'
   ```
2. **Telemetría** — Windows Security **Event 4769** (*A Kerberos service ticket was requested*) en DC01.
3. **Pipeline** — agente Wazuh en DC01 (ID 001) → manager → decoder `windows_eventchannel` → regla custom **100110**.
4. **Detección** — alerta **nivel 12**, MITRE **T1558.003** (Credential Access / Kerberoasting).

## Alerta generada (`/var/ossec/logs/alerts/alerts.json`)

| Campo | Valor |
|---|---|
| `rule.id` | **100110** |
| `rule.description` | Kerberoasting (honeypot): TGS solicitado para la cuenta senuelo svc_sql |
| `rule.level` | 12 |
| `rule.mitre.id` | T1558.003 |
| `rule.groups` | local, soc_lab, attack, kerberoasting, credential_access, honeypot |
| `agent` | DC01 (10.10.10.10) |
| `data.win.system.eventID` | 4769 |
| `data.win.eventdata.serviceName` | **svc_sql** |
| `data.win.eventdata.ticketEncryptionType` | **0x12 (AES256)** |
| `decoder.name` | windows_eventchannel |

## Hallazgo clave (confirma el Proyecto 3)

El cifrado del ticket es **`0x12` (AES256), NO RC4 (`0x17`)** — Windows Server 2025 emite AES por defecto.
Por eso la detección fuerte es el **honeypot** (cualquier 4769 hacia `svc_sql` = malicioso, **enc-agnóstico**),
no la firma clásica de RC4. La regla `100111` (RC4) queda como respaldo para entornos con cifrado débil.

## Qué demuestra

SIEM self-hosted (Wazuh) **operativo de punta a punta**: ingesta real de Windows Security vía agente,
**detección como código** (regla Wazuh con MITRE), validada **atacando el lab** — y todo en una red **aislada**,
sin coste y sin nube.
