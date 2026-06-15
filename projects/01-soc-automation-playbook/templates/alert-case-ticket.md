# Plantilla — Ticket/Caso de alerta SOC

Plantilla operativa para abrir, triar y documentar un caso a partir de una alerta de Wazuh en el lab `corp.local`. Rellenar todos los campos. Las alertas de nivel >=12 abren caso automaticamente vía Wazuh Active Response (lado-manager, solo-lectura); las de nivel 10 se abren manualmente.

---

## 1. Formulario en blanco (copiar y rellenar)

```
====================================================================
CASO SOC — corp.local
====================================================================
ID de caso .............. : CASE-<AAAAMMDD>-<NNN>
Fecha/hora apertura (UTC) : 
Fecha/hora del evento (UTC): 
Analista ................ : 
--------------------------------------------------------------------
DETECCION
Regla Wazuh (ID) ........ : <100110|100111|100120|100130|100140|100150|100151|100152|100160|100161|100170>
Nivel Wazuh ............. : <10 | 12>
Nombre de la regla ...... : 
Tecnica ATT&CK .......... : <T1558.003 | T1558.004 | T1059.001 | T1027 | T1562.001 | T1105 | T1543.003>
Canal / EventID ......... : <Security 4769 | 4768 | 4688 | PowerShell 4104 | Defender 1116/1117 | System 7045>
--------------------------------------------------------------------
ALCANCE
Host afectado ........... : <DC01 10.10.10.10 | WIN11 10.10.10.21>
Cuenta / usuario ........ : <CORP\...>
Cuenta origen / IP ...... : 
Proceso / linaje ........ : 
--------------------------------------------------------------------
RESUMEN
<2-4 lineas: que disparo, donde, cuando, por que importa>
--------------------------------------------------------------------
EVIDENCIA / IoCs
- Alerta(s) (id, timestamp, full_log):
- IoC host (proceso, ruta, SHA256):
- IoC red (IP/dominio/URL):
- Cuenta/SPN/ticket:
--------------------------------------------------------------------
ENRIQUECIMIENTO
LOCAL (lab):
  - AD (Get-ADUser / grupos):
  - Linaje proceso (Sysmon EID 1, parentImage + SHA256):
  - Historico 4688 (alerts.json regla base 67027):
  - Endpoint (Get-MpThreat / Get-MpComputerStatus):
  - Baseline known-good (admin / PS-remoting / Sysmon): [ ] coincide  [ ] no coincide
EXTERNO (conceptual — lab aislado, plantilla IoC lookup):
  - SHA256 -> VirusTotal:
  - IP/dominio -> AbuseIPDB / OTX:
--------------------------------------------------------------------
VEREDICTO ............... : [ ] TP  [ ] FP  [ ] Benigno-esperado  [ ] Indeterminado
Justificacion ........... : 
--------------------------------------------------------------------
ACCIONES TOMADAS
[ ] AR abrio caso automatico (nivel>=12)
[ ] Enriquecimiento local ejecutado
[ ] Endpoint revisado (Get-MpThreat)
[ ] Contencion inicial (aislar / deshabilitar cuenta)
[ ] Otra: 
--------------------------------------------------------------------
ESTADO .................. : [ ] Nuevo [ ] En triage [ ] En contencion [ ] Cerrado-TP [ ] Cerrado-FP
ESCALADO ................ : [ ] No  [ ] Si -> IR (PICERL, Proyecto 4)
Notas de handoff a IR ... : 
====================================================================
```

---

## 2. Ejemplo relleno — Caso real del lab (Kerberoasting honeypot 100110)

```
====================================================================
CASO SOC — corp.local
====================================================================
ID de caso .............. : CASE-20260614-001
Fecha/hora apertura (UTC) : 2026-06-14 (apertura automatica vía AR, nivel 12)
Fecha/hora del evento (UTC): 2026-06-14
Analista ................ : SOC L1 (triage) / SOC lead (validacion)
--------------------------------------------------------------------
DETECCION
Regla Wazuh (ID) ........ : 100110
Nivel Wazuh ............. : 12
Nombre de la regla ...... : Kerberoasting HONEYPOT (TGS hacia cuenta senuelo svc_sql)
Tecnica ATT&CK .......... : T1558.003 (Kerberoasting)
Canal / EventID ......... : Security 4769 (Kerberos Service Ticket Operations)
--------------------------------------------------------------------
ALCANCE
Host afectado ........... : DC01 10.10.10.10 (KDC/AD DS/DNS — emisor del 4769)
Cuenta / usuario ........ : Cuenta senuelo CORP\svc_sql (SPN MSSQLSvc/sql01.corp.local:1433)
Cuenta origen / IP ...... : (ver win.eventdata.targetUserName solicitante y win.eventdata.ipAddress)
Proceso / linaje ........ : N/A en el 4769; pivotar a 4688/Sysmon en el host origen
--------------------------------------------------------------------
RESUMEN
Se solicito un TGS (4769) para el SPN de la cuenta senuelo svc_sql. svc_sql es un
HONEYPOT sin uso legitimo: cualquier solicitud de ticket de servicio contra ella es
maliciosa por definicion (deteccion determinista). Indica reconocimiento/extraccion
de credenciales de servicio (Kerberoasting) desde un principal del dominio.
--------------------------------------------------------------------
EVIDENCIA / IoCs
- Alerta: rule.id 100110, nivel 12, Security 4769, full_log con el SPN MSSQLSvc/sql01.corp.local:1433.
- Cuenta/SPN: svc_sql / MSSQLSvc/sql01.corp.local:1433; msDS-SupportedEncryptionTypes=23 (RC4 habilitado), pw debil 'Summer2024!'.
- IoC host: pendiente — cuenta solicitante (targetUserName) e IP (ipAddress) del 4769 = punto de pivote.
- Nota: NO depender de la firma RC4 0x17 (WS2025 negocia AES 0x12); el honeypot es la deteccion robusta.
--------------------------------------------------------------------
ENRIQUECIMIENTO
LOCAL (lab):
  - Alerta cruda:
      jq -c 'select(.rule.id=="100110")' /var/ossec/logs/alerts/alerts.json
  - Solicitante + IP + tipo de cifrado del TGS:
      jq -c 'select(.rule.id=="100110") | {ts:.timestamp, sol:.data.win.eventdata.targetUserName, ip:.data.win.eventdata.ipAddress, enc:.data.win.eventdata.ticketEncryptionType}' /var/ossec/logs/alerts/alerts.json
  - AD — confirmar que svc_sql es el senuelo y revisar el principal solicitante (PowerShell Direct desde el host):
      Get-ADUser svc_sql -Properties ServicePrincipalNames,msDS-SupportedEncryptionTypes
      Get-ADUser <solicitante> -Properties MemberOf,LastLogonDate
  - Historico de 4688 del solicitante (regla base 67027 alerta en cada 4688):
      jq -c 'select(.data.win.system.eventID=="4688") | {ts:.timestamp, np:.data.win.eventdata.newProcessName, host:.agent.name}' /var/ossec/logs/alerts/alerts.json
  - Linaje del proceso sospechoso en el host origen (Sysmon EID 1, parentImage + Hashes):
      Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} -MaxEvents 50 | Format-List TimeCreated,Message
  - Evento crudo en DC01:
      Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -MaxEvents 20 | Format-List TimeCreated,Message
  - Baseline known-good: [ ] coincide  [X] no coincide (svc_sql no tiene uso legitimo)
EXTERNO (conceptual — lab aislado):
  - IP solicitante -> AbuseIPDB/OTX (N/A: red interna 10.10.10.0/24).
  - No aplica hash en este vector (4769 no porta proceso).
--------------------------------------------------------------------
VEREDICTO ............... : [X] TP  (deteccion determinista del honeypot)
Justificacion ........... : Cualquier TGS contra svc_sql es malicioso; no existe uso
                            legitimo de la cuenta senuelo. Confirmado por regla 100110.
--------------------------------------------------------------------
ACCIONES TOMADAS
[X] AR abrio caso automatico (nivel 12)
[X] Enriquecimiento local ejecutado (alerts.json + Get-ADUser + Sysmon EID 1)
[ ] Endpoint revisado (Get-MpThreat) -> pendiente sobre el host solicitante
[ ] Contencion inicial -> recomendado deshabilitar el principal solicitante si se
    confirma uso no autorizado y rotar credenciales de cuentas de servicio reales
[X] Otra: identificada cuenta solicitante e IP como pivote para el host de origen
--------------------------------------------------------------------
ESTADO .................. : [X] En triage -> escalar
ESCALADO ................ : [X] Si -> IR (PICERL, Proyecto 4)
Notas de handoff a IR ... : TP confirmado por honeypot. Pivotar al host del solicitante
                            (IP/targetUserName del 4769), revisar 4688/Sysmon de ese host,
                            Get-MpThreat en WIN11, y evaluar si el principal esta
                            comprometido. Identify -> Contain en IR.
====================================================================
```

---

## 3. Guia rapida de relleno por regla

| Regla | Nivel | Canal/EID | ATT&CK | Pivote de enriquecimiento clave |
|-------|-------|-----------|--------|---------------------------------|
| 100110 Kerberoasting honeypot | 12 | Security 4769 | T1558.003 | `targetUserName`/`ipAddress` del 4769 -> host origen |
| 100111 Kerberoasting RC4 | 10 | Security 4769 (`ticketEncryptionType`=0x17) | T1558.003 | Confirmar que no es cuenta de equipo ($); ojo: WS2025 negocia AES, RC4 evadible |
| 100120 PowerShell ofuscado | 12 | PowerShell 4104 (`scriptBlockText`) | T1059.001 / T1027 | Linaje Sysmon EID 1 (`parentImage`+SHA256); contrastar con baseline admin |
| 100130 Tamper Defender | 12 | 4688 (`commandLine`) | T1562.001 | `Get-MpComputerStatus`; revisar exclusiones; baseline reinstalacion admin |
| 100140 AS-REP Roasting | 12 | Security 4768 (`preAuthType`=0) | T1558.004 | `Get-ADUser a.garcia` (DoesNotRequirePreAuth); aun sin disparo real |
| 100150 certutil | 10 | 4688 (`commandLine`) | T1105 | Pivotar a Defender 1116/1117 (p.ej. Trojan:Win32/Ceprolad.A) |
| 100151 bitsadmin /transfer | 10 | 4688 (`commandLine`) | T1105 | Linaje + URL destino del comando |
| 100152 mshta + http | 10 | 4688 (`commandLine`) | T1105 | URL en `commandLine`; linaje Sysmon |
| 100160 Defender DETECCION | 12 | Defender 1116 | — | `win.eventdata."threat Name"`; pivote de caza |
| 100161 Defender ACCION | 10 | Defender 1117 | — | `win.eventdata."action Name"`; confirma bloqueo/cuarentena |
| 100170 Servicio nuevo (cand.) | 12 | System 7045 (`imagePath`) | T1543.003 | `imagePath` sospechoso; linaje del instalador |

**Queries de apoyo (ejecutables):**

```bash
# Triage rapido de cualquier alerta por ID de regla
jq -c 'select(.rule.id=="<ID>") | {ts:.timestamp, host:.agent.name, lvl:.rule.level, log:.full_log}' /var/ossec/logs/alerts/alerts.json

# Defender (campos con espacio)
jq -c 'select(.rule.id=="100160" or .rule.id=="100161") | {ts:.timestamp, threat:.data.win.eventdata."threat Name", action:.data.win.eventdata."action Name"}' /var/ossec/logs/alerts/alerts.json
```

```powershell
# Endpoint (PowerShell Direct desde el host Hyper-V)
Get-MpThreat
Get-MpComputerStatus | Format-List AMRunningMode, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated
```

> Cierre del caso solo tras veredicto justificado. TP de nivel >=12 -> handoff a IR (PICERL, Proyecto 4). FP -> documentar causa y, si aplica, proponer ajuste de baseline/regla.