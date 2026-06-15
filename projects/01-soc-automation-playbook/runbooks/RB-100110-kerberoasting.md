# 🛠️ Runbook RB-100110 — Kerberoasting (honeypot svc_sql)

> **Regla(s) Wazuh:** 100110 (honeypot svc_sql, nivel 12) + 100111 (RC4 clásico, nivel 10) · **ATT&CK:** T1558.003 Kerberoasting (Credential Access) · **Severidad:** Alta (nivel 12 honeypot / nivel 10 clásico)

## 1. Disparo

La alerta nace de un evento **Security 4769** (solicitud de ticket de servicio Kerberos / TGS) registrado en DC01 (10.10.10.10) y reenviado al manager Wazuh (10.10.10.20).

- **100110 (honeypot, determinista):** un 4769 cuyo `targetUserName` (la **cuenta de servicio cuyo TGS se solicita**) es **svc_sql**. svc_sql es una cuenta señuelo con SPN `MSSQLSvc/sql01.corp.local:1433` que no presta ningún servicio real. Ninguna aplicación ni usuario legítimo pide su TGS, por lo que **cualquier** solicitud es sospechosa por diseño. Disparo de máxima confianza.
- **100111 (RC4 clásico):** un 4769 con `ticketEncryptionType = 0x17` (RC4-HMAC), excluyendo cuentas de equipo (las que terminan en `$`). El RC4 es la firma del roasting tradicional porque el TGS RC4 es crackeable offline.
- **Aviso "mito del RC4":** en WS2025 el KDC negocia **AES (0x12)** por defecto, así que un ataque real puede salir cifrado en AES y **NO disparar 100111**. La detección robusta es el honeypot 100110. No descartes un ataque por ausencia de RC4.

> **Semántica del 4769 (clave para el triage):** en el evento Security 4769, `targetUserName` identifica a la **cuenta/servicio cuyo ticket se pide** (aquí, el señuelo svc_sql); el **solicitante** se identifica por su origen de red `ipAddress`. No confundas ambos campos.

## 2. Triage inicial (objetivo: TP/FP en < 5 min)

1. **Identifica qué regla disparó.** Si es **100110 → trátalo como TP casi seguro**; svc_sql es señuelo, no hay caso de uso legítimo.
2. **¿Qué cuenta se pidió?** Campo `win.eventdata.targetUserName` (debe ser **svc_sql** en 100110). **¿Desde dónde?** El origen del solicitante es `win.eventdata.ipAddress`.
3. **Mapea el origen** al inventario: 10.10.10.21 = WIN11, 10.10.10.10 = DC01, 10.10.10.20 = manager. Un origen fuera del inventario conocido eleva la sospecha.
4. **Cifrado:** mira `ticketEncryptionType`. 0x17 (RC4) refuerza la hipótesis de roasting; 0x12 (AES) **no la descarta** (ver mito del RC4).
5. **Criterio TP/FP:**
   - **TP:** TGS hacia svc_sql (100110), o un único origen pidiendo TGS de varios SPN distintos en poco tiempo (roasting masivo), o RC4 forzado sobre cuentas de servicio.
   - **FP / known-good:** la caza del Proyecto 2 mostró que gran parte del ruido era **actividad de ADMIN** (PS-remoting, reinstalación de Sysmon) → hay baseline de known-good. Pero ojo: **un 4769 a svc_sql NO tiene known-good** — ni el admin tiene motivo para pedir su TGS. Si aparece, es TP aunque venga de un host administrativo (posible cuenta/host comprometido).

## 3. Enriquecimiento

**Local (disponible en el lab):**

Alertas de la regla en `alerts.json` — servicio objetivo, origen y cifrado:
```bash
jq -r 'select(.rule.id=="100110" or .rule.id=="100111")
  | [.timestamp, .rule.id, .data.win.eventdata.targetUserName,
     .data.win.eventdata.ipAddress, .data.win.eventdata.ticketEncryptionType]
  | @tsv' /var/ossec/logs/alerts/alerts.json
```

Volumen de cuentas-servicio distintas por origen (detectar roasting masivo) — todos los 4769:
```bash
jq -r 'select(.data.win.system.eventID=="4769")
  | [.data.win.eventdata.ipAddress, .data.win.eventdata.targetUserName]
  | @tsv' /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn
```

Estado del propio señuelo svc_sql (confirmar SPN/RC4 y fecha de último cambio de pw) por PowerShell Direct desde el host:
```powershell
Get-ADUser -Identity svc_sql -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes,PasswordLastSet,LastLogonDate |
  Select-Object SamAccountName,ServicePrincipalName,msDS-SupportedEncryptionTypes,PasswordLastSet,LastLogonDate
```

Log crudo del 4769 en DC01 (correlación temporal, campos completos y, sobre todo, la **cuenta solicitante** que el 4769 trae en su mensaje):
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 50 |
  Where-Object { $_.Message -match 'svc_sql' } |
  Format-List TimeCreated,Message
```

AD de la cuenta solicitante identificada en el 4769 (grupos, último logon, estado):
```powershell
Get-ADUser -Identity <solicitante> -Properties MemberOf,LastLogonDate,Enabled,whenCreated |
  Select-Object SamAccountName,Enabled,LastLogonDate,whenCreated,@{n='Grupos';e={$_.MemberOf}}
```

Linaje del proceso que originó la petición en el host origen (Sysmon EID 1: imagen, proceso padre + hash) — pivote sobre la `ipAddress` del 4769 (ejemplo para WIN11):
```bash
jq -r 'select(.data.win.system.eventID=="1" and .agent.ip=="10.10.10.21")
  | [.timestamp, .data.win.eventdata.image, .data.win.eventdata.parentImage,
     .data.win.eventdata.hashes]
  | @tsv' /var/ossec/logs/alerts/alerts.json
```

**Externo (conceptual — lab aislado, sin internet):** en un SOC real se haría IoC lookup del hash SHA256 del binario solicitante (p. ej. Rubeus/impacket) en VirusTotal/OTX y de cualquier IP externa en AbuseIPDB. Aquí queda como plantilla; el enriquecimiento ejecutable es 100% local.

## 4. Investigación

Preguntas a responder y pivotes:

- **¿Qué se pidió?** Confirma que `targetUserName` es svc_sql. **¿Quién lo pidió?** Identifica la cuenta solicitante en el mensaje del 4769 (`Get-WinEvent`): ¿es un usuario de dominio (j.perez/m.lopez/a.garcia/helpdesk), una cuenta de servicio o `CORP\Administrator`? Si es admin pidiendo svc_sql → fuerte indicio de **cuenta comprometida**.
- **¿Desde dónde?** Pivota la `ipAddress` al host (p. ej. WIN11 = 10.10.10.21). Salta al **linaje de proceso** (Sysmon EID 1): ¿qué binario y proceso padre generaron la petición? ¿PowerShell, un binario sin firmar, un hash desconocido?
- **¿Alcance?** ¿El mismo origen pidió TGS de **múltiples cuentas-servicio/SPN distintos**? Volumen alto = roasting masivo → escalado inmediato a IR.
- **¿Temporalidad?** ¿A qué hora? ¿Coincide con ventana de mantenimiento de admin conocida (baseline) o es fuera de horario?
- **¿Cadena?** Correlaciona en `alerts.json` con otras detecciones del mismo origen y ventana: 100120 (PowerShell ofuscado), 100150–100152 (LOLBins certutil/bitsadmin/mshta), 100160/100161 (Defender detectó/bloqueó). El EDR (1116/1117) sirve de **pista de caza** y pivote.
- **¿Crackeo?** La pw de svc_sql (`'Summer2024!'`) es trivial. Asumir crackeo offline en cuanto salió su TGS.

## 5. Respuesta

Acciones proporcionadas a severidad Alta:

1. **Resetear la contraseña de svc_sql** de inmediato (la pw débil `'Summer2024!'` debe considerarse crackeable/crackeada en cuanto sale su TGS):
   ```powershell
   Set-ADAccountPassword -Identity svc_sql -Reset -NewPassword (Read-Host -AsSecureString)
   Set-ADUser -Identity svc_sql -ChangePasswordAtLogon $false
   ```
2. **Aislar el host origen** (p. ej. WIN11). En el lab por PowerShell Direct: desconectar el adaptador de la VM / quitarla de LAB-Net. En un SOC real: contención de red vía EDR.
3. **Revisar uso indebido de credenciales** de la cuenta solicitante: si una cuenta legítima (admin/usuario) pidió el TGS de svc_sql, **deshabilitarla o resetearla** por sospecha de compromiso:
   ```powershell
   Disable-ADAccount -Identity <solicitante>
   ```
4. **Escalar a IR (Proyecto 4 / PICERL)** si hay **múltiples cuentas-servicio/SPN** solicitados, evidencia de crackeo, o el solicitante es `CORP\Administrator`. Este playbook llega hasta la respuesta inicial y el **handoff a IR**.
5. **Verificar el endpoint** (Defender) en el host origen por si hubo herramientas de roasting:
   ```powershell
   Get-MpThreat
   Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled
   ```

## 6. Documentación

Registrar en el caso:

- **Identificadores:** rule.id (100110/100111), nivel, timestamp del 4769, agente/DC01.
- **Qué/quién/dónde:** `targetUserName` (cuenta-servicio objetivo = svc_sql), cuenta **solicitante** (del mensaje 4769), `ipAddress` (origen → host mapeado), `ticketEncryptionType` (0x17/0x12, con nota del mito del RC4).
- **IoCs:** IP origen, cuenta solicitante, hash SHA256 y ruta del binario solicitante (linaje Sysmon), número de cuentas-servicio/SPN distintos solicitados.
- **Enriquecimiento AD:** grupos y último logon del solicitante; ServicePrincipalName / msDS-SupportedEncryptionTypes / PasswordLastSet de svc_sql.
- **Decisión y acciones:** veredicto TP/FP con justificación (recordar que svc_sql no tiene known-good), reset de svc_sql, host aislado, cuenta deshabilitada, escalado a IR (sí/no y motivo).
- **MITRE:** T1558.003.

## 7. Automatización aplicable

Wazuh **Active Response lado-manager** ya abre automáticamente un **caso/ticket** ante alertas de nivel ≥ 12 (acción segura y de solo-lectura: apertura + enriquecimiento), lo que cubre la creación del caso para 100110. Sobre esa base se puede automatizar el enriquecimiento de lectura (volcado del estado de svc_sql con `Get-ADUser` y del `Get-ADUser` del solicitante) y adjuntarlo al caso; las acciones de impacto (reset de svc_sql, aislamiento del host, deshabilitar cuentas) se mantienen **manuales con aprobación del analista** por su carácter destructivo.