# Hunt H5 — Kerberoasting (honeypot svc_sql) y el mito del RC4

> **Tactica ATT&CK:** Credential Access (TA0006) · **Tecnica:** T1558.003 (Kerberoasting).

## Hipotesis

Un atacante con cualquier cuenta de dominio valida puede enumerar cuentas de servicio con SPN y solicitar sus tickets TGS para crackear el material de clave offline y recuperar la contrasena en claro. Sospechamos que las cuentas de servicio de `corp.local` son objetivo y que la deteccion clasica basada en cifrado RC4 (0x17) puede no disparar si el KDC negocia AES. Cazamos el comportamiento (peticion de TGS hacia el senuelo `svc_sql`), no el cifrado.

## Tecnica ATT&CK

**T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting** (Credential Access). Cualquier principal autenticado en el dominio puede pedir al KDC un ticket de servicio (TGS) para una cuenta que tenga un SPN registrado. La porcion del TGS dirigida al servicio va cifrada con la clave de la cuenta de servicio; el atacante la extrae y la somete a fuerza bruta offline (Hashcat) sin tocar el DC ni generar bloqueos de cuenta.

Detalle que sostiene el resto del hunt: **la clave con la que se cifra el TGS depende del tipo de cifrado (etype) que negocie el KDC**, no del atacante.

- Con **RC4-HMAC** (etype 23 = `0x17`) la clave **es el hash NT** de la contrasena (sin sal). Es lo que historicamente se fuerza, porque el crackeo es mas barato y el indicador "TGS en RC4" es facil de firmar.
- Con **AES256-CTS-HMAC-SHA1-96** (etype 18 = `0x12`) la clave se deriva de la contrasena mediante PBKDF2 **con sal** (el principal Kerberos). Sigue siendo crackeable offline contra la contrasena en claro, pero mas lento y sin el hash NT directo.

En ambos casos el objetivo del crackeo es la contrasena de la cuenta de servicio. Por eso una deteccion anclada en `0x17` deja un hueco: si el KDC entrega AES, el ataque ocurre igual y la firma de RC4 nunca dispara.

## Fuente de datos

- **Config de AD (DC01):** `Get-ADUser` filtrando `ServicePrincipalName` — inventario de cuentas con SPN (superficie de Kerberoasting) y revision de `msDS-SupportedEncryptionTypes`.
- **Security 4769** (canal `Security`, ingerido por el agente Wazuh del DC): *A Kerberos service ticket was requested*. Es el evento ancla: nos da `serviceName` (a quien se pidio el ticket), `ticketEncryptionType` (cifrado negociado), `targetUserName` (quien lo pidio, la cuenta cliente) e `ipAddress` (origen).
- Cazamos sobre **alerts.json** en el manager y sobre los **logs crudos** del DC via `Get-WinEvent`.
  - **Matiz importante del almacen:** la regla base 67027 (nivel 3) alerta en cada **4688**, no en 4769. Por tanto **un 4769 solo llega a alerts.json si alguna regla custom dispara** sobre el (100110 ante cualquier 4769 a `svc_sql`; 100111 ante 4769 con `0x17`). Eso significa que **alerts.json no es la fuente autoritativa para 4769**: solo contiene los que ya matchearon una regla. La fuente completa y la que cierra el caso del RC4 evadido es el **log crudo del DC** (`Get-WinEvent`), coherente con la leccion de metodologia: cazar mira la telemetria cruda, no solo lo que ya disparo una regla.

## La caza

### Config hunt — inventario de SPN en el DC (PowerShell Direct)

```powershell
# Cuentas de usuario con SPN = superficie de Kerberoasting
Get-ADUser -Filter {ServicePrincipalName -like "*"} `
  -Properties ServicePrincipalName, 'msDS-SupportedEncryptionTypes' |
  Select-Object SamAccountName,
                @{n='SPN';e={$_.ServicePrincipalName -join ', '}},
                @{n='EncTypes';e={$_.'msDS-SupportedEncryptionTypes'}} |
  Format-Table -AutoSize
# Esperado: krbtgt (built-in: SPN kadmin/changepw, presente en todo dominio AD)
#           y svc_sql (SENUELO: SPN MSSQLSvc/sql01.corp.local:1433, EncTypes=23 -> RC4 habilitado)
```

### Wazuh (alerts.json, jq en el manager)

```bash
# (a) DETECCION ROBUSTA / honeypot: CUALQUIER 4769 hacia el senuelo svc_sql es malicioso por definicion.
#     Agnostico del cifrado -> es lo que sostiene la deteccion cuando el RC4 no aparece.
#     Lo encontramos en alerts.json porque la regla 100110 dispara y escribe la alerta.
jq -c 'select(.data.win.system.eventID=="4769"
        and (.data.win.eventdata.serviceName // "" | ascii_downcase)=="svc_sql")
       | {ts:.timestamp, rule:.rule.id, lvl:.rule.level,
          service:.data.win.eventdata.serviceName,
          enc:.data.win.eventdata.ticketEncryptionType,
          requestedBy:.data.win.eventdata.targetUserName,
          clientIp:.data.win.eventdata.ipAddress}' \
  /var/ossec/logs/alerts/alerts.json

# (b) DETECCION CLASICA: 4769 cifrado con RC4 (0x17) hacia cualquier servicio.
#     Util como contraste -> en este lab NO devuelve el ticket de svc_sql (salio en AES 0x12),
#     y solo aparece aqui lo que la regla 100111 haya escrito en alerts.json.
jq -c 'select(.data.win.system.eventID=="4769"
        and .data.win.eventdata.ticketEncryptionType=="0x17")
       | {ts:.timestamp, rule:.rule.id,
          service:.data.win.eventdata.serviceName,
          enc:.data.win.eventdata.ticketEncryptionType,
          requestedBy:.data.win.eventdata.targetUserName,
          clientIp:.data.win.eventdata.ipAddress}' \
  /var/ossec/logs/alerts/alerts.json
```

### Origen — logs crudos (PowerShell Direct, Get-WinEvent)

```powershell
# 4769 crudo en el DC (10.10.10.10). Fuente AUTORITATIVA para 4769: valida serviceName,
# cifrado, solicitante e IP de origen SIN depender de que una regla haya disparado.
# Aqui se demuestra que el ticket de svc_sql salio en AES256 (0x12) y no en RC4 (0x17).
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4769 } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [PSCustomObject]@{
      Time        = $_.TimeCreated
      ServiceName = $d['ServiceName']          # svc_sql = senuelo
      EncType     = $d['TicketEncryptionType'] # 0x12 AES256 / 0x17 RC4
      RequestedBy = $d['TargetUserName']       # cuenta cliente que pidio el TGS
      ClientIP    = $d['IpAddress']            # origen del ataque
    }
  } |
  Where-Object { $_.ServiceName -eq 'svc_sql' -or $_.EncType -eq '0x17' } |
  Format-Table -AutoSize
```

### KQL (Sentinel / Defender XDR — equivalente teorico)

```kql
// No se ejecuta en el lab (corre Wazuh); referencia de como se veria en un SIEM cloud.
// EventID 4769 = Kerberos service ticket requested. 0x17 = RC4 (etype 23), 0x12 = AES256 (etype 18).
SecurityEvent
| where EventID == 4769
| extend Service = ServiceName, Enc = tostring(TicketEncryptionType), RequestedBy = TargetUserName
| where Service =~ "svc_sql"        // (a) honeypot: deteccion deterministica, agnostica del cifrado
      or Enc == "0x17"              // (b) clasico: RC4 forzado
| project TimeGenerated, Computer, Service, Enc, RequestedBy, IpAddress
| sort by TimeGenerated desc
```

## Hallazgos (datos REALES del lab)

| # | Hallazgo | Dato |
|---|----------|------|
| 1 | Inventario de SPN en `corp.local` | `Get-ADUser` devuelve **krbtgt** (built-in, esperado) y **svc_sql** (el SENUELO). `a.garcia` no aparece: es honeypot de AS-REP y **no tiene SPN**. |
| 2 | Configuracion del senuelo | `svc_sql` -> SPN `MSSQLSvc/sql01.corp.local:1433`, `msDS-SupportedEncryptionTypes=23` (bits DES+**RC4**+AES256 -> **RC4 habilitado**), password debil `Summer2024!`. |
| 3 | TGS observado (4769) | `ServiceName = svc_sql`, `TicketEncryptionType = 0x12` (**AES256**, NO 0x17/RC4), `requestedBy = Administrator`. |
| 4 | **Hallazgo clave** | Aunque `svc_sql` tiene RC4 habilitado, como `EncTypes=23` tambien incluye AES256, **Windows Server 2025 negocia el etype mas fuerte mutuo (AES256, 0x12)**. La deteccion clasica "TGS con RC4 0x17" (**regla 100111**) **NO dispara** -> el ataque se evade. |
| 5 | Deteccion que sí dispara | La **regla 100110** (alta severidad; el nivel exacto se lee en `rule.level` de la query a) alerta por **cualquier** 4769 hacia `svc_sql`, independientemente del cifrado. Deteccion deterministica. |

## Triage: known-good vs malicioso

- **Honeypot (determinista):** `svc_sql` es una cuenta senuelo. No existe servicio MSSQL real escuchando ni proceso legitimo que solicite su ticket. **Cualquier** 4769 con `serviceName=svc_sql` es malicioso por definicion — cero falsos positivos. El solicitante (`requestedBy=Administrator`) y su `ipAddress` son el origen del ataque a investigar.
- **RC4 (0x17) en cuentas reales:** ruido posible. Sistemas legacy o apps mal configuradas pueden negociar RC4 de forma legitima; este indicador requiere correlacion (volumen de SPN distintos pedidos por un mismo usuario en poco tiempo, host inusual). En este lab **no aplica**: el ticket de `svc_sql` salio en AES256 (0x12), por lo que el indicador clasico de RC4 ni siquiera estaria presente.
- **Leccion de triage:** no dependas del cifrado. El etype lo decide el KDC, no el atacante; basar la deteccion en `0x17` deja un hueco evadible — confirmado aqui, donde `EncTypes=23` incluye AES256 y el KDC lo prefiere. El honeypot de identidad convierte la deteccion en binaria.

## Outcome

- **Deteccion robusta (cobertura principal):** mantener y priorizar la **regla 100110** (alta severidad, agnostica del cifrado) — alerta ante cualquier 4769 hacia `svc_sql`. Es la deteccion deterministica que cubre el caso que la regla clasica evade.
- **Deteccion clasica (complementaria):** conservar la **regla 100111** (4769 con `0x17`/RC4) como red de seguridad para cuentas de servicio *reales* que aun negocien RC4, asumiendo que por sí sola es evadible.
- **Leccion metodologica:** los **honeypots de identidad** (cuenta senuelo con SPN) dan deteccion determinista y de bajo ruido; superan a las firmas basadas en cifrado. Y dado que ningun base-rule cubre 4769, la verificacion definitiva se hace sobre el **log crudo del DC**, no sobre alerts.json.
- **Hardening:**
  - Forzar **AES-only** en cuentas de servicio reales (`msDS-SupportedEncryptionTypes=24` = AES128+AES256, retira el bit RC4 y DES que en `svc_sql` valen 23) y desactivar RC4 a nivel de dominio donde sea viable.
  - **Contrasenas largas y aleatorias** (gMSA / >25 caracteres) en cuentas de servicio para que el crackeo offline sea inviable incluso con AES salada — el caso `Summer2024!` ilustra el riesgo.
  - Auditar periodicamente el inventario de SPN con el *config hunt* de `Get-ADUser` para detectar SPN nuevos o inesperados.
