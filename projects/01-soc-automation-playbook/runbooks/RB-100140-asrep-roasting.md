# 🛠️ Runbook RB-100140 — AS-REP Roasting
> **Regla(s) Wazuh:** 100140 · **ATT&CK:** T1558.004 (AS-REP Roasting, Credential Access) · **Severidad:** Alta (nivel 12)

## 1. Disparo
La regla 100140 dispara ante un evento de seguridad **4768** (Kerberos Authentication Service — solicitud de TGT) en el que `win.eventdata.preAuthType` es **0**, es decir, la cuenta solicita un TGT **sin preautenticacion Kerberos**. Cuando una cuenta tiene `DoesNotRequirePreAuth=True` (flag UF_DONT_REQUIRE_PREAUTH), el KDC entrega la parte cifrada del AS-REP con la clave derivada de la contrasena del usuario sin exigir el timestamp precifrado, lo que permite a un atacante (Rubeus / impacket `GetNPUsers`) extraerla offline y crackearla.

En este lab existe el honeypot **a.garcia** (`DoesNotRequirePreAuth=True`) como senuelo: es una cuenta que de forma legitima nunca deberia autenticarse, por lo que cualquier 4768 con preAuth 0 hacia ella es altamente sospechoso. Nota operativa: **aun no hay disparo real** en el lab (requiere lanzar Rubeus o impacket `GetNPUsers`); el valor actual de este runbook es la **caza proactiva de configuracion**.

## 2. Triage inicial (objetivo: TP/FP en < 5 min)
Checklist, en orden:
1. **¿Que cuenta?** Lee `win.eventdata.targetUserName`. Si es **a.garcia** (honeypot) → trátalo como **TP de alta confianza**; ninguna actividad legitima debe tocar esa cuenta.
2. **¿Cuenta esperada?** Cualquier 4768 preAuth 0 hacia una cuenta **no esperada** (es decir, una cuenta que no deberia tener el flag DONT_REQ_PREAUTH) es sospechoso. Cruza contra el inventario de cuentas roastables del paso 3.
3. **Origen de la peticion.** Lee `win.eventdata.ipAddress`. ¿Viene de un host del dominio esperado (DC01 10.10.10.10, WIN11 10.10.10.21) o de un origen anomalo dentro de LAB-Net?
4. **Volumen/patron.** Una sola peticion puntual difiere de un **barrido** (multiples cuentas con preAuth 0 en segundos), firma tipica de `GetNPUsers` enumerando todo el dominio.
5. **Known-good del lab.** El baseline de Proyecto 2 indica que la mayoria del ruido era **actividad de ADMIN** (PS-remoting, reinstalacion de Sysmon). El AS-REP Roasting **no** tiene un known-good legitimo equivalente: la preautenticacion deshabilitada no es una configuracion operativa normal en este dominio. Salvo que se confirme una prueba autorizada y documentada del propio analista, trátalo como TP.

Criterio rapido: **target = a.garcia → TP**. Target ≠ cuenta esperada con preAuth 0 → **TP probable**, sigue al enriquecimiento. Solo es FP si se corresponde con una prueba autorizada y documentada del equipo.

## 3. Enriquecimiento
**Local (disponible en el lab):**

Alertas 100140 recientes con sus campos clave (manager Wazuh):
```bash
jq -r 'select(.rule.id=="100140") | [.timestamp, .data.win.eventdata.targetUserName, .data.win.eventdata.ipAddress, .data.win.eventdata.preAuthType] | @tsv' /var/ossec/logs/alerts/alerts.json
```

Inventario de **cuentas roastables** por configuracion (caza proactiva — el valor actual del runbook), por PowerShell Direct contra DC01:
```powershell
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth, msDS-SupportedEncryptionTypes, whenChanged, memberOf |
  Select-Object SamAccountName, DoesNotRequirePreAuth, whenChanged, memberOf
```

Contexto de la cuenta objetivo (grupos, ultima modificacion, estado):
```powershell
Get-ADUser -Identity a.garcia -Properties DoesNotRequirePreAuth, MemberOf, whenChanged, LastLogonDate, Enabled |
  Select-Object SamAccountName, Enabled, DoesNotRequirePreAuth, LastLogonDate, whenChanged, MemberOf
```

Log crudo 4768 en el DC para confirmar origen y patron (PS Direct contra DC01). El campo "Pre-Authentication Type" se renderiza en decimal; el patron se ancla a fin de token para evitar coincidencias parciales:
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4768 } -MaxEvents 50 |
  Where-Object { $_.Message -match 'Pre-Authentication Type:\s+0\s*$' } |
  Select-Object TimeCreated,
    @{n='Target';e={ (($_.Message -split "`n" | Select-String 'Account Name:').Line -join '; ').Trim() }},
    @{n='SrcIP'; e={ (($_.Message -split "`n" | Select-String 'Client Address:').Line -join '; ').Trim() }}
```

Correlacion temporal: ¿hubo en el mismo origen/ventana alertas de descarga LOLBin (100150/100151/100152) o PowerShell ofuscado (100120) que indiquen entrega de Rubeus/impacket?
```bash
jq -r 'select(.rule.id=="100120" or .rule.id=="100150" or .rule.id=="100151" or .rule.id=="100152") | [.timestamp, .rule.id, (.data.win.eventdata.ipAddress // .agent.name), .data.win.eventdata.commandLine] | @tsv' /var/ossec/logs/alerts/alerts.json
```

**Externo (conceptual — lab AISLADO, sin internet):** en un SOC real se ejecutaria la plantilla de IoC lookup: reputacion de la IP de origen (AbuseIPDB / VirusTotal / OTX) si fuera externa, y hash del binario atacante (Rubeus / `GetNPUsers`) en VirusTotal. Aqui queda documentado como paso que se realizaria, no ejecutable en el lab.

## 4. Investigacion
Preguntas a responder y pivotes:
- **¿Que cuentas son roastables?** Define el alcance real con `Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'`. ¿Solo el honeypot a.garcia o hay otras cuentas con el flag puesto inadvertidamente?
- **Usuario/origen.** Resuelve la IP de `ipAddress` a un host del dominio. ¿Coincide con DC01 (10.10.10.10) / WIN11 (10.10.10.21) o es un origen inesperado dentro de LAB-Net?
- **Linaje de proceso en el origen.** Si la peticion sale de WIN11, pivota a Sysmon EID 1 (`parentImage`, `image`, hash SHA256) y al historico de 4688 (la regla base 67027 alerta en cada 4688) para identificar el proceso que lanzo la enumeracion (powershell.exe, un binario Rubeus, python para impacket).
- **Temporalidad.** ¿Peticion unica o barrido? ¿Correlaciona con alertas 100120 / 100150-152 (entrega del tooling) en la misma ventana?
- **Alcance.** ¿Se solicitaron AS-REP para varias cuentas? ¿Hubo despues autenticaciones exitosas (4624) que sugieran que una contrasena fue crackeada y reutilizada?

## 5. Respuesta
Acciones proporcionadas a la severidad alta:
- **Contencion del origen.** Si la peticion procede de un host identificado (p. ej. WIN11), aislalo a nivel de operacion del lab (PowerShell Direct desde el host, sin red — LAB-Net ya esta aislada de internet) para detener cualquier exfiltracion de tickets.
- **Erradicacion de la exposicion de configuracion.** Para cualquier cuenta **no honeypot** con el flag puesto, **quitar DONT_REQ_PREAUTH** si no es necesario:
  ```powershell
  Set-ADAccountControl -Identity <cuenta> -DoesNotRequirePreAuth $false
  ```
- **Reset de contrasena** de toda cuenta cuyo AS-REP haya podido ser capturado (especialmente si la pw es debil), forzando cambio:
  ```powershell
  Set-ADAccountPassword -Identity <cuenta> -Reset
  Set-ADUser -Identity <cuenta> -ChangePasswordAtLogon $true
  ```
- **Honeypot a.garcia:** NO se remedia su configuracion (debe seguir siendo roastable como senuelo). Su disparo es la senal; la accion es **escalar e investigar el origen**, no "arreglar" la cuenta.
- **Escalado / handoff a IR.** Confirmado el TP, abrir/elevar el caso y entregar a IR (PICERL completo en Proyecto 4). Este playbook llega hasta la **respuesta inicial**.

## 6. Documentacion
Registrar en el caso:
- **Campos clave:** `rule.id` (100140), `targetUserName`, `ipAddress` (origen), `preAuthType` (0), `timestamp` del 4768; host/agente Wazuh.
- **IoCs:** cuenta(s) objetivo (a.garcia u otras), IP de origen, y — si se identifico — hash SHA256 + nombre del binario atacante (Rubeus / impacket) via Sysmon EID 1.
- **Inventario de exposicion:** salida de `Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'` (cuentas roastables al momento del incidente).
- **Decision y justificacion:** TP/FP, criterio aplicado (target=honeypot, cuenta inesperada, barrido), correlacion con 100120 / 100150-152, acciones tomadas (flag retirado, pw reseteada, origen aislado) y handoff a IR.
- **Mapeo:** T1558.004; vinculo a las alertas correlacionadas.

## 7. Automatizacion aplicable
La AR lado-manager de Wazuh ya abre **automaticamente un caso** ante cualquier alerta nivel ≥12 (la 100140 lo es), realizando apertura de ticket y enriquecimiento de solo-lectura. Sobre esa base se puede automatizar el **enriquecimiento AD** del paso 3 (volcado de cuentas con `DoesNotRequirePreAuth=True` y contexto de la cuenta objetivo) adjuntandolo al caso. La contencion activa (retirar el flag, reset de pw, aislar origen) se mantiene **manual** por su impacto, reservada al analista tras confirmar el TP.