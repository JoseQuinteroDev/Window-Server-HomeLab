# Triage y severidad

Playbook de respuesta inicial para el SOC del lab `corp.local`. Cubre cómo clasificar una alerta de Wazuh, asignarle severidad, decidir TP vs FP en menos de 5 minutos apoyándose en el baseline de known-good, y cuándo escalar a Respuesta a Incidentes (IR, Proyecto 4). El alcance termina en la respuesta inicial y el handoff a IR; la contención/erradicación se desarrolla en el Proyecto 4.

## 1. Mapeo nivel Wazuh -> severidad SOC -> SLA

Las reglas locales (`/var/ossec/etc/rules/local_rules.xml`) usan dos niveles. El nivel es la guía inicial de severidad, pero la severidad final la fija el triage (un FP confirmado baja a informativo; un TP confirmado puede subir a crítico en el escalado).

| Nivel Wazuh | Severidad SOC | SLA de toma (TTA) | SLA de triage (TTT) | Reglas en este nivel |
|---|---|---|---|---|
| 12 | Alta | <= 15 min | <= 60 min | 100110, 100120, 100130, 100140, 100160 |
| 10 | Media | <= 60 min | <= 4 h | 100111, 100150, 100151, 100152, 100161, (100170 candidata) |

Notas operativas:
- Nivel 12 = ejecución/manipulación confirmada por contenido (PowerShell ofuscado, tamper de Defender), señuelo tocado (honeypot Kerberoasting) o detección del propio EDR (1116). Tratar como **Alta** por defecto.
- Nivel 10 = técnica plausible pero con ruido conocido (RC4 clásico, LOLBins, acción de Defender). Tratar como **Media**: requiere correlación antes de escalar.
- La **Active Response lado-manager** ya abre un caso automáticamente para toda alerta de nivel >= 12 (apertura de ticket + enriquecimiento de solo lectura). Para nivel 12 el ticket ya existe cuando el analista llega; para nivel 10 el analista lo abre manualmente si confirma señal.

## 2. Decisión TP vs FP en < 5 min (flujo estándar)

El objetivo no es resolver el incidente, sino clasificar señal/ruido y decidir si se escala. Secuencia:

1. **Leer la alerta cruda** (campos clave por regla, ver tabla §4). 30 s.
2. **Identificar actor**: ¿qué cuenta y qué host? `win.eventdata.targetUserName`, origen del evento. ¿Es CORP\Administrator o una cuenta de servicio/usuario? 30 s.
3. **Contrastar con el BASELINE de known-good** (§3). Si el patrón coincide con actividad admin documentada -> FP probable. 60 s.
4. **Enriquecer en local** (el lab está aislado; el enriquecimiento externo es conceptual). 2 min:
   - Linaje de proceso: Sysmon EID 1 `parentImage` + hash SHA256.
   - Histórico de `4688` del actor en `alerts.json` (la regla base 67027 alerta en cada 4688).
   - Estado del endpoint: `Get-MpThreat` / `Get-MpComputerStatus` por PowerShell Direct.
   - Contexto AD: `Get-ADUser`, pertenencia a grupos.
5. **Veredicto**: TP -> escalar/abrir caso; FP -> cerrar con justificación y, si es recurrente, proponer afinado de regla (exclusión por baseline). 30 s.

Reglas de oro del lab:
- **Honeypot = determinista.** Cualquier `4769` hacia `svc_sql` (regla 100110) es TP por definición. No hay uso legítimo de la cuenta señuelo. No pierdas tiempo buscando FP.
- **El "mito del RC4".** WS2025 negocia AES (`0x12`); la firma RC4 `0x17` (regla 100111) es evadible y, por sí sola, débil. Trátala como **señal de apoyo**, no como prueba: correlaciónala con 100110 antes de escalar.
- **Defender como pivote.** Una alerta 100160 (1116) / 100161 (1117) confirma que algo malicioso ya ocurrió: es punto de partida de caza, no FP.

Enriquecimiento externo (CONCEPTUAL, plantilla de IoC lookup para un SOC real, no ejecutable en el lab aislado): hash SHA256 -> VirusTotal; IP/dominio -> AbuseIPDB / OTX. Documentar el IoC y dejarlo marcado para enriquecer al pasar a IR.

### Consultas de triage (ejecutables)

Leer la alerta y el actor desde `alerts.json` (manager Wazuh):

```bash
# Últimos TGS al honeypot svc_sql (Kerberoasting determinista, regla 100110)
jq -c 'select(.rule.id=="100110")
       | {ts:.timestamp, src:.data.win.eventdata.ipAddress,
          tgt:.data.win.eventdata.targetUserName,
          enc:.data.win.eventdata.ticketEncryptionType}' \
   /var/ossec/logs/alerts/alerts.json
```

```bash
# PowerShell ofuscado: extraer el scriptBlockText para clasificar (regla 100120)
jq -r 'select(.rule.id=="100120")
       | .data.win.eventdata.scriptBlockText' \
   /var/ossec/logs/alerts/alerts.json
```

```bash
# Histórico de procesos (4688) de la cuenta sospechosa, para baseline/linaje
jq -c 'select(.data.win.system.eventID=="4688")
       | select(.data.win.eventdata.targetUserName=="j.perez")
       | {ts:.timestamp, proc:.data.win.eventdata.newProcessName,
          cmd:.data.win.eventdata.commandLine}' \
   /var/ossec/logs/alerts/alerts.json
```

```bash
# Detección/acción de Defender (campos con espacio: "threat Name"/"action Name")
jq -c 'select(.rule.id=="100160" or .rule.id=="100161")
       | {ts:.timestamp, eid:.data.win.system.eventID,
          threat:.data.win.eventdata."threat Name",
          action:.data.win.eventdata."action Name"}' \
   /var/ossec/logs/alerts/alerts.json
```

Enriquecimiento local en el endpoint (PowerShell Direct desde el host, sin red):

```powershell
# AD: ¿es cuenta de servicio, usuario o admin de dominio?
Get-ADUser -Identity 'j.perez' -Properties MemberOf, ServicePrincipalNames, userAccountControl

# Estado y amenazas en WIN11 (10.10.10.21)
Invoke-Command -VMName 'WIN11' -ScriptBlock { Get-MpComputerStatus; Get-MpThreat }

# Log crudo del evento que disparó la regla (ej. 4769 Kerberoasting)
Invoke-Command -VMName 'DC01' -ScriptBlock {
  Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4769 } -MaxEvents 20 |
    Format-List TimeCreated, Message
}
```

## 3. Baseline de known-good (hallazgo del Proyecto 2)

Hallazgo central de la caza: **la mayoría del "ruido sospechoso" era actividad de ADMIN**, no ataque. Documentar lo benigno acelera el triage y reduce FP. Antes de escalar, descartar que el evento sea uno de estos patrones legítimos:

| Patrón benigno | Cómo se ve | Por qué es known-good | Regla que puede gatillar |
|---|---|---|---|
| PS-remoting del admin | `4104`/`4688` desde sesión de CORP\Administrator, host de gestión, horario laboral | Operación del lab vía PowerShell (administración legítima) | 100120 (si el script usa cmdlets vigilados de forma legítima) |
| Reinstalación de Sysmon | `7045` servicio Sysmon, o ejecución de `Sysmon*.exe` por admin | Mantenimiento del propio tooling de detección | 100170 (candidata, 7045) |
| `rundll32` de Windows | `rundll32.exe` invocando DLLs firmadas del sistema, parentImage de proceso de SO | Operación normal del SO, no LOLBin malicioso | (vigilancia LOLBin) |

Criterios para tratar algo como baseline:
- **Actor = CORP\Administrator** desde host/horario esperado, **y**
- **Linaje coherente** (parentImage esperado, binario firmado, hash SHA256 conocido), **y**
- Acción explicable por una tarea de administración documentada.

Si los tres se cumplen -> FP por baseline; cerrar con la justificación y, si recurre, proponer exclusión en la regla. Si falta cualquiera (p. ej. el actor es `j.perez` o `helpdesk` ejecutando PS ofuscado) -> NO es baseline, escalar.

## 4. Señal vs ruido por detección

| Regla | Técnica (ATT&CK) | Señal (TP fuerte) | Ruido / contexto a descartar | Acción de triage |
|---|---|---|---|---|
| 100110 (12) Kerberoasting honeypot | T1558.003 | Cualquier `4769` a `svc_sql`. Determinista. | Ninguno: la cuenta es señuelo, sin uso legítimo. | TP inmediato. Capturar `ipAddress` origen y escalar. |
| 100111 (10) Kerberoasting RC4 | T1558.003 | `4769` con `ticketEncryptionType=0x17` desde cuenta de usuario, correlacionado con 100110. | Excluye cuentas de equipo (`$`). RC4 es evadible (mito del RC4): por sí solo, señal débil. | Correlacionar con 100110/AD. Solo escalar si hay más señal. |
| 100120 (12) PowerShell ofuscado | T1059.001 / T1027 | `scriptBlockText` con `FromBase64String`/`IEX`/`DownloadString`/`Net.WebClient`/`-EncodedCommand` por usuario no-admin. | PS-remoting de admin con cmdlets legítimos (baseline). | Leer el scriptBlockText. Si actor != admin -> TP. |
| 100130 (12) Tamper de Defender | T1562.001 | `commandLine` con `Add-MpPreference -ExclusionPath`/`DisableRealtimeMonitoring`/`Set-MpPreference`. | Endurecimiento/exclusiones legítimas hechas por admin documentadas. | Verificar actor y cambio en `Get-MpPreference`. TP si no autorizado. |
| 100140 (12) AS-REP Roasting | T1558.004 | `4768` con `preAuthType=0` hacia `a.garcia` (señuelo DoesNotRequirePreAuth). | Aún sin disparo real; requiere Rubeus/impacket. | TP si toca el señuelo `a.garcia`. Capturar origen. |
| 100150 (10) certutil | T1105 | `commandLine` con certutil + `-urlcache`/`/urlcache`/`-verifyctl`/`-split`. | Uso administrativo legítimo de certutil (gestión de certs). | Revisar linaje + correlacionar con Defender (Ceprolad.A). |
| 100151 (10) bitsadmin /transfer | T1105 | `bitsadmin /transfer` descargando payload. | Tareas BITS legítimas (poco habituales en el lab). | Revisar destino/origen del transfer. |
| 100152 (10) mshta + http | T1105 | `mshta` invocando URL http. | mshta legítimo es raro; tratar con sospecha. | Revisar URL y parentImage. |
| 100160 (12) Defender DETECCIÓN | (EID 1116) | EID 1116 en canal Defender Operational con `"threat Name"`. | Ninguno: el EDR ya detectó algo. Pivote de caza. | TP/pivote. Buscar el proceso/cuenta origen. |
| 100161 (10) Defender ACCIÓN | (EID 1117) | EID 1117 (bloqueo/cuarentena) con `"action Name"`. | El bloqueo ya mitigó; confirma defensa en profundidad. | Confirmar acción exitosa; documentar IoC; investigar causa raíz. |
| 100170 (cand., 7045) | T1543.003 | `7045` con `imagePath` sospechoso (ruta temporal, sin firma). | Reinstalación de Sysmon u otros servicios legítimos (baseline). | Contrastar `imagePath`/hash con baseline antes de escalar. |

## 5. Criterio de escalado a IR (Proyecto 4)

Escalar a Respuesta a Incidentes (PICERL) y hacer el handoff cuando se cumpla **cualquiera**:

- **TP confirmado de nivel 12** (100110, 100120, 100130, 100140, 100160) que NO sea baseline.
- **Honeypot tocado** (100110 a `svc_sql` o 100140 a `a.garcia`): siempre escala; indica reconocimiento/ataque activo dirigido a credenciales.
- **Detección del EDR (100160/1116)** con amenaza confirmada en el endpoint (`Get-MpThreat`), p. ej. `Trojan:Win32/Ceprolad.A`.
- **Correlación de varias reglas** sobre el mismo actor/host en ventana corta (p. ej. 100150 certutil -> 100160 detección Defender -> 100120 PS ofuscado): cadena de ataque.
- **Compromiso de CORP\Administrator** o cualquier cuenta privilegiada que NO encaje con el baseline.

NO escalar (cerrar con justificación) cuando:
- FP por baseline confirmado (actor admin + linaje coherente + tarea documentada).
- 100161 (acción de Defender) en la que el bloqueo/cuarentena fue exitoso y la causa raíz ya está identificada y contenida por el propio EDR, sin señal adicional.

Handoff a IR (paquete mínimo que entrega el analista de triage):
1. ID de regla, nivel, severidad SOC y veredicto (TP).
2. Actor (`targetUserName`), host afectado, timestamp y origen (`ipAddress`).
3. Linaje de proceso (Sysmon EID 1 `parentImage` + hash SHA256) e histórico relevante de 4688.
4. Estado del endpoint (`Get-MpComputerStatus` / `Get-MpThreat`).
5. IoC para enriquecimiento externo (plantilla de lookup: hash, IP, dominio), marcados como pendientes.
6. Caso abierto por la Active Response (nivel >= 12) o ticket creado manualmente (nivel 10 escalado), con la cadena de correlación documentada.

A partir de aquí, la contención (Contain), erradicación (Eradicate), recuperación (Recover) y lecciones aprendidas (Lessons) se ejecutan en el Proyecto 4.