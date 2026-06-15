# Informe de Incident Response — Ransomware simulado en WIN11 (corp.local)

> **EJERCICIO BENIGNO Y CONTENIDO.** El 2026-06-15 (19:21–19:50 UTC) se simuló en `WIN11` (10.10.10.21) una cadena de intrusión Kerberoasting → ejecución → evasión → ingress → "impacto ransomware" (solo renombrado de 6 ficheros dummy a `*.locked`, **sin cifrado real**). Severidad nominal: **Alta** (T1486 / Impact). Estado: **CONTENIDO y CERRADO**. Cinco de seis etapas detectadas por Wazuh + Defender; la etapa de impacto no disparó ninguna regla (gap documentado).

---

## Resumen ejecutivo (para dirección, sin jerga)

El 15 de junio de 2026 se ejecutó, de forma planificada y totalmente controlada, un simulacro de ataque tipo *ransomware* contra un equipo de pruebas (`WIN11`) dentro de un laboratorio **aislado de internet**. El objetivo era comprobar si las defensas y los procedimientos del SOC funcionan de principio a fin ante un incidente realista.

**Qué pasó:** un atacante simulado pidió un ticket de una credencial señuelo, ejecutó comandos ocultos, intentó añadir una exclusión al antivirus, descargó un fichero de prueba con `certutil` y finalmente "secuestró" 6 ficheros de prueba. **Nada fue real ni destructivo:** no hubo cifrado, la URL de descarga era **local**, la exclusión del antivirus se revirtió en el acto, no se borraron copias de seguridad (shadow copies) y no hubo propagación a otros equipos.

**Qué funcionó bien:**
- El sistema de monitorización (Wazuh) **detectó 5 de las 6 fases** del ataque casi en tiempo real.
- El antivirus (Microsoft Defender) **detectó y bloqueó por su cuenta** la descarga con `certutil`.
- El SOC **abrió los casos de investigación automáticamente**, sin esperar a un analista.

**Qué hay que mejorar:**
- La fase final (el "secuestro" de ficheros) **no generó ninguna alerta**. En un ataque real con herramientas a medida, el cifrado se habría completado sin aviso. Esta es la principal lección y ya tiene una acción correctiva asignada.
- Una cuenta de servicio señuelo (plantada a propósito) tenía contraseña débil y cifrado obsoleto (RC4); se endurece.

**Resultado:** incidente contenido y cerrado el mismo día. El equipo se restauró a un estado limpio conocido (checkpoint Hyper-V). El ejercicio cumplió su objetivo: validó las defensas y reveló un punto ciego concreto y corregible.

---

## 0. Preparación (Prepare)

El SOC llegó al incidente con tres proyectos previos del portfolio ya operativos. Esto es lo que estaba listo *antes* de que ocurriera nada:

- **Detecciones (Proyecto 3 — reglas Wazuh `100110`–`100161`):** firmas a medida para Kerberoasting, PowerShell ofuscado, manipulación de Defender, transferencia de herramientas vía `certutil` y eventos del propio EDR. Cada técnica de la cadena tenía su regla **salvo la de impacto (T1486)**.
- **Baseline de caza (Proyecto 2):** inventario *known-good* del endpoint y del dominio para distinguir rápido lo anómalo de lo normal durante el triaje.
- **Playbook + Active Response (Proyecto 1):**
  - Runbooks por regla: `RB-100110` (Kerberoasting), `RB-100120` (ejecución), `RB-100130` (evasión), `RB-100150` (ingress), `RB-100160` (EDR).
  - Active Response **`open-soc-case`** (lado-manager, grupo `soc_lab`): **abre un caso automáticamente por cada detección**, escribiendo un registro JSON en el casebook `/var/ossec/logs/soc-cases.log` (campos: `case`, `opened`, `rule`, `level`, `agent`, `mitre`, `status=NEW`, `description`, `alert_ts`).
- **Señuelos (honeypots) en AD:**
  - `svc_sql` — SPN `MSSQLSvc/sql01.corp.local:1433`, **RC4 habilitado**, contraseña débil `Summer2024!` (cebo de Kerberoasting).
  - `a.garcia` — flag `DONT_REQ_PREAUTH` (cebo de AS-REP Roasting).
- **Capacidad de respuesta:** acceso por **PowerShell Direct** desde el host Hyper-V, control de red de `LAB-Net`, y un **checkpoint Hyper-V `pre-wazuh-agent_20260615`** de `WIN11` como punto de restauración limpio.

Este Proyecto 4 toma el caso ya triado que entrega el Proyecto 1 y ejecuta el ciclo IR completo (metodología **PICERL**).

---

## 1. Identificación (Identify)

**Primer indicador (19:21:39 UTC).** El analista no recibió primero una alerta suelta, sino un **caso ya abierto** en el casebook. El Active Response `open-soc-case` reaccionó a la regla **`100110` (nivel 12, Kerberoasting)** y escribió un caso JSON `CASE-…-100110` con `status=NEW`, mismo timestamp que la alerta. Telemetría de origen: emisión de un TGS para el SPN del señuelo `svc_sql` en `DC01`.

**Lo que vio el analista al entrar al casebook**, en cascada y en cuestión de ~30 segundos a partir de las 19:50:08:

```bash
# Casos abiertos automáticamente por el AR (uno por detección)
sudo jq -c 'select(.status=="NEW")' /var/ossec/logs/soc-cases.log

# Resumen rápido: timestamp, caso, regla, nivel, MITRE y descripción
sudo jq -r '[.alert_ts, .case, .rule, .level, .mitre, .description] | @tsv' \
  /var/ossec/logs/soc-cases.log | sort
```

Señales convergentes desde tres fuentes independientes:
1. **Wazuh** — alertas `100110`/`100120`/`100130`/`100150`/`100160`/`100161` en ráfaga.
2. **Active Response** — un caso `CASE-…` por cada una de esas reglas, sin intervención humana.
3. **Microsoft Defender** — detección propia (EID 1116) y bloqueo/cuarentena (EID 1117) sobre el `certutil`.

Conclusión de la fase: cadena de intrusión activa en `WIN11`, con actividad de Credential Access en `DC01` (señuelo) y un patrón de progresión Execution → Defense Evasion → Ingress → **(impacto sospechado)**. Se eleva a incidente y se pasa a Análisis.

---

## 2. Análisis (Analyze)

### 2.1 Reconstrucción de la cadena de ataque

| # | Hora UTC | Táctica | Técnica ATT&CK | Acción observada | Detección |
|---|----------|---------|----------------|------------------|-----------|
| 1 | 19:21:39 | Credential Access | **T1558.003** Kerberoasting | TGS del señuelo `svc_sql` (SPN `MSSQLSvc/sql01.corp.local:1433`) en `DC01` | Regla **100110** (n12) → caso |
| 2 | 19:50:08 | Execution | **T1059.001 / T1027** | PowerShell `-EncodedCommand` → `IEX "Write-Output 'IR-SIM-EXEC-MARKER'"` | Regla **100120** (n12) → caso |
| 3 | 19:50:08 | Defense Evasion | **T1562.001** | `Add-MpPreference -ExclusionPath C:\soc-ir-sim` (revertido en el acto) | Regla **100130** (n12) → caso |
| 4 | 19:50:09–14 | Ingress Tool Transfer | **T1105** | `certutil -urlcache -f http://127.0.0.1/ir-sim-payload` | Regla **100150** (n10) → caso (x2) |
| 5 | 19:50:19 | EDR (detección) | (cobertura T1105) | Defender detecta el `certutil` = `Trojan:Win32/Ceprolad.A` (ThreatID 2147726914), EID **1116** | Regla **100160** (n12) → caso |
| 6 | 19:50:32 | EDR (respuesta) | (cobertura T1105) | Defender **bloquea/pone en cuarentena**, EID **1117** | Regla **100161** (n10) → caso |
| 7 | ~19:50:35 | **Impact** | **T1486** Data Encrypted for Impact | 6 ficheros dummy → `*.locked` + nota `RECOVER-FILES.txt` (marcada SIMULACIÓN) en `C:\soc-ir-sim\victim-data` | **NINGUNA** (ni regla Wazuh ni Defender) |

### 2.2 Alcance

- **Host afectado:** `WIN11` (10.10.10.21), endpoint único. **Sin propagación** a otros equipos.
- **Dominio:** la actividad en `DC01` (10.10.10.10) se limitó a la emisión de un TGS para un **SPN señuelo** (`svc_sql`); no hubo compromiso de cuentas reales ni de `CORP\Administrator`.
- **Datos:** únicamente **6 ficheros DUMMY** en el sandbox `C:\soc-ir-sim\victim-data`. **Sin cifrado real, sin borrado de shadow copies, sin exfiltración.**
- **Ventana del incidente:** 19:21:39 → ~19:50:35 UTC, con la fase de host condensada en ~27 s (19:50:08–19:50:35).

### 2.3 Causa raíz (del ejercicio)

El ejercicio se inició deliberadamente. En términos de superficie de ataque, la cadena explotó dos debilidades plantadas a propósito: una **cuenta de servicio con SPN, RC4 y contraseña débil** (`svc_sql`), kerberoasteable offline, y la capacidad de ejecutar **LOLBins** (`powershell`, `certutil`) en el endpoint. La causa raíz de la *única fase no detectada* fue la **ausencia de una regla conductual para T1486**.

### 2.4 Defensa en profundidad: el `certutil`

La etapa de Ingress (paso 4) disparó **dos controles independientes sobre el mismo evento**:
- **Regla propia `100150`** — basada en Windows Security **4688** (creación de proceso) + `commandLine`.
- **EDR Microsoft Defender** — detección `100160`/`100161` que además **lo bloqueó y puso en cuarentena**.

Si una capa hubiera fallado (p. ej. el atacante evade la firma de `certutil`), la otra habría cubierto el hueco. Esto es exactamente el comportamiento buscado de *defense in depth*.

### 2.5 El GAP: impacto (T1486) sin detección

Las fases tempranas (execution → evasion → ingress) se detectaron, y Defender **frenó el `certutil`** porque es un LOLBin con firma conocida (`Ceprolad.A`). Pero la **fase de impacto** (renombrado masivo a `*.locked` + nota de rescate) **no disparó ninguna regla Wazuh ni alerta de Defender**.

**Implicación crítica:** en un ataque real con un **binario de cifrado propio** (no un LOLBin ya catalogado por Defender), todas las capas previas podrían haber sido sorteadas y **el cifrado se habría completado sin una sola alerta**. La detección actual depende demasiado de firmas conocidas y de las fases *previas* al impacto; falta una red de seguridad **conductual** en la propia fase de impacto.

---

## 3. Contención (Contain)

Prioridad: **cortar la propagación y el impacto** antes de erradicar. Acciones proporcionadas (un endpoint, sin propagación confirmada), ejecutadas desde el host Hyper-V por PowerShell Direct y en `DC01`.

**3.1 Aislar `WIN11` de la red (LAB-Net).**
```powershell
# Desde el host Hyper-V: cortar la NIC del endpoint comprometido
Disconnect-VMNetworkAdapter -VMName "WIN11"
# Verificar el estado del adaptador (debe quedar sin conexión al switch)
Get-VMNetworkAdapter -VMName "WIN11" | Select-Object VMName, SwitchName, Status, Connected
```

**3.2 Deshabilitar la cuenta implicada (en `DC01`).** El señuelo `svc_sql` fue el objeto del Kerberoasting; se deshabilita preventivamente hasta erradicar/rotar. `a.garcia` (cebo AS-REP) se revisa por higiene aunque no participó en esta cadena.
```powershell
# En DC01 (o vía PowerShell Direct contra DC01)
Disable-ADAccount -Identity svc_sql
Get-ADUser svc_sql -Properties Enabled,ServicePrincipalNames,msDS-SupportedEncryptionTypes |
  Select-Object Name,Enabled,ServicePrincipalNames,msDS-SupportedEncryptionTypes
```

**3.3 Congelar evidencia (antes de tocar el endpoint).** Crear un checkpoint *post-incidente* para preservar el estado y copiar el casebook del manager Wazuh (10.10.10.20).
```powershell
# Snapshot forense del estado comprometido (NO revertir todavía)
Checkpoint-VM -Name "WIN11" -SnapshotName "post-incident_20260615_T1486"
```
```bash
# Preservar el casebook del manager Wazuh (10.10.10.20)
sudo cp -a /var/ossec/logs/soc-cases.log \
  /var/ossec/logs/soc-cases_20260615_post-incident.log
```

**Estado tras contención:** `WIN11` aislado, `svc_sql` deshabilitada, evidencia congelada. El "impacto" ya se había producido sobre datos dummy, pero no había nada que propagar.

---

## 4. Erradicación (Eradicate)

Objetivo: eliminar tooling/artefactos, revertir cambios de configuración y cerrar la debilidad explotada.

**4.1 Revertir la exclusión de Defender** (la evasión `T1562.001`; ya revertida en el acto durante el ejercicio, se confirma idempotente).
```powershell
# Vía PowerShell Direct contra WIN11
Remove-MpPreference -ExclusionPath "C:\soc-ir-sim"
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath   # debe NO listar C:\soc-ir-sim
```

**4.2 Confirmar la cuarentena del payload** (el `certutil` / `Ceprolad.A`).
```powershell
Get-MpThreat                                          # historial de amenazas detectadas
Get-MpThreatDetection |
  Where-Object { $_.ThreatID -eq 2147726914 } |
  Select-Object ThreatID, ActionSuccess, ProcessName, Resources
```

**4.3 Eliminar tooling y artefactos del ejercicio en el endpoint** (sandbox, payload descargado, marcadores). Persistencia: no se instaló ninguna; aun así se valida.
```powershell
# Eliminar el sandbox del ejercicio y artefactos del payload
Remove-Item -Path "C:\soc-ir-sim" -Recurse -Force -ErrorAction SilentlyContinue
# Revisar tareas programadas fuera de Microsoft por persistencia (esperado: nada del ejercicio)
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
  Select-Object TaskName, TaskPath, State
```

**4.4 Resetear el señuelo `svc_sql` por su contraseña débil** (cierra el vector de Kerberoasting offline; rotación de credencial).
```powershell
# En DC01: nueva contraseña fuerte y aleatoria
Add-Type -AssemblyName System.Web
$pw = [System.Web.Security.Membership]::GeneratePassword(32,8)
Set-ADAccountPassword -Identity svc_sql -Reset `
  -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force)
```

**Estado tras erradicación:** exclusión revertida, payload en cuarentena confirmada, artefactos eliminados, credencial del señuelo rotada. (El endurecimiento de cifrado/gMSA se aborda en Lecciones aprendidas.)

---

## 5. Recuperación (Recover)

Objetivo: devolver el entorno a un estado **limpio conocido** y validar que no queda actividad maliciosa.

> Nota de orden: como vía maestra de recuperación se restaura `WIN11` desde el checkpoint limpio (5.2), lo que devuelve el endpoint a un estado pre-incidente verificado. La reversión manual del renombrado (5.1) solo aplica si se necesita preservar/recuperar los ficheros dummy *antes* de revertir; en un caso real, aquí entraría la restauración desde backup/Volume Shadow Copy.

**5.1 Restaurar los ficheros `*.locked` (opcional, solo si no se revierte por checkpoint).** Como no hubo cifrado real (solo renombrado), la "recuperación" es revertir la extensión en el sandbox.
```powershell
# Revertir el renombrado simulado en el sandbox (si no se ha purgado aún)
Get-ChildItem "C:\soc-ir-sim\victim-data\*.locked" | ForEach-Object {
    Rename-Item $_.FullName ($_.FullName -replace '\.locked$','')
}
Remove-Item "C:\soc-ir-sim\victim-data\RECOVER-FILES.txt" -ErrorAction SilentlyContinue
```

**5.2 Restaurar `WIN11` desde el checkpoint limpio** (vía maestra: vuelve el endpoint a un estado pre-incidente verificado, eliminando cualquier resto).
```powershell
# Desde el host Hyper-V: revertir al checkpoint limpio conocido
Restore-VMSnapshot -VMName "WIN11" -Name "pre-wazuh-agent_20260615" -Confirm:$false
```

**5.3 Resetear credenciales** (cierre del vector). Confirmar la rotación de `svc_sql` (hecha en Erradicación) y, por higiene del ejercicio, rotar la cuenta local del endpoint `WIN11\labadmin`.
```powershell
# Reset de la cuenta local del endpoint tras restaurar (vía PowerShell Direct contra WIN11)
Add-Type -AssemblyName System.Web
$np = ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(24,6)) -AsPlainText -Force
Set-LocalUser -Name "labadmin" -Password $np
```

**5.4 Reconectar y reactivar.** Reincorporar `WIN11` a `LAB-Net` y reactivar el señuelo solo si el ejercicio lo requiere (con su nueva contraseña y cifrado endurecido).
```powershell
# Desde el host Hyper-V
Connect-VMNetworkAdapter -VMName "WIN11" -SwitchName "LAB-Net"
# En DC01, si procede reactivar el honeypot
Enable-ADAccount -Identity svc_sql
```

**5.5 Validar limpieza (Defender + estado).**
```powershell
# Estado general del motor y firmas
Get-MpComputerStatus |
  Select-Object AMRunningMode, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, QuickScanAge
# Escaneo de confirmación
Start-MpScan -ScanType FullScan
Get-MpThreat   # esperado: sin amenazas activas tras la restauración
```

**Estado tras recuperación:** `WIN11` restaurado a checkpoint limpio, ficheros revertidos, credenciales rotadas, Defender activo y verificado, agente Wazuh operativo. Entorno listo para nuevos ejercicios.

---

## 6. Lecciones aprendidas (Lessons learned)

### Qué funcionó
- **El Active Response abrió los casos solo.** Cada detección generó un caso JSON en `/var/ossec/logs/soc-cases.log` con el mismo timestamp que la alerta, sin esperar a un analista. El SOC arrancó el IR con el caso ya triado.
- **Defensa en profundidad real.** La etapa `certutil` (T1105) activó **dos controles independientes** (regla propia `100150` sobre Security 4688 + EDR Defender `100160`/`100161`), y **Defender la detectó y bloqueó por sí mismo**. Una capa habría cubierto a la otra.
- **Cobertura amplia de la cadena.** 5 de 6 fases detectadas en tiempo casi real, con runbooks ya asociados a cada regla.

### Qué falló — y acciones correctivas
1. **GAP crítico: el impacto (T1486) no disparó nada.** El renombrado masivo + nota de rescate pasó invisible para Wazuh y Defender.
   - **Acción → nueva regla conductual `100180` (candidata):**
     - **Extensión homogénea masiva** en ventana corta (muchos ficheros renombrados a una misma extensión nueva, p. ej. `*.locked`).
     - **Notas de rescate** por patrón de nombre (`*RECOVER*`, `*DECRYPT*`, `*RANSOM*`, `*RESTORE*`).
     - **Inhibición de recuperación (T1490):** ejecución de `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set {default} recoveryenabled no`.
   - Esta regla no depende de firmas: detectaría el caso del **binario propio** que hoy se nos escaparía.
2. **Cuenta de servicio débil (`svc_sql`): RC4 + `Summer2024!`.** Kerberoasteable offline.
   - **Acción → hardening:** forzar **AES-only** (`msDS-SupportedEncryptionTypes`), valorar migrar a **gMSA** (rotación automática de contraseña), eliminar el SPN si no es necesario.
   ```powershell
   # En DC01: forzar AES128/AES256 y deshabilitar RC4 en la cuenta de servicio (valor 24 = 0x18)
   Set-ADUser -Identity svc_sql -Replace @{ "msDS-SupportedEncryptionTypes" = 24 }
   ```
3. **Dependencia de firmas conocidas.** Defender frenó el `certutil` porque es un LOLBin catalogado; un binario nuevo no se habría detectado igual. Refuerza la prioridad de la regla conductual `100180`.

### Cierre del ciclo IR → detección
Este incidente alimenta de vuelta al **Proyecto 3 (detecciones)**: el gap T1486 se convierte en la regla `100180`, con su correspondiente runbook `RB-100180` en el **Proyecto 1 (playbook)**, y se actualiza el **baseline (Proyecto 2)** con la extensión `.locked` y los patrones de nota de rescate como anomalías. El ciclo se valida re-ejecutando este mismo ejercicio (debe disparar `100180`).

---

## Indicadores (IoCs) y mapeo MITRE ATT&CK

> **Nota:** todos los IoCs proceden de un **ejercicio benigno y contenido**. El payload nunca se ejecutó como malware real, la URL era **local** (`127.0.0.1`) y el "ransomware" solo renombró ficheros dummy.

### IoCs del ejercicio

| Tipo | Indicador | Contexto |
|------|-----------|----------|
| Host | `WIN11` / 10.10.10.21 | Endpoint víctima (simulado) |
| Cuenta señuelo | `svc_sql` (SPN `MSSQLSvc/sql01.corp.local:1433`) | Objeto del Kerberoasting |
| Cuenta señuelo | `a.garcia` (`DONT_REQ_PREAUTH`) | Cebo AS-REP Roasting (no usado en esta cadena) |
| Ruta sandbox | `C:\soc-ir-sim\victim-data` | Datos dummy "secuestrados" |
| Ruta exclusión | `C:\soc-ir-sim` (Add-MpPreference, revertida) | Evasión de Defender |
| Marcador | `IR-SIM-EXEC-MARKER` (salida del PowerShell codificado) | Ejecución simulada |
| URL | `http://127.0.0.1/ir-sim-payload` | Ingress local (certutil) |
| Comando | `certutil -urlcache -f http://127.0.0.1/ir-sim-payload` | LOLBin de descarga |
| Detección EDR | `Trojan:Win32/Ceprolad.A`, ThreatID **2147726914** | Veredicto de Defender sobre el certutil |
| EventIDs Defender | **1116** (detección), **1117** (bloqueo/cuarentena) | Microsoft-Windows-Windows Defender/Operational |
| Extensión | `*.locked` | Renombrado de impacto (simulado) |
| Nota de rescate | `RECOVER-FILES.txt` (marcada SIMULACIÓN) | Artefacto de impacto |
| Casebook | `/var/ossec/logs/soc-cases.log` | Casos JSON abiertos por el AR (manager 10.10.10.20) |
| Reglas Wazuh | `100110`, `100120`, `100130`, `100150`, `100160`, `100161` | Detecciones de la cadena |

### Técnicas MITRE ATT&CK

| Táctica | Técnica | Etapa en este incidente | Detectado |
|---------|---------|--------------------------|-----------|
| Credential Access | **T1558.003** — Kerberoasting | TGS de `svc_sql` en `DC01` (19:21:39) | Sí — `100110` |
| Execution | **T1059.001** — PowerShell | `-EncodedCommand` → IEX (19:50:08) | Sí — `100120` |
| Defense Evasion | **T1027** — Obfuscated Files or Information | Comando codificado en Base64 | Sí — `100120` |
| Defense Evasion | **T1562.001** — Impair Defenses: Disable/Modify Tools | `Add-MpPreference -ExclusionPath` (19:50:08, revertido) | Sí — `100130` |
| Command & Control | **T1105** — Ingress Tool Transfer | `certutil` desde URL local (19:50:09–14) | Sí — `100150` + Defender `100160`/`100161` |
| Impact | **T1486** — Data Encrypted for Impact | Renombrado a `*.locked` + nota (~19:50:35) | **No — GAP** → regla candidata `100180` |
| *(correctiva)* | **T1490** — Inhibit System Recovery | No ejecutado (sin borrado de shadow copies) | Incluido en `100180` como detección preventiva |

---

*Ejercicio benigno y contenido — corp.local LAB-Net (aislado, sin internet). Sin cifrado real, sin borrado de copias de seguridad, sin propagación. Metodología PICERL. Caso de referencia: repo "Threat Hunting on my own PC" (incidente Lumma).*