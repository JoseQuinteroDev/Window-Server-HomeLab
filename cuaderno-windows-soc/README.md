# 🪟 Cuaderno de Comandos Windows para Analista SOC

> **Autor:** José Quintero · **Fase 0.A** del [portfolio Blue Team](../ROADMAP.md)
> **Qué es:** un cuaderno de **triage en vivo de un endpoint Windows** usando solo herramientas **nativas** (sin EDR). Cada bloque trae: el comando, **qué buscar**, y **cómo se ve un compromiso real**.
> **Por qué importa:** en un SOC, antes (o además) del EDR, hay que saber interrogar la máquina a mano. Esto es lo primero que se hace en un triage y en un Incident Response.

---

## 🎯 Cómo usar este cuaderno

- Abre una **PowerShell como Administrador** (varias consultas requieren privilegios).
- Practica cada bloque en tu propio equipo y, más adelante, en `WIN11` del [laboratorio](../LAB-BUILD.md).
- Datos **sanitizados**: el host de ejemplo es `WORKSTATION`, el usuario `<user>`.
- 🔴 = señal de posible compromiso · 🟢 = línea base normal.

> **Conexión con un caso real:** este cuaderno está informado por un incidente real de malware (un *loader* tipo Lumma ejecutado vía EAs crackeados) en el que el atacante **añadió exclusiones a Microsoft Defender** para sobrevivir. Por eso la sección de Defender es central: revisar exclusiones que **no pusiste tú** es exactamente lo que falló detectar a tiempo.

---

## 1. 🧠 Procesos — ¿qué se está ejecutando y quién lo lanzó?

| Comando | Para qué |
|---|---|
| `tasklist /v` | Lista procesos con usuario y título de ventana |
| `tasklist /svc` | Qué **servicios** corre cada `svchost.exe` |
| `Get-Process \| Sort-Object CPU -Descending \| Select -First 15` | Top por CPU |
| `Get-CimInstance Win32_Process \| Select ProcessId,ParentProcessId,Name,CommandLine` | ⭐ **PID, PID padre y LÍNEA DE COMANDOS** — lo más valioso |

**Investigar un proceso concreto (PID → padre → imagen → firma):**
```powershell
$pid = 1234
Get-CimInstance Win32_Process -Filter "ProcessId=$pid" |
  Select ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath
# ¿Quién es el padre?
$ppid = (Get-CimInstance Win32_Process -Filter "ProcessId=$pid").ParentProcessId
Get-CimInstance Win32_Process -Filter "ProcessId=$ppid" | Select ProcessId,Name,CommandLine
# ¿Está firmado el binario?  (un binario de sistema SIN firma válida es banderazo)
Get-AuthenticodeSignature (Get-Process -Id $pid).Path | Select Status, SignerCertificate
```

**Matar un proceso malicioso:**
```powershell
Stop-Process -Id $pid -Force        # PowerShell
taskkill /PID 1234 /T /F            # cmd (/T mata también hijos)
```

**🔴 Qué delata un compromiso:**
- Procesos lanzados desde **`%TEMP%`, `%APPDATA%`, `\Users\Public\`, `\ProgramData\`** → ruta típica de malware.
- **Nombres que imitan** legítimos: `svch0st.exe`, `scvhost.exe`, o `svchost.exe` ejecutándose **fuera de `C:\Windows\System32`**.
- **Cadena de padres anómala** (MITRE **T1059**): `winword.exe`/`excel.exe`/`outlook.exe` → `cmd.exe`/`powershell.exe` (macro maliciosa); `services.exe` no es el padre de un `svchost` que debería serlo.
- **PowerShell con línea de comandos ofuscada**: `-enc <base64>`, `-w hidden`, `-nop`, `IEX (New-Object Net.WebClient).DownloadString(...)`.
- Binario de sistema **sin firma** o firmado por un editor desconocido.

---

## 2. 🌐 Red — conexiones y posible C2

| Comando | Para qué |
|---|---|
| `netstat -ano` | Conexiones + PID (cmd) |
| `netstat -anob` | + el **ejecutable** (requiere admin) |
| `Get-NetTCPConnection -State Established` | Conexiones TCP establecidas (PowerShell) |
| `Get-DnsClientCache` / `ipconfig /displaydns` | Dominios resueltos recientemente |

**Mapear conexión ↔ PID ↔ proceso (lo que de verdad quieres ver):**
```powershell
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,
    @{N='Proceso';E={ (Get-Process -Id $_.OwningProcess).ProcessName }},
    @{N='Ruta';E={ (Get-Process -Id $_.OwningProcess).Path }} |
  Sort-Object RemoteAddress | Format-Table -AutoSize
```

**🔴 Qué delata un C2 (command & control):**
- Conexiones salientes desde **procesos de usuario raros** (un `notepad.exe` o algo en `%TEMP%` hablando a Internet).
- **Beaconing**: conexiones repetidas y regulares a la misma IP/puerto (cada X segundos).
- Puertos no estándar para "web" (4444, 8080, 8443, 1337…) o IPs sin reverse-DNS.
- **LOLBins con red** (MITRE **T1105**): `certutil -urlcache -f http://...`, `bitsadmin /transfer`, `mshta http://...`, `powershell ... DownloadString`.
- Dominios recién registrados / DGA en la caché DNS.

---

## 3. 🔒 Persistencia — ¿cómo sobrevive al reinicio?

**Tareas programadas** (MITRE **T1053.005**):
```powershell
Get-ScheduledTask | Where-Object State -ne 'Disabled' |
  Select TaskName, TaskPath, State
# Detalle + acción que ejecuta:
Get-ScheduledTask -TaskName "<nombre>" | Select -ExpandProperty Actions
schtasks /query /fo LIST /v          # versión cmd, muy detallada
```

**Claves Run del registro** (MITRE **T1547.001**):
```powershell
$rk = @(
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
$rk | ForEach-Object { "`n== $_ =="; Get-ItemProperty $_ -ErrorAction SilentlyContinue }
```

**Servicios** (MITRE **T1543.003**):
```powershell
Get-CimInstance Win32_Service |
  Select Name, State, StartMode, StartName, PathName |
  Where-Object { $_.PathName -notmatch 'C:\\Windows' } | Format-Table -AutoSize
sc query                              # estado rápido (cmd)
```

**Carpetas de inicio** y **WMI**:
```powershell
explorer "shell:startup"; explorer "shell:common startup"
# Persistencia WMI (MITRE T1546.003) — sigilosa, mírala siempre:
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

**🔴 Qué delata persistencia maliciosa:**
- Tareas/servicios/Run apuntando a **scripts en `%TEMP%`/`%APPDATA%`** o a `powershell -enc ...`.
- Servicios con **`PathName` fuera de `C:\Windows`** o con ruta **sin comillas** (unquoted service path).
- **Suscripciones WMI** que tú no creaste (casi siempre = malware).
- Entradas Run con nombres genéricos ("Update", "Adobe", "Microsoft") que lanzan binarios en rutas de usuario.

---

## 4. 🛡️ Microsoft Defender — estado y EXCLUSIONES

> ⭐ **Sección clave** (y la lección de tu incidente real): el malware suele **desactivar protección** o **añadir exclusiones** para que Defender ignore su carpeta/proceso (MITRE **T1562.001 — Impair Defenses**).

```powershell
Get-MpComputerStatus | Select RealTimeProtectionEnabled, AntivirusEnabled,
  IsTamperProtected, AMServiceEnabled, BehaviorMonitorEnabled, NISEnabled
```
**Revisar EXCLUSIONES (¿las pusiste tú?):**
```powershell
Get-MpPreference | Select -ExpandProperty ExclusionPath
Get-MpPreference | Select -ExpandProperty ExclusionProcess
Get-MpPreference | Select -ExpandProperty ExclusionExtension
```
**Amenazas detectadas + historial:**
```powershell
Get-MpThreat
Get-MpThreatDetection | Select ThreatID, InitialDetectionTime, ProcessName, Resources
```
**Quitar una exclusión maliciosa** (lo que quedó pendiente tras tu incidente):
```powershell
Remove-MpPreference -ExclusionPath 'C:\ruta\que\no\reconozco'
Remove-MpPreference -ExclusionProcess 'proceso_sospechoso.exe'
```

**🔴 Qué delata sabotaje de Defender:**
- `RealTimeProtectionEnabled = False` o `IsTamperProtected = False` sin que tú lo tocaras.
- **Exclusiones de rutas/procesos que no reconoces** → 🔴🔴 bandera roja clásica.
- Detecciones recientes en `Get-MpThreat` cuya carpeta coincide con una exclusión (el atacante se auto-excluyó).

---

## 5. 📜 Logs y eventos — la memoria del sistema

> Sin auditoría activa no hay telemetría (eso lo enciendes por GPO en la [FASE 4 del lab](../LAB-BUILD.md)). Aquí, cómo **leerla**.

```powershell
# Últimos eventos de seguridad
Get-WinEvent -LogName Security -MaxEvents 50
# Filtrar por ID (mucho más rápido con FilterHashtable):
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688 } -MaxEvents 20 |
  Select TimeCreated, @{N='Msg';E={ $_.Message.Split("`n")[0] }}
# Equivalente en cmd:
wevtutil qe Security /c:5 /rd:true /f:text
```

**Eventos que todo analista debe reconocer:**

| ID | Log | Significado | Por qué importa |
|---|---|---|---|
| **4624** | Security | Inicio de sesión correcto | Logon Type 3 (red), 10 (RDP), 9 (RunAs) |
| **4625** | Security | Inicio de sesión **fallido** | 🔴 muchos seguidos = fuerza bruta / password spray |
| **4688** | Security | **Creación de proceso** (+ línea de comandos si está la GPO) | El "qué se ejecutó" — base del threat hunting |
| **7045** | System | **Servicio nuevo instalado** | 🔴 servicio raro = persistencia / herramienta lateral |
| **4720** | Security | **Usuario creado** | 🔴 cuenta nueva no autorizada |
| **4104** | PowerShell/Operational | **Script Block Logging** | 🔴 base64/IEX/descargas → PowerShell malicioso |
| **1102** | Security | **Registro de auditoría BORRADO** | 🔴🔴 anti-forense (MITRE **T1070.001**) |

```powershell
# PowerShell sospechoso (script block):
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104 } -MaxEvents 30 |
  Where-Object { $_.Message -match 'IEX|FromBase64|DownloadString|-enc' }
```

---

## 6. 👤 Usuarios y permisos — ¿quién tiene acceso?

```powershell
net user                              # cuentas locales
net localgroup administrators         # ⭐ ¿quién es admin local?
Get-LocalUser | Select Name, Enabled, LastLogon
Get-LocalGroupMember Administrators
whoami /priv                          # privilegios de MI sesión
whoami /groups                        # grupos (incl. integridad)
query user                            # sesiones interactivas/RDP activas
```

**🔴 Qué delata abuso de cuentas:**
- **Cuentas nuevas** (correlaciona con evento **4720**) o cuentas deshabilitadas que aparecen **habilitadas**.
- Un usuario **inesperado dentro de `Administrators`** (MITRE **T1136 / T1078**).
- Cuenta `Guest` habilitada; privilegios sensibles (`SeDebugPrivilege`, `SeBackupPrivilege`) en cuentas que no deberían tenerlos.

---

## 7. 🧪 Mini-ejercicio: triage de un proceso sospechoso de punta a punta

> El flujo mental real de un analista cuando "algo huele mal":

```powershell
# 1) Veo un proceso raro y saco su PID, padre y línea de comandos
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -match 'Temp|AppData|Public' } |
  Select ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath

# 2) ¿Quién lo lanzó? (padre)  -> ¿es coherente?
# 3) ¿Tiene conexión de red? (¿C2?)
Get-NetTCPConnection -OwningProcess <PID> -ErrorAction SilentlyContinue

# 4) ¿Está firmado el binario?
Get-AuthenticodeSignature '<ruta_del_exe>' | Select Status

# 5) ¿Dejó persistencia? (tarea/servicio/Run que apunte a esa ruta)
# 6) ¿Qué dicen los eventos? (4688 de ese proceso, 7045 si creó servicio)
# 7) Contención: matar proceso, quitar persistencia, quitar exclusión Defender, aislar red
```

**Resultado esperado del ejercicio:** un mini-informe con *proceso → padre → red → firma → persistencia → eventos → acción*, que es el esqueleto de un ticket de SOC y del Proyecto 4 (Incident Response).

---

## 🗺️ Mapeo MITRE ATT&CK (resumen)

| Táctica | Técnica | Dónde se ve en este cuaderno |
|---|---|---|
| Execution | T1059 (Command/Scripting Interpreter) | §1 cadena de padres, §5 evento 4104 |
| Persistence | T1547.001 (Run Keys), T1543.003 (Service), T1053.005 (Scheduled Task), T1546.003 (WMI) | §3 |
| Defense Evasion | T1562.001 (Impair Defenses), T1070.001 (Clear Logs) | §4 exclusiones, §5 evento 1102 |
| Command & Control | T1105 (Ingress Tool Transfer) | §2 LOLBins con red |
| Persistence/Priv | T1136 / T1078 (Create/Valid Accounts) | §6, §5 evento 4720 |

---

## ✅ Qué demuestra este proyecto

- **Triage de un endpoint Windows sin depender de un EDR**, con herramientas nativas (cmd + PowerShell + WMI).
- Conocimiento de **dónde se esconde el adversario** (procesos, red, persistencia, Defender, logs, cuentas) y **cómo se ve un compromiso**.
- Lectura de los **eventos de seguridad** clave que luego se cazan con KQL en Sentinel.
- Mentalidad de **Incident Response**: del indicio a la contención, mapeado a **MITRE ATT&CK**.
- Está **anclado a un incidente real** (sabotaje de exclusiones de Defender), no a teoría.
