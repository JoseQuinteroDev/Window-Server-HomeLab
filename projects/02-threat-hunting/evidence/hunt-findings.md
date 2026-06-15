# 📊 Evidencia — resultados reales de la caza (lab `corp.local`)

> Datos obtenidos en vivo el **2026-06-15** sobre la telemetría real del lab: `alerts.json` del manager Wazuh
> (`10.10.10.20`, vía `jq`) y logs crudos en origen (`Get-WinEvent` por PowerShell Direct en WIN11/DC01).
> Inventario base: 1.501 alertas; 822 del canal Security, 31 Sysmon, 15 PowerShell, 11 Defender, 2 System.
> La regla base `67027` alerta en **cada** 4688 → `alerts.json` contiene de facto todo el historial de procesos de WIN11.

---

## Resumen por hunt

| Hunt | Técnica | Señal real encontrada | Veredicto | Detección |
|------|---------|------------------------|-----------|-----------|
| **H1** PowerShell ofuscado | T1059.001 / T1027 | `IEX "Write-Output 'SOC-DE-PS-MARKER'"` (de un `-EncodedCommand`) entre 15× 4104 | Malicioso (simulado) sobre fondo admin | 100120 ✅ |
| **H2** LOLBin descarga | T1105 | `certutil.exe -urlcache -f http://127.0.0.1/...` ×16; `rundll32` ×5 | certutil = ataque; rundll32 = benigno | 100150 ✅ |
| **H3** Evasión Defender | T1562.001 | `Add-MpPreference -ExclusionPath`; Defender `Trojan:Win32/Ceprolad.A` (1116/1117) | Tamper simulado + bloqueo real del EDR | 100130 / 100160-161 ✅ |
| **H4** Persistencia servicios | T1543.003 | 7045: `Sysmon64` + `SysmonDrv` @ 14:23:40 | Benigno (nuestro propio sensor) | candidata (nueva) |
| **H5** Kerberoasting | T1558.003 | 4769 a `svc_sql`, `encType=0x12 (AES)`; cuenta con RC4 habilitado (encTypes=23) | Honeypot tocado; RC4 evadido por AES | 100110 ✅ |
| **H6** AS-REP roastable | T1558.004 | `a.garcia` con `DoesNotRequirePreAuth=True` | Exposición de config (proactivo) | 100140 (lista) |

---

## Detalle de los hallazgos crudos

### H1 — PowerShell (canal PowerShell/Operational, 4104)
- **Malicioso (simulado):** `scriptBlockText = IEX "Write-Output 'SOC-DE-PS-MARKER'"` → **regla 100120, nivel 12**.
- **Ruido legítimo (baseline):** funciones de PS-Remoting (`PSCopyFileToRemoteSession`, `CheckPSDriveSize`,
  `PSCopyToSessionHelper`) de `Copy-Item -ToSession` al desplegar agentes; script de inventario de `*.inf`.
- **Lección:** la mayoría del 4104 "sospechoso" era actividad del administrador → hace falta baseline de *known-good*.

### H2 — LOLBins (Security 4688, `commandLine`)
```
35  powershell.exe
16  certutil.exe     <-- certutil.exe -urlcache -f http://127.0.0.1/soc-de-test  (T1105) -> regla 100150
 5  rundll32.exe     <-- uso legítimo de Windows en este lab (triar, no alertar)
```
- Matiz de DE: el Sysmon del lab (include) no listaba `certutil` → no había EID 1; el único evento era **4688**
  (imagen en `newProcessName`). Por eso la regla casa `commandLine` (común a 4688 y Sysmon), no `image`.

### H3 — Defender (4688 `commandLine` + canal Defender 1116/1117)
- Tamper: `Add-MpPreference -ExclusionPath 'C:\soc-de-test-REMOVEME'` (revertido) → **regla 100130, nivel 12**.
- EDR como fuente de verdad: `1116` (detección) + `1117` (acción) — amenaza **`Trojan:Win32/Ceprolad.A`**
  (ThreatID 2147726914) = el `certutil -urlcache`, **bloqueado** por Defender → **reglas 100160/100161**.
- Defensa en profundidad: el *mismo* `certutil` disparó **100150** (nuestra regla, vía 4688) **y** **100160/161** (Defender).

### H4 — Servicios nuevos (System 7045)
```
14:23:40  Sysmon64   C:\WINDOWS\Sysmon64.exe
14:23:40  SysmonDrv  C:\WINDOWS\SysmonDrv.sys
```
- Veredicto: **benigno** (reinstalación de nuestro Sysmon). El hunt de 7045 saca todos los servicios nuevos; el
  valor está en el triage (firma, ruta, contexto). Señal roja sería `imagePath` en `%TEMP%`, sin firma o nombre aleatorio.

### H5 — Kerberoasting (config AD + Security 4769)
- **Config hunt** (`Get-ADUser` por SPN): `svc_sql` → `SPN=MSSQLSvc/sql01.corp.local:1433`,
  `msDS-SupportedEncryptionTypes=23` (**RC4 habilitado**), `pwdLastSet=2026-06-13`. También `krbtgt` (built-in).
- **TGS real (4769):** `ServiceName=svc_sql | TicketEncryptionType=0x12 (AES256) | requestedBy=Administrator@CORP.LOCAL`.
- **Hallazgo clave:** aunque `svc_sql` tiene RC4, **Server 2025 emite AES (0x12)** → la detección clásica "RC4 0x17"
  (regla 100111) **no dispara**. El **honeypot** (cualquier 4769 a `svc_sql`) sí → **regla 100110, nivel 12**, agnóstica del cifrado.

### H6 — AS-REP roastable (config AD)
- **Config hunt** (`Get-ADUser -Filter "DoesNotRequirePreAuth -eq True"`): **`a.garcia`** (señuelo plantado).
- Disparo real del `4768 preAuthType=0` **pendiente** (requiere Rubeus/impacket; KALI diferido). Caza **proactiva de configuración**:
  encontramos la exposición antes de que se explote. La regla **100140** queda lista para el evento real.

### Baseline de logons (Security 4624)
- 24× logon **type 2** (interactivo) de `labadmin`; **0** eventos 4625 (fallos). Sin anomalías de autenticación.
