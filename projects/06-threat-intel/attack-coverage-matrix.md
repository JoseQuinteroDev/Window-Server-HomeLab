# 🎯 Matriz de cobertura — Akira (AA24-109A) vs. detección del lab `corp.local`

> Cruce de cada técnica ATT&CK atribuida a **Akira** contra la cobertura de detección del lab (reglas Wazuh `100110`–`100180` + Active Response + Defender, ver [matriz Purple del P5](../05-purple-team/attack-detection-matrix.md)).
> Convierte la inteligencia del [informe](intel-report.md) en un **plan de ingeniería de detección priorizado**: qué ya cazamos, qué nos evade y qué derivamos nuevo.

## Leyenda de estado

| Estado | Significado |
|---|---|
| ✅ **CUBIERTO** | Regla del lab ya existente y validada que casa esta técnica |
| ⚠️ **EVADIDO** | Existe regla para la técnica, pero la **variante concreta de Akira la esquiva** → refinar |
| 🟥 **HUECO → NUEVA REGLA** | Sin cobertura, pero **detectable con la telemetría actual** → detección derivada en este proyecto |
| ⬜ **RIESGO RESIDUAL** | No representable/observable en este lab → documentado, no fingido |

## Matriz

| Táctica | Técnica | ID | Telemetría del lab | Estado | Detección |
|---|---|---|---|---|---|
| Credential Access | Kerberoasting | T1558.003 | Security 4769 (honeypot `svc_sql`) | ✅ **CUBIERTO** | Regla **100110** (n12) |
| Defense Evasion | Impair Defenses (Defender) | T1562.001 | 4688 / Sysmon EID1 (`commandLine`) | ✅ **CUBIERTO** | Regla **100130** — la firma `Set-MpPreference -DisableRealtimeMonitoring` de Akira casa **exacto** |
| Execution / Def. Evasion | PowerShell / Obfuscation | T1059.001 / T1027 | PowerShell 4104 | ✅ **CUBIERTO** | Regla **100120** |
| Impact | Inhibit System Recovery | T1490 | 4688 / Sysmon (`commandLine`) | ⚠️ **EVADIDO** | **100180** solo casa `vssadmin`/`wmic`/`Remove-CimInstance`; Akira usa `Get-WmiObject Win32_Shadowcopy…Delete()` → **nueva 100181** |
| Credential Access | OS Cred. Dumping: LSASS | T1003.001 | 4688 / Sysmon (`commandLine`) | 🟥 **HUECO → NUEVA** | **100190** (`comsvcs.dll` MiniDump / rundll32) |
| Discovery | Remote System Discovery | T1018 | 4688 (`commandLine`) | 🟥 **HUECO → NUEVA** | **100200** (`nltest /dclist`, `net group "Domain Admins"`) |
| Discovery | Domain Trust Discovery | T1482 | 4688 (`commandLine`) | 🟥 **HUECO → NUEVA** | **100200** (`nltest /domain_trusts`) |
| Discovery | Account Discovery: Domain | T1087.002 | PowerShell 4104 / 4688 | 🟥 **HUECO → NUEVA** | **100210** (BloodHound / SharpHound / `Invoke-BloodHound`) |
| Persistence | Create Account: Local | T1136.001 | 4688 (`commandLine`) + Security 4720 | 🟥 **HUECO → NUEVA** | **100220** (`net user … /add`) |
| Lateral Movement (prep) | Disable Firewall / RDP | T1562.004 / T1021.001 | 4688 (`commandLine`) | 🟥 **HUECO → NUEVA** | **100230** (`netsh advfirewall … rdp`, `fDenyTSConnections=0`) |
| Credential Access | OS Cred. Dumping (Mimikatz/LaZagne) | T1003 | 4688 / Sysmon | 🟥 *parcial* | Cubierto indirecto si la herramienta corre por nombre/cmdline; **100190** cubre la vía LSASS nativa |
| Command & Control | External Remote Services (AnyDesk) | T1133 | 4688 / Sysmon | ⬜ **RESIDUAL** | Herramienta legítima dual-use; alto ruido — se documenta, no se fuerza regla frágil |
| Lateral Movement | WMIEXEC / SSH | T1047 / T1021.004 | 4688 / 4624 | ⬜ **RESIDUAL** | Sin segundo endpoint Windows ni host Linux destino en el lab |
| Exfiltration | rclone / WinSCP / MEGA | T1567 / T1048 | — | ⬜ **RESIDUAL** | Sin monitorización de egreso/red en el lab |
| Initial Access | Exploit Public-Facing App / Valid Accounts | T1190 / T1078 | — | ⬜ **RESIDUAL** | Sin VPN/appliance perimetral en el lab aislado |
| Impact | Data Encrypted for Impact | T1486 | — | ⬜ **RESIDUAL** | Requiere FIM de frecuencia (mismo gap reconocido en P5); **mitigado vía su precursor T1490** |

## Resumen de cobertura

Universo: **16 técnicas ATT&CK** atribuidas a Akira y mapeadas contra el lab.

- **✅ Ya cubiertas por reglas existentes:** **3** — T1558.003 (100110), T1562.001 (100130), T1059.001/T1027 (100120). El lab estaba, sin saberlo, preparado para el **núcleo de identidad** de Akira.
- **⚠️ Evadidas (refinamiento necesario):** **1** — T1490: la variante WMI de Akira esquiva 100180 → **100181**.
- **🟥 Huecos detectables → detecciones derivadas nuevas:** **5 reglas** (100190, 100200, 100210, 100220, 100230) cubriendo 6 técnicas (T1003.001, T1018, T1482, T1087.002, T1136.001, T1021.001/T1562.004).
- **⬜ Riesgo residual documentado (no representable en el lab):** **6** — T1190, T1078, T1133, T1047/T1021.004, T1567/T1048, T1486.

**Ganancia neta del proyecto:** de **3** técnicas de Akira cubiertas → **10** (3 existentes + 1 refinada + 6 nuevas), pasando la cobertura de la cadena *intra-dominio* de Akira (lo que el lab puede ver) del **~33 %** al **~100 %** de lo observable.

### El hallazgo que justifica el proyecto

> **La inteligencia real expuso un punto ciego en nuestra propia detección.** La regla **100180** (T1490) se validó en vivo en el Purple Team (P5) contra `vssadmin`/`wmic`. Pero Akira **deliberadamente evita `vssadmin`** y borra las instantáneas por WMI (`Get-WmiObject Win32_Shadowcopy | %{$_.Delete();}`), un patrón que **100180 no casa**. Sin este informe CTI, habríamos creído tener cubierto T1490 cuando el adversario más activo de su categoría lo esquiva. → Lección: **una detección no está "completa" hasta contrastarla con cómo lo hace el adversario real**, no solo con la PoC más cómoda. La regla **100181** cierra la evasión.

## Detecciones derivadas (resumen)

| Regla | Técnica | Fuente de datos | Patrón clave | Artefactos |
|---|---|---|---|---|
| **100181** | T1490 | 4688 / Sysmon `commandLine` | `Get-WmiObject\|gwmi\|Get-CimInstance … Win32_Shadowcopy … Delete` | [sigma](detections/sigma/shadowcopy_wmi_delete_t1490.yml) · [kql](detections/kql/akira-derived-detections.kql) · [wazuh](detections/wazuh/akira-local-rules.xml) |
| **100190** | T1003.001 | 4688 / Sysmon `commandLine` | `comsvcs.dll` + `MiniDump` (o `rundll32 … #+24`) | [sigma](detections/sigma/lsass_comsvcs_minidump_t1003_001.yml) |
| **100200** | T1018 / T1482 | Security 4688 `commandLine` | `nltest /dclist\|/domain_trusts`, `net group "Domain Admins" /domain` | [sigma](detections/sigma/ad_discovery_nltest_t1018_t1482.yml) |
| **100210** | T1087.002 | PowerShell 4104 / 4688 | `Invoke-BloodHound`, `SharpHound`, `-CollectionMethod` | [sigma](detections/sigma/bloodhound_sharphound_t1087_002.yml) |
| **100220** | T1136.001 | 4688 `commandLine` (+ Security 4720) | `net … user … /add` | [sigma](detections/sigma/suspicious_account_creation_t1136.yml) |
| **100230** | T1021.001 / T1562.004 | 4688 `commandLine` | `netsh advfirewall … rdp`, `fDenyTSConnections … 0` | [sigma](detections/sigma/rdp_enable_firewall_t1021_001.yml) |

Diseño consistente con el lab: todas casan **`win.eventdata.commandLine`**, campo **común a Security 4688 y Sysmon EID 1** — la lección del ciclo Purple #1 (una regla atada a un solo sensor es un punto ciego). Estado de despliegue/validación: ver [`evidence/deployment-and-validation.md`](evidence/deployment-and-validation.md).
