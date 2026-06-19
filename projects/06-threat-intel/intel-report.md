# 🧩 Informe de Inteligencia de Amenazas — Akira Ransomware

> **Autor:** José Quintero · **Proyecto 6** del [portfolio SOC Blue Team](../../README.md)
> **Fuente primaria:** Aviso conjunto **CISA/FBI #StopRansomware: Akira Ransomware (AA24-109A)** — publicado 2024-04-18, **actualizado 2025-11-13**.
> **Marco:** MITRE ATT&CK for Enterprise · **Clasificación de manejo:** TLP:CLEAR (todo de fuentes públicas).
> **Propósito:** convertir inteligencia bruta de un adversario real en **acción defensiva** sobre el lab `corp.local` — detecciones nuevas mapeadas a ATT&CK y desplegables en Wazuh. Cierra el círculo con el [Proyecto 3 (Detection Engineering)](../03-detection-engineering/README.md).

---

## 1. Resumen ejecutivo *(para dirección)*

**Akira** es una operación de **ransomware como servicio (RaaS)** activa desde **marzo de 2023**. Opera con **doble extorsión**: primero **roba** datos y después **cifra** los sistemas, amenazando con publicar la información en su portal de filtraciones si no se paga. El aviso conjunto internacional de noviembre de 2025 estima en **~244 millones USD** lo recaudado en rescates y confirma su expansión a Norteamérica, Europa y Australia, con cifradores para **Windows, Linux, VMware ESXi y Nutanix AHV**.

**Por qué nos importa (relevancia para una empresa con Active Directory como `corp.local`):**

- Akira **no entra "hackeando" el dominio**: entra por el **perímetro** (VPN sin MFA, CVEs conocidas) y, una vez dentro, **abusa de Active Directory exactamente igual que practicamos en el lab**: *Kerberoasting*, volcado de credenciales y reconocimiento del dominio.
- Su objetivo no es sigilo eterno, sino **velocidad**: del primer acceso al cifrado pueden pasar **horas**. La ventana de detección es estrecha → las detecciones tienen que estar **ya escritas y desplegadas**, no improvisadas.
- **La buena noticia:** la mayor parte de su cadena ocurre **en el endpoint y el DC con comandos observables** (creación de cuentas, `nltest`, volcado de LSASS, borrado de shadow copies). Es decir: **es cazable con la telemetría que el lab ya genera** (auditoría avanzada por GPO + Sysmon + canal de Defender).

**Conclusión accionable:** este informe demuestra que el lab **ya detecta 3 de las técnicas núcleo de Akira** y deriva **6 detecciones nuevas** que cierran los huecos más peligrosos (volcado de LSASS, reconocimiento de dominio, BloodHound, creación de cuentas, habilitación de RDP y la variante WMI de borrado de shadow copies que **evade** una de nuestras reglas actuales).

---

## 2. Perfil del grupo

| Atributo | Detalle |
|---|---|
| **Nombre** | Akira (variantes/relaciones: **Megazord**, **Akira_v2**; vínculos atribuidos a **Storm-1567**, **Howling Scorpius**; linaje técnico asociado a **Conti**) |
| **Tipo** | Ransomware como servicio (RaaS), **doble extorsión** |
| **Activo desde** | Marzo 2023 |
| **Víctimas** | Empresas medianas y grandes; sectores diversos e **infraestructura crítica**; foco creciente en virtualización (ESXi/AHV) |
| **Cifrado** | Híbrido **ChaCha20 + RSA** (variante original en C++); variantes **Megazord/Akira_v2 en Rust** |
| **Extensiones / nota** | `.akira` (+ `.powerranges` en Megazord) · nota de rescate **`akira_readme.txt`** |
| **Impacto estimado** | ~**244 M USD** en rescates (aviso actualizado nov-2025) |

---

## 3. Ciclo de ataque (kill chain de Akira)

```
1. ACCESO INICIAL        VPN sin MFA + CVEs (Cisco ASA/FTD, Veeam, SonicWall, VMware ESXi)
        │                AnyDesk portable como acceso remoto persistente
        ▼
2. CRED. ACCESS / ESCAL. Kerberoasting (dumper de tickets) → si falla:
        │                volcado de LSASS vía comsvcs.dll MiniDump → Mimikatz / LaZagne
        ▼
3. DESCUBRIMIENTO         nltest /dclist + /domain_trusts · net · AdFind · SharpHound/BloodHound
        │                SoftPerfect / Advanced IP Scanner / NetScan
        ▼
4. PERSISTENCIA           creación de cuenta local/dominio (net user /add)
        │
        ▼
5. MOV. LATERAL           RDP → si bloqueado: Impacket WMIEXEC → si falla: SSH
        │                (habilita RDP: netsh advfirewall add rule)
        ▼
6. EVASIÓN                Set-MpPreference -DisableRealtimeMonitoring · PowerTool / Terminator
        │
        ▼
7. EXFILTRACIÓN           WinRAR/FileZilla (recolecta) → rclone/WinSCP/MEGA/Cloudflare (saca)
        │
        ▼
8. IMPACTO                borra shadow copies (Get-WmiObject Win32_Shadowcopy → .Delete())
                         → cifra (ChaCha20+RSA, .akira) → nota akira_readme.txt
```

**Detalle de credential access (clave para AD):** Akira despliega un *dumper* de tickets Kerberos para **Kerberoasting** y escalar privilegios; **si el Kerberoasting falla**, vuelca la memoria del proceso **LSASS** a un fichero **Minidump** usando la librería **`comsvcs.dll`** y luego usa **Mimikatz** para extraer credenciales. También emplea **Mimikatz** y **LaZagne** como *credential scraping*.

**Detalle de impacto (clave para la detección):** a diferencia del ransomware "clásico", Akira **evita `vssadmin.exe`** y borra las instantáneas consultando la clase WMI **`Win32_Shadowcopy`** y llamando a `.Delete()` sobre cada objeto, vía PowerShell:
```powershell
Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
```

---

## 4. TTPs mapeados a MITRE ATT&CK

> Técnicas observadas según el aviso AA24-109A y análisis corroborantes. IDs textuales del marco ATT&CK for Enterprise.

| Táctica | Técnica | ID | Cómo la usa Akira (herramienta / comando) |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | **T1190** | CVEs en VPN/appliances: Cisco `CVE-2020-3259`, `CVE-2023-20269`; Veeam `CVE-2023-27532`, `CVE-2024-40711`; SonicWall `CVE-2024-40766`; VMware ESXi `CVE-2024-37085` |
| Initial Access | Valid Accounts | **T1078** | VPN **sin MFA** con credenciales válidas |
| Command & Control | External Remote Services | **T1133** | **AnyDesk** portable para acceso remoto persistente |
| Credential Access | Kerberoasting | **T1558.003** | *Dumper* de tickets Kerberos para escalar privilegios |
| Credential Access | OS Credential Dumping: LSASS Memory | **T1003.001** | Volcado de **LSASS** vía **`comsvcs.dll` MiniDump** → **Mimikatz** |
| Credential Access | OS Credential Dumping | **T1003** | **Mimikatz**, **LaZagne** (credential scraping) |
| Discovery | Remote System Discovery | **T1018** | **`nltest /dclist:`** para identificar DCs; **AdFind** (LDAP); módulo AD de PowerShell |
| Discovery | Domain Trust Discovery | **T1482** | **`nltest /DOMAIN_TRUSTS`** |
| Discovery | Account Discovery: Domain Account | **T1087.002** | **SharpHound / BloodHound** (`Invoke-BloodHound`) |
| Discovery | System Network Config. Discovery | **T1016** | **SoftPerfect**, **Advanced IP Scanner**, **NetScan**; `fsutil fsinfo drives` |
| Execution | Windows Command Shell | **T1059.003** | comandos **`net`** para enumerar dominio/confianzas |
| Execution | PowerShell | **T1059.001** | `Invoke-BloodHound`, `Get-WmiObject`, `Set-MpPreference` |
| Persistence | Create Account: Local Account | **T1136.001** | **`net.exe user /add <usuario> <pass>`** |
| Defense Evasion | Impair Defenses: Disable/Modify Tools | **T1562.001** | **`Set-MpPreference -DisableRealtimeMonitoring`**; **PowerTool**, **Terminator** (kill de EDR) |
| Defense Evasion | Disable/Modify System Firewall | **T1562.004** | **`netsh advfirewall firewall add rule name=rdp ...`** (abre RDP) |
| Lateral Movement | Remote Services: RDP | **T1021.001** | **RDP** para moverse a sistemas remotos |
| Lateral Movement | Windows Management Instrumentation | **T1047** | **Impacket WMIEXEC** (si RDP está bloqueado) |
| Lateral Movement | Remote Services: SSH | **T1021.004** | **SSH** como último recurso |
| Collection | Archive Collected Data | **T1560** | **WinRAR**, **FileZilla** para recolectar |
| Exfiltration | Exfil. Over Web Service / Alt. Protocol | **T1567 / T1048** | **rclone**, **WinSCP**, **MEGA**, túnel de **Cloudflare** |
| Impact | Inhibit System Recovery | **T1490** | **`Get-WmiObject Win32_Shadowcopy \| ForEach-Object {$_.Delete();}`** (evita `vssadmin`) |
| Impact | Data Encrypted for Impact | **T1486** | Cifrado **ChaCha20 + RSA**, extensión `.akira` |

---

## 5. Indicadores de compromiso (IOCs) — de comportamiento

> Priorizamos IOCs **de comportamiento** (TTP), más duraderos que los atómicos (hashes que rotan en cada campaña).

| IOC | Tipo | Nota |
|---|---|---|
| `akira_readme.txt` (`powerranges_readme.txt`) | Fichero | Nota de rescate |
| Extensión `.akira` / `.powerranges` | Fichero | Ficheros cifrados |
| Ficheros `.dmp` en `%TMP%` | Artefacto | Restos de volcado de LSASS |
| `rundll32 ... comsvcs.dll, MiniDump ...` | Línea de comandos | Volcado de LSASS |
| `nltest /dclist:` · `nltest /domain_trusts` | Línea de comandos | Reconocimiento de dominio |
| `net user <x> <pass> /add` | Línea de comandos | Cuenta de persistencia |
| `netsh advfirewall firewall add rule name="rdp"` | Línea de comandos | Apertura de RDP |
| `Get-WmiObject Win32_Shadowcopy ... Delete()` | Línea de comandos | Borrado de instantáneas |
| `AnyDesk.exe`, `rclone.exe`, `WinSCP`, `AdFind`, `PowerTool`, `Terminator` | Binarios | Herramientas de terceros |

---

## 6. Qué significa para `corp.local` (puente a la acción)

El análisis cruzado contra la cobertura actual del lab (reglas Wazuh `100110`–`100180` y la [matriz Purple del P5](../05-purple-team/attack-detection-matrix.md)) arroja tres categorías. El detalle cuantitativo está en **[`attack-coverage-matrix.md`](attack-coverage-matrix.md)**; resumen:

- **✅ Ya cubierto (3 técnicas núcleo):** Kerberoasting `T1558.003` (regla **100110**), manipulación de Defender `T1562.001` — la firma `Set-MpPreference -DisableRealtimeMonitoring` de Akira **casa exactamente** la regla **100130** — y PowerShell/ofuscación `T1059.001`/`T1027` (**100120**).
- **⚠️ Hueco crítico — evasión de una regla validada:** el borrado de shadow copies de Akira (`Get-WmiObject Win32_Shadowcopy`) **evade** la regla **100180** (que solo cubre `vssadmin`/`wmic`/`Remove-CimInstance`). La inteligencia real **expone un punto ciego en nuestra propia detección**.
- **🟥 Huecos sin cobertura, pero detectables con la telemetría actual:** volcado de LSASS (`T1003.001`), reconocimiento con `nltest` (`T1018`/`T1482`), BloodHound (`T1087.002`), creación de cuentas (`T1136.001`) y habilitación de RDP (`T1021.001`/`T1562.004`).

→ De aquí salen las **6 detecciones derivadas** del proyecto (Sigma + KQL + reglas Wazuh `100181`, `100190`–`100230`). Ver [`detections/`](detections/) y la matriz.

**Riesgo residual aceptado (honestidad metodológica):** algunas técnicas **no son representables/observables en este lab** y se documentan como tales, no se fingen: acceso inicial `T1190` (no hay VPN/appliance perimetral en el lab), cifrado `T1486` (requiere FIM de frecuencia — mismo gap reconocido en P5), exfiltración por servicios cloud (sin monitorización de egreso) y `T1021.004` SSH (no hay host Linux de destino).

---

## 7. Recomendaciones de mitigación *(del aviso, priorizadas para AD)*

1. **MFA en todos los accesos remotos** (VPN, RDP expuesto) — corta el vector de acceso inicial.
2. **Parcheo prioritario** de VPN/appliances perimetrales (las CVEs listadas).
3. **Cuentas de servicio robustas**: contraseñas largas/aleatorias y, donde se pueda, **gMSA**; auditar SPNs → reduce el Kerberoasting.
4. **Protección de LSASS**: *Credential Guard* / RunAsPPL; vigilar accesos a LSASS y uso de `comsvcs.dll`.
5. **Segmentación y mínimo privilegio en RDP**; deshabilitar RDP donde no se use.
6. **Copias de seguridad offline/inmutables** (3-2-1) — la defensa real contra `T1490`/`T1486`.
7. **Detección desplegada y validada** (lo que hace este proyecto): que las reglas existan *antes* del incidente.

---

## 8. Fuentes

- CISA / FBI / Europol / NCSC-NL et al. — **#StopRansomware: Akira Ransomware (AA24-109A)**, 2024-04-18, actualizado 2025-11-13. <https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a> (mirror IC3/FBI: <https://www.ic3.gov/CSA/2024/240418.pdf>)
- Unit 42 (Palo Alto Networks) — *Threat Assessment: Howling Scorpius (Akira Ransomware)*. <https://unit42.paloaltonetworks.com/threat-assessment-howling-scorpius-akira-ransomware/>
- Picus Security — *Akira Ransomware Analysis, Simulation and Mitigation (CISA AA24-109A)*. <https://www.picussecurity.com/resource/blog/akira-ransomware-analysis-simulation-and-mitigation-cisa-alert-aa24-109a>
- Trend Micro — *Ransomware Spotlight: Akira*. <https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-akira>
- MITRE ATT&CK — Akira (Group **G1024**). <https://attack.mitre.org/groups/G1024/>

> *Las técnicas y herramientas se citan tal como aparecen en las fuentes públicas. Datos del lab (`corp.local`, `svc_sql`, `a.garcia`, DC01/WIN11) son del entorno aislado propio.*
