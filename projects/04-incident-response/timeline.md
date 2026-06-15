# ⏱️ Timeline del incidente — Ransomware simulado en WIN11

> Reconstruccion cronologica de un EJERCICIO BENIGNO Y CONTENIDO (2026-06-15) sobre el endpoint WIN11 (10.10.10.21) del lab corp.local: cadena de intrusion simulada de extremo a extremo, SIN cifrado real, ejecutada para practicar el ciclo IR completo (PICERL).

## Linea de tiempo (kill chain)

| Hora (UTC) | Host | Etapa kill-chain | Tactica/Tecnica ATT&CK | Accion observada | Evidencia (regla/EID/caso AR) |
|---|---|---|---|---|---|
| 19:21:39 | DC01 (10.10.10.10) | Credential Access | T1558.003 Kerberoasting | Solicitud de TGS contra el senuelo `svc_sql` (SPN `MSSQLSvc/sql01.corp.local:1433`, RC4 habilitado) en el KDC | Regla **100110** (nivel 12) → caso `CASE-...-100110` |
| 19:50:08 | WIN11 (10.10.10.21) | Execution | T1059.001 / T1027 PowerShell ofuscado | `powershell -EncodedCommand` decodifica a `IEX "Write-Output 'IR-SIM-EXEC-MARKER'"` (solo imprime, sin payload) | Regla **100120** (nivel 12) → caso |
| 19:50:08 | WIN11 (10.10.10.21) | Defense Evasion | T1562.001 Impair Defenses | `Add-MpPreference -ExclusionPath C:\soc-ir-sim` (revertido en el acto) | Regla **100130** (nivel 12) → caso |
| 19:50:09–14 | WIN11 (10.10.10.21) | Command & Control / Ingress | T1105 Ingress Tool Transfer | `certutil -urlcache -f http://127.0.0.1/ir-sim-payload` (URL LOCAL, sin internet) | Regla **100150** (nivel 10) → caso (x2) |
| 19:50:19 | WIN11 (10.10.10.21) | EDR — Deteccion | T1105 (control independiente) | Microsoft Defender DETECTA el `certutil` como `Trojan:Win32/Ceprolad.A` (ThreatID 2147726914) | EID **1116** → regla **100160** (nivel 12) → caso |
| 19:50:32 | WIN11 (10.10.10.21) | EDR — Contencion | — | Microsoft Defender BLOQUEA / pone en cuarentena la amenaza | EID **1117** → regla **100161** (nivel 10) → caso |
| ~19:50:35 | WIN11 (10.10.10.21) | Impact | T1486 Data Encrypted for Impact | "Ransomware" simulado: 6 ficheros DUMMY renombrados a `*.locked` en `C:\soc-ir-sim\victim-data` + nota `RECOVER-FILES.txt` (marcada SIMULACION) | **NINGUNA regla ni Defender disparo** — GAP de cobertura |

## Reconstruccion narrativa

A las **19:21:39 UTC** la cadena comienza por la fase de **acceso a credenciales**: se solicita un ticket de servicio (TGS) contra la cuenta senuelo `svc_sql` en DC01 (10.10.10.10), que expone deliberadamente un SPN `MSSQLSvc/sql01.corp.local:1433` con RC4 habilitado y password debil (`Summer2024!`). Esta tecnica de **Kerberoasting (T1558.003)** es exactamente lo que el honeypot estaba disenado para atrapar: la regla Wazuh **100110** dispara a nivel 12 y el Active Response `open-soc-case` abre automaticamente `CASE-...-100110` en `/var/ossec/logs/soc-cases.log`, sin intervencion de analista.

Casi media hora despues, a las **19:50:08 UTC**, el operador pasa a la **ejecucion** sobre el endpoint WIN11 (10.10.10.21). Un `powershell -EncodedCommand` (T1059.001 + T1027 por la ofuscacion Base64) decodifica a un `IEX` que SOLO imprime el marcador `IR-SIM-EXEC-MARKER` — sin descarga ni payload real — y dispara la regla **100120**. En el MISMO segundo se ejecuta la **evasion de defensas (T1562.001)**: un `Add-MpPreference -ExclusionPath C:\soc-ir-sim` que intentaria cegar a Defender sobre el directorio de trabajo del simulacro; la exclusion se revierte en el acto y la regla **100130** la captura. Entre las **19:50:09 y 19:50:14 UTC** llega la **transferencia de herramienta (T1105)** mediante el LOLBin `certutil -urlcache -f` apuntando a una URL LOCAL (`http://127.0.0.1/...`), que genera dos eventos cubiertos por la regla **100150**.

Aqui se materializa la **defensa en profundidad**: la misma etapa de `certutil` activo DOS controles independientes. La deteccion propia (regla 100150 sobre el evento Security 4688 / commandLine) y, en paralelo, el EDR Microsoft Defender, que a las **19:50:19 UTC** DETECTA el binario como `Trojan:Win32/Ceprolad.A` (ThreatID 2147726914, EID 1116 → regla 100160) y a las **19:50:32 UTC** lo BLOQUEA y pone en cuarentena (EID 1117 → regla 100161). Una capa habria cubierto a la otra: el ataque queda contenido en la etapa de ingreso.

Finalmente, a las **~19:50:35 UTC**, la fase de **impacto (T1486)** renombra 6 ficheros dummy a `*.locked` en el sandbox `C:\soc-ir-sim\victim-data` y deja una nota `RECOVER-FILES.txt` explicitamente marcada como SIMULACION — sin cifrado real, sin borrado de shadow copies y sin propagacion. Y aqui esta el hallazgo clave del ejercicio: **esta etapa no disparo NINGUNA regla ni alerta de Defender**. Como el binario malicioso ya conocido (el `certutil`) fue frenado antes, las primeras fases quedaron bien cubiertas; pero el renombrado masivo en si mismo no genero telemetria detectada. En un ataque real con un binario de cifrado propio (no un LOLBin previamente reconocido por Defender), el impacto habria completado SIN alerta.

## Mapa a MITRE ATT&CK (por tactica)

- **Credential Access**
  - T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting → senuelo `svc_sql` en DC01, 19:21:39 → regla 100110 → `CASE-...-100110`.
- **Execution**
  - T1059.001 Command and Scripting Interpreter: PowerShell → `-EncodedCommand` / `IEX`, 19:50:08 → regla 100120.
- **Defense Evasion**
  - T1027 Obfuscated Files or Information: comando PowerShell Base64-encoded, 19:50:08.
  - T1562.001 Impair Defenses — Disable or Modify Tools: `Add-MpPreference -ExclusionPath` (revertido), 19:50:08 → regla 100130.
- **Command & Control / Ingress**
  - T1105 Ingress Tool Transfer: `certutil -urlcache -f` contra URL local, 19:50:09–14 → regla 100150 (x2); detectado y bloqueado por Defender, 19:50:19 / 19:50:32 → reglas 100160 / 100161.
- **Impact**
  - T1486 Data Encrypted for Impact: renombrado de 6 ficheros dummy a `*.locked` + nota de rescate, ~19:50:35 → **sin deteccion (GAP)**.

## Cobertura de deteccion por etapa

| Etapa kill-chain | Tecnica | ¿Detectado? | Por que |
|---|---|---|---|
| Credential Access | T1558.003 | **SI** | El honeypot `svc_sql` genero el TGS esperado; regla 100110 (n12) + apertura automatica de caso via Active Response. |
| Execution | T1059.001 / T1027 | **SI** | El `-EncodedCommand` quedo en telemetria de PowerShell/Sysmon; regla 100120 (n12). |
| Defense Evasion | T1562.001 | **SI** | El `Add-MpPreference -ExclusionPath` se observo y registro; regla 100130 (n12). La exclusion no llego a cegar nada (revertida en el acto). |
| Ingress Tool Transfer | T1105 | **SI (doble cobertura)** | Defensa en profundidad: regla propia 100150 (Security 4688 / commandLine, n10) **Y** EDR Defender (deteccion EID 1116 → 100160 n12; bloqueo EID 1117 → 100161 n10). Una capa respaldo a la otra. |
| Impact | T1486 | **NO — GAP** | El renombrado masivo a `*.locked` no genero ninguna regla Wazuh ni deteccion de Defender. Las etapas previas se frenaron porque el `certutil` era un LOLBin ya conocido por Defender; el impacto en si carecia de regla de cobertura. En un ataque real con binario de cifrado propio, la fase de impacto habria completado SIN alerta. **Accion de mejora:** anadir deteccion de comportamiento de cifrado/renombrado masivo (creacion en masa de `*.locked`, aparicion de nota de rescate, FileCreate Sysmon a alta tasa) y, en endpoint, activar Controlled Folder Access / reglas ASR anti-ransomware. |
