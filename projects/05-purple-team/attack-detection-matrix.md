# 🟣 Matriz de cobertura ataque <-> deteccion (MITRE ATT&CK)

> Mapeo cuantitativo de tecnicas ATT&CK emuladas (RED, de forma controlada y benigna en el lab aislado corp.local) contra su deteccion (BLUE, reglas Wazuh 4.13.1 + Active Response + Defender), cerrando el bucle Purple del lab.

## Matriz

| Tactica | Tecnica (Txxxx) | Emulacion (RED) | Deteccion (BLUE: regla/EID) | Severidad | Estado |
|---|---|---|---|---|---|
| Credential Access | T1558.003 Kerberoasting | TGS solicitado sobre el senuelo `svc_sql` (SPN `MSSQLSvc/sql01.corp.local:1433`) en DC01 | Regla **100110** (honeypot, nivel 12) — determinista, agnostica del cifrado | n12 | **DETECTADO** |
| Credential Access | T1558.004 AS-REP Roasting | Hunt configurado sobre `a.garcia` (DONT_REQ_PREAUTH); SIN disparo real (falta Rubeus/Kali) | Regla **100140** (nivel 12) ARMADA | n12 | **DETECCION ARMADA** (emulacion real pendiente) |
| Execution | T1059.001 PowerShell | `powershell -EncodedCommand` -> `IEX "...IR-SIM-EXEC-MARKER"` | Regla **100120** (nivel 12) | n12 | **DETECTADO** |
| Defense Evasion | T1027 Obfuscated Files or Information | El `-EncodedCommand`/`IEX` del caso anterior (codificacion benigna) | Regla **100120** (nivel 12) | n12 | **DETECTADO** |
| Defense Evasion | T1562.001 Impair Defenses | `Add-MpPreference -ExclusionPath` (revertido tras la prueba) | Regla **100130** (nivel 12) | n12 | **DETECTADO** |
| Command and Control | T1105 Ingress Tool Transfer | `certutil -urlcache -f http://127.0.0.1/...` (loopback, sin payload real) | Regla **100150** (nivel 10) + Defender **100160/100161** | n10 | **DEFENSA EN PROFUNDIDAD** |
| Impact | T1486 Data Encrypted for Impact | "Ransomware" simulado: 6 ficheros dummy -> `*.locked` + nota de rescate (SIN cifrado real) | NINGUNA | — | **GAP** |
| Impact | T1490 Inhibit System Recovery | Borrado de Shadow Copies re-emulado (benigno, `cmd /c rem ...`, sin borrado real) en WIN11 | Regla **100180** (nivel 13) + caso AR | n13 | **DETECTADO** (mejora validada en vivo) |

## Resumen de cobertura

Universo de la matriz: **8 tecnicas ATT&CK** mapeadas (5 tacticas: Credential Access, Execution, Defense Evasion, Command and Control, Impact).

- **Tecnicas emuladas (disparo RED real)**: 7 de 8 — T1558.003, T1059.001, T1027, T1562.001, T1105, T1486, T1490.
  - No emuladas: T1558.004 (deteccion armada, falta toolkit).
- **Tecnicas emuladas y detectadas**: 6 de 7 — todas menos T1486.
- **% de cobertura de lo emulado**: **6/7 = 85,7 %** de las tecnicas realmente disparadas generaron al menos una deteccion.
- **Con doble control (defensa en profundidad)**: 1 — T1105 (regla propia 100150 **Y** EDR Defender 100160/100161, deteccion independiente del SIEM).
- **Gaps abiertos**: 1 — T1486 (cifrado/renombrado masivo directo no visible sin FIM de frecuencia; **mitigado via su precursor T1490 / regla 100180**).
- **Deteccion lista pero sin emular**: 1 — T1558.004 (regla 100140 armada).
- **Mejora desplegada y VALIDADA en vivo**: 1 — T1490 (regla 100180 desplegada en el manager y re-emulada el 2026-06-15: disparo **nivel 13** + caso AR `CASE-20260615-202434-100180`). Cierra el gap de impacto del Proyecto 4.
- **Casos SOC abiertos automaticamente**: 7 en el ultimo ejercicio (Active Response P1 `open-soc-case`, grupo `soc_lab`, casebook `/var/ossec/logs/soc-cases.log`), uno por cada deteccion disparada.

### Ciclos de mejora del bucle Purple

- **Ciclo #1 — T1105 / certutil (VALIDADO EN VIVO)**: la 1a pasada fue un **TRUE NEGATIVE** — la regla 100150 casaba `win.eventdata.image`, campo SOLO presente en Sysmon EID 1, pero el Sysmon del lab (`ProcessCreate onmatch=include`) no listaba `certutil`, asi que no emitia EID 1; el unico evento era Security 4688, donde la imagen va en `newProcessName` (`image=null`). IMPROVE: se reescribio 100150/100151/100152 para casar `win.eventdata.commandLine` (campo COMUN a 4688 y Sysmon EID 1, como ya hacia 100130). RE-EMULAR: el relanzamiento de `certutil` disparo la regla (validado multiples veces) y Defender aporto deteccion independiente. **Leccion**: una regla atada a un unico sensor es un punto ciego; casar el campo comun da cobertura agnostica del sensor y resistente a tamper.
- **Ciclo #2 — T1486 → T1490 / ransomware (VALIDADO EN VIVO)**: el ejercicio IR (P4) revelo que la etapa de IMPACTO no disparo nada y que el cifrado masivo directo es dificil de ver en el SIEM sin FIM de frecuencia. IMPROVE: regla **100180** (nivel 13, T1490) que caza por `commandLine` el borrado de Shadow Copies/backups (`vssadmin`/`wmic shadowcopy`/`wbadmin`/`bcdedit`) — el **precursor detectable** que casi todo ransomware ejecuta justo antes de cifrar. RE-EMULAR (2026-06-15, tras autorizar el despliegue): se re-emulo el borrado de Shadow Copies de forma **benigna** (`cmd /c "rem ... vssadmin delete shadows /all /quiet"`, no destructivo) -> la regla **100180 disparo a nivel 13** y el Active Response abrio el caso `CASE-20260615-202434-100180`. **Gap del Proyecto 4 cerrado con evidencia.**
- **Hallazgo de cobertura — "mito del RC4"**: WS2025 emite tickets AES (`0x12`), por lo que la firma RC4 `0x17` (regla 100111) se evade. La deteccion robusta es el honeypot `svc_sql` (regla 100110): **reforzar por honeypot/identidad, no por cifrado**.

## Leyenda de estados

- **DETECTADO**: la tecnica se emulo (disparo RED real, benigno) y al menos una regla/Active Response del SIEM la cazo de forma validada.
- **DEFENSA EN PROFUNDIDAD**: la tecnica detectada cuenta con dos controles independientes (regla propia del SIEM **y** EDR Defender), de modo que el fallo de uno no deja la tecnica ciega.
- **GAP**: la tecnica se emulo pero NO genero ninguna alerta; cobertura ausente, requiere ingenieria de deteccion (ej. FIM de frecuencia o precursores).
- **MEJORA DISENADA**: regla autorada y en el repo (`wazuh/rules/local_rules.xml`) que cubre el gap o su precursor, pero AUN NO desplegada/validada en el manager (pendiente de autorizacion explicita por modificar la infraestructura del SIEM).
- **DETECCION ARMADA**: la regla esta cargada y lista para disparar, pero la tecnica todavia NO se ha emulado de forma real en el lab (falta herramienta/toolkit), por lo que la deteccion no se ha validado en vivo.