# Simulacion Purple Team — corp.local

> Un ciclo Purple completo (RED emula -> BLUE detecta/responde -> IMPROVE -> RE-EMULAR) sobre el lab AD aislado corp.local, con telemetria real de Wazuh 4.13.1 y una mejora de deteccion validada en vivo de extremo a extremo.

## Objetivo y metodologia

El objetivo de este ejercicio (P5) es **cuantificar la cobertura de deteccion** del lab y **cerrar el bucle red<->blue**: no basta con tener reglas escritas, hay que demostrar que disparan ante la tecnica real y corregir los puntos ciegos.

Todas las emulaciones fueron **controladas y benignas**, ejecutadas en un entorno Hyper-V **aislado** (sin salida a produccion ni a Internet):

- **DC01** — Server 2025, KDC, 10.10.10.10
- **WIN11** — Win11 Pro con Sysmon + Defender, 10.10.10.21
- **Wazuh manager** — 10.10.10.20, SIEM Wazuh **4.13.1**
- Senuelos AD: **svc_sql** (SPN `MSSQLSvc/sql01.corp.local:1433`, RC4, pw `Summer2024!`) y **a.garcia** (`DONT_REQ_PREAUTH`).

El ciclo aplicado:

1. **RED** emula tecnicas ATT&CK de forma controlada.
2. **BLUE** detecta con reglas Wazuh (`local_rules.xml`, familia 1001xx) y responde via Active Response.
3. **IMPROVE** corrige reglas/procesos sobre los gaps observados.
4. **RE-EMULAR** relanza la tecnica para demostrar que la mejora funciona.

**Que se midio:** cobertura por tecnica ATT&CK (detectado / gap / deteccion lista pero sin emulacion), profundidad de la deteccion (sensor unico vs. campo comun vs. defensa en profundidad) y respuesta automatica (casos abiertos por el Active Response). El alcance: **8 tecnicas** en 6 tacticas, **1 ciclo de mejora demostrado en vivo** y **1 ciclo de mejora disenado** pendiente de autorizacion.

## 1. Emulacion (RED)

Tecnicas emuladas de forma controlada/benigna sobre el lab:

| Tactica | Tecnica | Como se emulo | Deteccion | Estado |
|---|---|---|---|---|
| Credential Access | **T1558.003** Kerberoasting | TGS del senuelo `svc_sql` en DC01 | regla **100110** (honeypot, n12) | DETECTADO (determinista, agnostico del cifrado) |
| Credential Access | **T1558.004** AS-REP Roasting | config hunt (`a.garcia` `DONT_REQ_PREAUTH`); **sin disparo real** (falta Rubeus/Kali) | regla **100140** (n12) ARMADA | DETECCION LISTA, emulacion real pendiente |
| Execution | **T1059.001** PowerShell | `powershell -EncodedCommand` -> `IEX "...IR-SIM-EXEC-MARKER"` | regla **100120** (n12) | DETECTADO |
| Defense Evasion | **T1027** Obfuscation | el `-EncodedCommand`/`IEX` anterior | regla **100120** | DETECTADO |
| Defense Evasion | **T1562.001** Impair Defenses | `Add-MpPreference -ExclusionPath` (revertido) | regla **100130** (n12) | DETECTADO |
| Command and Control | **T1105** Ingress Tool Transfer | `certutil -urlcache -f http://127.0.0.1/...` | regla **100150** (n10) + Defender **100160/100161** | DETECTADO (defensa en profundidad: regla propia Y EDR) |
| Impact | **T1486** Data Encrypted for Impact | "ransomware" simulado: 6 ficheros dummy -> `*.locked` + nota (**sin cifrado real**) | NINGUNA | **GAP** (no detectado) |
| Impact | **T1490** Inhibit System Recovery | precursor; **no emulado todavia** | regla **100180** (n13) AUTORADA, pendiente de despliegue | MEJORA DISENADA |

Todas las acciones potencialmente destructivas se ejecutaron de forma inerte o reversible: el `-ExclusionPath` de Defender se **revirtio**, el "ransomware" **solo renombro ficheros dummy** (sin cifrado real) y el `certutil` apunto a `127.0.0.1` (sin descarga externa).

## 2. Deteccion y respuesta (BLUE)

De las tecnicas con emulacion real disparada, **BLUE detecto** Kerberoasting (100110), PowerShell ofuscado (100120, que cubre a la vez T1059.001 y T1027), Impair Defenses (100130) y, tras la mejora, el Ingress Tool Transfer (100150 + Defender 100160/161).

**Active Response — casos solos.** El Active Response `open-soc-case` (P1) esta enganchado al grupo `soc_lab`: por **cada deteccion** abre automaticamente un caso en el casebook `/var/ossec/logs/soc-cases.log`. En el ultimo ejercicio esto produjo **7 casos** sin intervencion humana, materializando la respuesta automatica (deteccion -> caso) en el propio SIEM.

**Defensa en profundidad — caso certutil.** Tras corregir la regla (ver 4.1), `certutil` queda cubierto por **dos sensores independientes**: la regla propia **100150** (telemetria de creacion de proceso) **y** Defender via **100160/100161** (EDR). Si un atacante neutralizara o evadiera una capa, la otra sigue alertando — esa redundancia es el patron objetivo para el resto de tecnicas.

## 3. Gaps encontrados

- **Gap de Impacto (T1486).** El "ransomware" simulado (renombrado masivo a `*.locked` + nota) **no disparo ninguna regla**. El cifrado/renombrado masivo directo es **dificil de ver en el SIEM sin FIM de frecuencia** (deteccion por tasa de cambios de fichero). Es el gap mas relevante de cobertura. La mitigacion disenada (4.2) ataca el **precursor**, no el cifrado en si.
- **El "mito del RC4" — honeypot > cifrado.** La firma de deteccion por cifrado RC4 (`0x17`, regla **100111**) es evadible: WS2025 emite **AES (`0x12`)** por defecto, de modo que un Kerberoasting moderno no encaja con la firma RC4. La deteccion **robusta** es el **honeypot por identidad** (`svc_sql`, regla **100110**), que es determinista y agnostica del cifrado. Leccion: **reforzar por honeypot/identidad, no por algoritmo de cifrado.**
- **AS-REP Roasting (T1558.004) sin emulacion real.** La regla **100140** esta **armada** y el senuelo `a.garcia` (`DONT_REQ_PREAUTH`) configurado, pero **falta el disparo real** (no hay Rubeus/Kali en el lab). La deteccion esta lista; la validacion en vivo queda pendiente. No es un gap de cobertura, sino de **evidencia**: armada != validada.

## 4. Mejoras

### 4.1 DEMOSTRADA: certutil `image` -> `commandLine` (ciclo completo, validado en vivo)

Ciclo Purple cerrado y **validado en vivo**, de extremo a extremo:

- **MISSED (1a pasada).** RED emulo `certutil -urlcache`. BLUE **no lo detecto**: la regla 100150 casaba `win.eventdata.image`, un campo que **solo** produce Sysmon **EID 1**. Pero el Sysmon del lab usa `ProcessCreate onmatch=include` y **no lista `certutil`**, asi que **no generaba EID 1**. El unico evento era **Security 4688**, donde la imagen viaja en `newProcessName` (con `image=null`). Resultado: **true negative** — el ataque ocurrio sin alerta y entro como regla generica **67027**.
- **IMPROVE.** Se reescribieron **100150/100151/100152** para casar **`win.eventdata.commandLine`**, campo **comun** a Security 4688 **y** a Sysmon EID 1 — exactamente el patron que ya usaba con exito la regla 100130.
- **RE-EMULAR.** Se relanzo `certutil`: la regla **100150 SI disparo** (validado multiples veces). Ademas Defender aporto deteccion **independiente** (100160/161).
- **Leccion (detection engineering).** Una regla atada a un **unico sensor / unico campo** es un punto ciego silencioso. Casar el **campo comun** (`commandLine`) da cobertura **agnostica del sensor** y **resistente a tamper** (si el atacante manipula Sysmon, Security 4688 sigue alimentando la regla).

### 4.2 DISENADA: regla 100180 (T1490 Inhibit System Recovery) para el gap de Impacto

El ejercicio IR (P4) confirmo que la etapa de **Impacto no disparo nada** (gap de la seccion 3). Dado que ver el cifrado directo (T1486) exige FIM de frecuencia, la mejora ataca el **precursor detectable**:

- **Que detecta.** La regla **100180** (nivel **13**) caza por `commandLine` el **borrado de Shadow Copies / backups** — `vssadmin`, `wmic shadowcopy`, `wbadmin`, `bcdedit` — el paso que **casi todo ransomware ejecuta justo antes de cifrar** para impedir la recuperacion.
- **Por que el precursor y no el cifrado.** El cifrado/renombrado masivo es invisible sin FIM de frecuencia; el borrado de copias de seguridad, en cambio, es un **proceso con linea de comando muy caracteristica**, encaja en el mismo patron `commandLine` ya probado y da una alerta **temprana, de alto valor** (nivel 13) antes de que el dano sea irreversible.
- **Estado.** **Autorada y en el repo** (`wazuh/rules/local_rules.xml`). Su **despliegue + validacion en el manager queda PENDIENTE de autorizacion explicita del usuario**, porque modifica infraestructura del SIEM y el clasificador lo bloquea sin OK explicito — el mismo estado por el que paso el Active Response antes de autorizarse.

## 5. Re-emulacion y resultado

- **Mejora #1 (certutil) — RE-EMULADA y VALIDADA.** Tras el fix `image`->`commandLine`, el relanzamiento de `certutil -urlcache` **disparo la regla 100150** de forma consistente (multiples ejecuciones), con deteccion **redundante** de Defender (100160/161). El punto ciego paso de **true negative** a **deteccion en profundidad**. Mejora **demostrada**.
- **Mejora #2 (100180 / T1490) — RE-EMULACION PLANIFICADA.** Una vez autorizado el despliegue en el manager, el plan de validacion es: emular de forma benigna el borrado de Shadow Copies (`vssadmin delete shadows` u equivalente inerte) y **confirmar que 100180 dispara a nivel 13** y abre caso via Active Response. Hasta entonces el estado es **disenada/armada, no validada** — y asi se reporta, sin contarla como cobertura efectiva.

## Conclusiones

- **La postura defensiva mejoro de forma medible y verificada.** Cerramos un punto ciego real (certutil) con un ciclo Purple completo y validado en vivo, y la respuesta automatica (7 casos abiertos solos por el Active Response) demuestra que el bucle deteccion -> caso funciona sin manos.
- **Lecciones clave:**
  - **Casar el campo comun** (`commandLine`), no el de un solo sensor: cobertura agnostica del sensor y resistente a tamper.
  - **Detectar por identidad/honeypot**, no por cifrado: el honeypot `svc_sql` (100110) sobrevive al "mito del RC4" que evade la firma RC4 (100111) en WS2025/AES.
  - **Atacar el precursor** cuando el evento final es invisible: T1490 (borrado de copias) es la palanca detectable del Impacto T1486.
  - **Armada != validada:** AS-REP (100140) y la regla 100180 estan listas pero pendientes de disparo/despliegue real; se contabilizan como tales.
- **Siguiente iteracion:** (1) autorizar el despliegue y **re-emular 100180** para cerrar el gap de Impacto; (2) **emular AS-REP Roasting real** (Rubeus/Kali) para validar 100140; (3) evaluar **FIM de frecuencia** como deteccion complementaria del cifrado masivo (T1486) directo.