# Proyecto 5 — Purple Team Simulation

> Cierre del bucle red ↔ blue en el lab `corp.local`: emulo técnicas ATT&CK de forma controlada, las detecto con Wazuh, corrijo los puntos ciegos y re-emulo para demostrar la mejora — con telemetría real del laboratorio.

---

## 1. Qué es Purple Team y el ciclo

Un equipo **Red** ataca y un equipo **Blue** defiende. El enfoque **Purple Team** une ambos en un único ciclo iterativo donde el objetivo no es "ganar", sino **medir y mejorar la detección**:

```
RED  ──►  BLUE  ──►  IMPROVE  ──►  RE-EMULAR
emula     detecta /   corrige        demuestra
ATT&CK    responde    reglas y       la mejora
(control) (Wazuh+AR)  procesos       (vuelve a RED)
```

- **RED** — emulación controlada de técnicas MITRE ATT&CK dentro del lab aislado.
- **BLUE** — detección y respuesta con reglas Wazuh (`1001xx`) + Active Response.
- **IMPROVE** — se corrige la regla o el proceso que falló o dejó un hueco.
- **RE-EMULAR** — se repite la técnica para **demostrar** que ahora sí se detecta.

### Entorno del laboratorio

| Host | Rol | IP | Telemetría |
|------|-----|-----|------------|
| DC01 | Dominio `corp.local`, KDC (Server 2025) | 10.10.10.10 | Security (4688, 4769…) |
| WIN11 | Endpoint (Win11 Pro) | 10.10.10.21 | Sysmon + Defender |
| Wazuh | SIEM manager (Wazuh 4.13.1) | 10.10.10.20 | Reglas + Active Response |

Hyper-V aislado. Señuelos AD desplegados: `svc_sql` (SPN `MSSQLSvc/sql01.corp.local:1433`) y `a.garcia` (`DONT_REQ_PREAUTH`).

---

## 2. Resumen de cobertura

**8 técnicas ATT&CK emuladas/cubiertas · 6 detectadas · 1 lista (emulación pendiente) · 1 gap (mejora ya diseñada).**

| Táctica | Técnica | Detección | Estado |
|---------|---------|-----------|--------|
| Credential Access | T1558.003 Kerberoasting | Regla 100110 (honeypot `svc_sql`) | **Detectado** — determinista, agnóstico del cifrado |
| Credential Access | T1558.004 AS-REP Roasting | Regla 100140 | Detección **armada**, emulación real pendiente |
| Execution | T1059.001 PowerShell | Regla 100120 | **Detectado** |
| Defense Evasion | T1027 Obfuscation | Regla 100120 | **Detectado** |
| Defense Evasion | T1562.001 Impair Defenses | Regla 100130 | **Detectado** |
| Command & Control | T1105 Ingress Tool Transfer | Regla 100150 + Defender 100160/100161 | **Detectado** — defensa en profundidad |
| Impact | T1486 Data Encrypted for Impact | — | **Gap** (mejora diseñada → 100180) |
| Impact | T1490 Inhibit System Recovery | Regla 100180 (nivel 13) | **Mejora diseñada**, despliegue pendiente |

Matriz completa de cobertura: **[`attack-detection-matrix.md`](attack-detection-matrix.md)** · Informe del ciclo: **[`purple-report.md`](purple-report.md)**.

El Active Response **`open-soc-case`** (P1) abrió automáticamente un **caso por cada detección** (grupo `soc_lab`) en el casebook `/var/ossec/logs/soc-cases.log`: **7 casos** en el último ejercicio.

---

## 3. Ciclos de mejora

### Ciclo #1 — `certutil` / T1105 · DEMOSTRADO Y VALIDADO EN VIVO

El ejemplo de libro de por qué Purple Team funciona: un punto ciego encontrado, corregido y verificado.

1. **RED** emuló `certutil -urlcache -f http://127.0.0.1/...` (descarga de herramienta).
2. **BLUE NO lo detectó** (primera pasada → *true negative*). La regla `100150` casaba `win.eventdata.image`, un campo que **solo** emite Sysmon EID 1. Pero el Sysmon del lab usa `ProcessCreate onmatch=include` y **no listaba `certutil`**, así que no se generaba EID 1. El único evento era Security **4688**, donde la imagen va en `newProcessName` (`image=null`). Resultado: el ataque ocurrió **sin alerta**, entrando como regla genérica `67027`.
3. **IMPROVE** — se reescribieron `100150/100151/100152` para casar **`win.eventdata.commandLine`**, un campo **común** a 4688 y a Sysmon EID 1 (igual que ya hacía `100130`).
4. **RE-EMULAR** — se relanzó `certutil` y la regla `100150` **sí disparó** (validado varias veces). Además, **Defender** aportó una detección independiente (`100160/100161`).

> **Lección:** una regla atada a un único sensor es un punto ciego. Casar el **campo común** (`commandLine`) da cobertura **agnóstica del sensor** y resistente a *tamper*.

### Ciclo #2 — Ransomware / T1486 → T1490 · DISEÑADO (despliegue pendiente)

1. El ejercicio de **IR (P4)** reveló que la etapa de **Impacto** —cifrado/renombrado masivo de 6 ficheros dummy a `*.locked` + nota de rescate (sin cifrado real)— **no disparó nada**. Detectar el cifrado masivo directo (T1486) en el SIEM es difícil sin un FIM de frecuencia.
2. **IMPROVE** — se autoró la regla **`100180` (nivel 13, T1490 Inhibit System Recovery)** que caza por `commandLine` el borrado de Shadow Copies / backups (`vssadmin`, `wmic shadowcopy`, `wbadmin`, `bcdedit`): el **precursor detectable** que casi todo ransomware ejecuta justo antes de cifrar.
3. **Estado:** regla autorada y en el repo (`wazuh/rules/local_rules.xml`). Su **despliegue + validación en el manager queda pendiente de autorización explícita** (modifica la infraestructura del SIEM) — el mismo estado que tuvo el Active Response antes de aprobarse.

---

## 4. Hallazgos

- **Defensa en profundidad (`certutil` × 2 controles).** Tras el Ciclo #1, T1105 queda cubierto por **dos detecciones independientes**: la regla propia `100150` (por `commandLine`) **y** el EDR de Defender (`100160/100161`). Si una falla o es evadida, la otra sigue cubriendo.
- **El Active Response abre casos solo.** `open-soc-case` materializó **7 casos** automáticamente, uno por detección, sin intervención humana: la detección se convierte en trabajo de SOC trazable de forma inmediata.
- **El mito del RC4.** Server 2025 emite tickets Kerberos en **AES (`0x12`)**, por lo que la firma basada en **RC4 `0x17`** (regla `100111`) se **evade**. La detección robusta es el **honeypot** `svc_sql` (`100110`): determinista y agnóstica del cifrado. **Lección:** reforzar por **honeypot/identidad**, no por algoritmo de cifrado.

---

## 5. Cómo integra todo el portfolio

Este proyecto **no añade reglas nuevas**: ejercita, mide y cierra el bucle sobre lo que ya construyeron los demás proyectos.

| Proyecto | Rol en la cadena |
|----------|------------------|
| **P3 — Detection Engineering** | **Escribió** las reglas `1001xx` (mapeadas a ATT&CK). |
| **P2 — Threat Hunting** | **Cazó** las técnicas y validó las firmas. |
| **P1 — SOC Operations** | **Opera** la detección: playbook + Active Response. |
| **P4 — Incident Response** | **Ejecutó** el IR del incidente de ransomware. |
| **P5 — Purple Team** *(este)* | **Cuantifica la cobertura y cierra el bucle red ↔ blue.** |

---

## 6. Estructura del repositorio

```
projects/05-purple-team/
├── README.md                     (este documento)
├── attack-detection-matrix.md    Matriz de cobertura MITRE ATT&CK
└── purple-report.md              Informe del ciclo Purple Team completo

../../wazuh/rules/local_rules.xml  Reglas 1001xx (referencia; las opera P1/P3)
```

---

## 7. Qué demuestra este proyecto

- Dominio del **ciclo Purple Team completo** (RED → BLUE → IMPROVE → RE-EMULAR), no solo de una mitad.
- Capacidad de **emular técnicas ATT&CK** de forma controlada y **mapearlas** a tácticas reales.
- **Detection engineering iterativo**: encontrar un punto ciego (`image` vs `commandLine`), entender la causa raíz (telemetría por sensor) y **demostrar la corrección en vivo**.
- Pensamiento de **defensa en profundidad** y de **detección agnóstica del sensor / del cifrado** (honeypot sobre firma frágil).
- **Cuantificación de cobertura** (técnicas emuladas / detectadas / gaps) como métrica de madurez del SOC.
- Rigor operativo: distinguir lo **demostrado en vivo** de lo **diseñado y pendiente de autorización**, sin inflar resultados.
