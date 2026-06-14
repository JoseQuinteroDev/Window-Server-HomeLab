# 🛡️ Plan Maestro — Portfolio Analista SOC / Blue Team

**Autor:** José Quintero
**Objetivo:** Construir un portfolio de proyectos **concretos y demostrables** que acrediten el perfil de **Analista SOC (Blue Team)**, no acumular teoría suelta.
**Filosofía:** Cada proyecto se **termina, se demuestra y se sube a GitHub** con su proceso de desarrollo visible (varios commits). Menos teoría flotando, más entregables que un reclutador pueda abrir y entender en 2 minutos.

> **Fecha de inicio del plan:** 2026-06-13

---

## 0. La idea que lo unifica todo: UN laboratorio = el motor

Tus 7 proyectos SOC + el proyecto de Active Directory/Windows Server + tu deseo de dominar Windows a fondo **no son 9 cosas separadas**. Son **1 laboratorio** que, corriendo escenarios distintos, **produce 7 entregables**.

No se puede hacer Detection Engineering, Threat Hunting, IR ni Purple Team "de verdad" sin **telemetría real generada por máquinas que atacas de forma controlada**. Por eso:

```
        ┌──────────────────────────────────────────────────┐
        │           LABORATORIO (Hyper-V, aislado)          │  ← EL MOTOR
        │   Windows Server (DC: AD + DNS + GPO)             │
        │   Windows 11 (endpoint con Sysmon + Defender)     │
        │   Kali (atacante: Atomic Red Team / herramientas) │
        └───────────────────────┬──────────────────────────┘
                                 │ telemetría (Sysmon, logs)
                                 ▼
        ┌──────────────────────────────────────────────────┐
        │     SIEM EN LA NUBE: Microsoft Sentinel +         │
        │     Defender XDR  (KQL)   — tenant E5 dev gratis  │
        └───────────────────────┬──────────────────────────┘
                                 │ datos / detecciones
                                 ▼
   ┌────────┬────────┬────────┬────────┬────────┬────────┬────────┐
   │ Proy 1 │ Proy 2 │ Proy 3 │ Proy 4 │ Proy 5 │ Proy 6 │ Proy 7 │  ← LOS 7 ENTREGABLES
   │Playbook│ Hunting│Detect. │  IR    │ Purple │  CTI   │Métricas│
   └────────┴────────┴────────┴────────┴────────┴────────┴────────┘
```

---

## 1. Inventario actual (lo que YA tienes)

| Repo / carpeta | Estado | Decisión |
|---|---|---|
| `Threat Hunting on my own PC` | Caso DFIR **real** maduro (Sysmon, Sigma, KQL, MITRE, IR 2 fases) | **CONSERVAR** — vale oro, es un caso real. Lo enlazamos desde el portfolio. |
| `Adversary Emulation Lab` | Era solo README de planificación | **ELIMINADO** (2026-06-13) — su contenido lo absorbe este plan. |
| `VLANs-Casa-PacketTracer` | Empezado (GUIA, configs R1/SW1) | **CONTINUAR** en paralelo (track de redes). |
| `SOC-Blue-Team/` | Nuevo (este plan) | Índice/umbrella del portfolio. |

---

## 2. ⚠️ Restricción de hardware — RESOLVER ANTES DE MONTAR EL LAB

Tu equipo: **i7-11800H (8 núcleos)** · **16 GB RAM** · **NVMe 512 GB con solo 27 GB libres en C:**.

- **CPU:** sobra. ✅
- **RAM (16 GB):** ajustada pero viable si vamos finos (ver dimensionado abajo). ⚠️
- **Disco (27 GB libres):** **BLOQUEANTE.** 3 VMs necesitan ~60–100 GB. **Hay que resolverlo primero.** 🔴

**Opciones (elige una; recomendación = la primera):**

1. **SSD/HDD externo USB para las VMs (RECOMENDADO).** Un SSD externo de 500 GB–1 TB es barato y es lo que hacen casi todos los home labs. Las VHDX viven ahí, C: queda libre. Cero riesgo para tu sistema de trading.
2. **Liberar ~60 GB en C:.** Tienes candidatos obvios en el Escritorio (vídeos `.mp4` de ~190 MB cada uno, PDFs grandes, juegos, editores de saves). Suficiente para un lab MÍNIMO (DC + 1 endpoint), justo.
3. **Lab híbrido nube-first.** El SIEM ya es nube (Sentinel/Defender XDR, no gasta disco local). Para AD usar Windows Server **Core** (sin GUI, ~8 GB) + 1 cliente, con discos **dinámicos**. Encaja en ~40 GB.

**Dimensionado de RAM del lab (16 GB):**

| VM | Rol | RAM | Notas |
|---|---|---|---|
| `DC01` | Windows Server (AD DS, DNS, GPO) | 4 GB | Core = aún menos |
| `WIN11` | Endpoint víctima (Sysmon, Defender) | 4 GB | |
| `KALI` | Atacante (Atomic, herramientas) | 2–3 GB | Encender solo cuando ataques |
| Host | Tu Windows 11 | ~4 GB | |

> Regla: **no enciendas las 3 VMs a la vez** salvo en los escenarios Purple Team. Para Detection Engineering basta DC+WIN11; el atacante se enciende a ratos.

---

## 3. Stack y glosario (entender las herramientas que pediste)

| Término | Qué es | Dónde encaja |
|---|---|---|
| **Sysmon** | Sensor de Microsoft que registra eventos detallados del endpoint (procesos, red, registro, DLLs) | La **fuente** de telemetría del lab |
| **EDR / XDR** | *Endpoint/Extended Detection & Response*. Detecta y responde en endpoints (EDR) o correlacionando varias capas: endpoint+identidad+email+nube (XDR) | **Defender XDR** es nuestro EDR/XDR |
| **SIEM** | *Security Information & Event Management*. Centraliza y correlaciona logs de todo | **Microsoft Sentinel** |
| **KQL** | *Kusto Query Language*. El lenguaje de consulta de Sentinel y Defender XDR | Lo que escribes para cazar/detectar. **Es lo que más piden en ofertas SOC.** |
| **MITRE ATT&CK** | Catálogo estándar de tácticas y técnicas de adversarios (T####) | El "idioma común"; mapeamos TODO a ATT&CK |
| **Sigma** | Reglas de detección en formato portable (YAML), convertibles a cualquier SIEM | Detection Engineering vendor-agnostic |
| **Atomic Red Team** | Tests pequeños y atómicos que ejecutan técnicas ATT&CK concretas | El **atacante reproducible** del lab |

---

## 4. FASES

### FASE 0 — Dominar Windows + montar el lab *(la base)*

**0.A — Cuaderno de comandos Windows a fondo** *(práctica pura, repo propio)*
Lo que pediste: manejar Windows muy bien antes que nada. Bloques de práctica con comandos + qué buscar + cómo se ve un compromiso:
- **Procesos:** `tasklist`, `Get-Process`, `Get-CimInstance Win32_Process` (con línea de comandos y PID padre), matar procesos maliciosos.
- **Red:** `netstat -ano`, `Get-NetTCPConnection`, mapear PID↔conexión↔proceso, detectar C2.
- **Persistencia:** `schtasks /query`, claves Run del registro (`reg query`), servicios (`sc query`, `Get-Service`), carpetas Startup, WMI.
- **Defender:** ver/quitar **exclusiones** (`Get-MpPreference`), estado (`Get-MpComputerStatus`), amenazas (`Get-MpThreat`), Tamper Protection.
- **Logs:** `Get-WinEvent` / `wevtutil`, eventos clave (4624/4625 logon, 4688 proceso, 7045 servicio, 4720 usuario creado).
- **Usuarios/permisos:** `net user`, `net localgroup`, `whoami /priv`, `Get-LocalUser`.

**0.B — Montar el lab Hyper-V** *(resuelto el disco primero)*
- Habilitar Hyper-V, crear **vSwitch interno aislado** (sin salida a tu LAN real).
- `DC01`: Windows Server (Eval) → promover a **Controlador de Dominio**, instalar **AD DS**, **DNS**, crear el dominio `corp.local`.
- `WIN11`: cliente Windows 11 unido al dominio.
- `KALI`: caja atacante.
- Topología, IPs y *snapshots* base documentados.
- **Aquí practicas lo que pediste de Windows Server:** AD, **GPO/políticas**, **servidores DNS**, unidades organizativas, usuarios de dominio.

### FASE 1 — Telemetría + SIEM *(EDR/XDR → Sysmon → SIEM → MITRE)*
- [x] **Sysmon** desplegado en `WIN11` (config curada del repo Threat Hunting) — Event ID 1 validado con hash + linaje (2026-06-13).
- ✅ **SIEM = Wazuh** (decidido 2026-06-14): self-hosted, gratis, **dentro de `LAB-Net` aislado**. Kit en [`wazuh/`](wazuh/) (arquitectura + 5 detecciones portadas + ingesta + runbook). Pendiente: levantar la VM `WAZUH` (Ubuntu + Wazuh AIO) y conectar agentes en DC01/WIN11.
- *(Opcional/cloud)* Tenant E5 dev → **Defender XDR + Sentinel** (KQL); kit en [`sentinel/`](sentinel/). Requiere Azure sub + tarjeta — aparcado a favor de Wazuh.
- Validación end-to-end: disparar `Invoke-DetectionTests.ps1` y ver la **alerta real** en el dashboard de Wazuh.

### FASE 2 — Los 7 proyectos (orden pedagógico)
Detalle en la sección 5. Orden recomendado: **3 → 2 → 1 → 4 → 5 → 6 → 7** (detección primero porque todo lo demás la necesita; métricas al final porque agregan todo lo anterior).

---

## 5. Los 7 proyectos (cada uno = 1 repo en GitHub)

> Cada repo: README en español, estructura clara, **varios commits** mostrando el proceso, mapeo a MITRE ATT&CK y una sección final "Qué demuestra este proyecto".

### Proyecto 3 — Detection Engineering *(EMPEZAR POR AQUÍ)*
**Flujo:** Data Source (Sysmon/Security logs) → Detection Logic (Sigma/KQL) → Test & Validate (Atomic Red Team) → Deploy & Monitor (SIEM/alerta).
- **Objetivo:** Construir detecciones, **probarlas atacando** y desplegarlas con su alerta.
- **Entregables:** N reglas Sigma + sus equivalentes KQL, evidencia de cada test atómico (antes/después), regla de alerta en Sentinel.
- **Definición de hecho:** cada detección tiene (1) lógica, (2) test Atomic que la dispara, (3) captura de la alerta en Sentinel, (4) técnica ATT&CK.

### Proyecto 2 — Threat Hunting Case Study
**Flujo:** Hipótesis → Hunt → Findings → Outcome.
- **Objetivo:** Partir de una hipótesis ("¿hay Kerberoasting en mi dominio?") y cazarla en la telemetría del lab hasta un hallazgo.
- **Entregables:** documento de caza con hipótesis, queries KQL usadas, hallazgo, y outcome (¿nueva detección? ¿hardening?).

### Proyecto 1 — SOC Automation Playbook
**Flujo:** Alert Triggered → Triage & Enrichment → Investigation → Response & Documentation.
- **Objetivo:** El **proceso** que envuelve a las detecciones: cómo un SOC maneja una alerta de principio a fin, reduciendo ruido y acelerando respuesta.
- **Entregables:** playbook (diagrama + runbook por paso), criterios de triage, plantillas de enriquecimiento (IoC lookup), árbol de decisión de respuesta. Opcional: automatización con Logic Apps / Sentinel Playbooks.

### Proyecto 4 — Incident Response Case Study
**Flujo (PICERL):** Identify → Analyze → Contain → Eradicate → Recover.
- **Escenario:** ransomware detectado en endpoint + movimiento lateral observado.
- **Objetivo:** ejecutar el escenario en el lab y documentar el IR completo con evidencia.
- **Entregables:** informe IR, timeline, acciones de contención/erradicación, lecciones. (Te apoyas en el formato real que ya tienes en `Threat Hunting on my own PC`.)

### Proyecto 5 — Purple Team Simulation
**Flujo:** Red Team (emula) → Purple (detecta y responde) → Improve (detecciones y procesos).
- **Objetivo:** un ciclo completo: el rojo ataca (Atomic), el azul detecta/responde, ambos mejoran.
- **Entregables:** matriz ataque↔detección (cobertura ATT&CK), qué se detectó/qué no, mejoras aplicadas y **re-emulación** demostrando la mejora.

### Proyecto 6 — Threat Intelligence Report
**Flujo:** Collect → Analyze → Deliver.
- **Objetivo:** convertir inteligencia bruta (un informe CTI real de, p.ej., un grupo ransomware) en acción.
- **Entregables:** informe ejecutivo + técnico, TTPs extraídos mapeados a ATT&CK, **detecciones derivadas y desplegadas en el lab** (cierra el círculo con el Proyecto 3).

### Proyecto 7 — SOC Metrics & Reporting Dashboard *(EL ÚLTIMO)*
- **Objetivo:** convertir datos crudos en insights para equipo y dirección.
- **Entregables:** dashboard (Sentinel Workbook / Power BI) con MTTD, MTTR, alertas por severidad, cobertura ATT&CK, falsos positivos. Agrega datos de los proyectos anteriores.

---

## 6. Track paralelo — Redes (VLANs + lab físico)
- Continuar `VLANs-Casa-PacketTracer` (ya tiene GUIA y configs R1/SW1).
- Objetivos: VLANs + trunking (802.1Q), inter-VLAN routing, ACLs/cortafuegos básico, DHCP por VLAN.
- **Replicar en casa:** segmentar tu red real (p.ej. VLAN trading aislada / IoT / invitados) — encaja con el aislamiento que ya aplicas tras el incidente de malware.

---

## 7. Flujo de trabajo GitHub
- **1 repo por proyecto.** Nombres sugeridos: `soc-detection-engineering`, `threat-hunting-case-study`, `soc-automation-playbook`, `incident-response-ransomware`, `purple-team-simulation`, `threat-intel-report`, `soc-metrics-dashboard`.
- **Commits que cuenten la historia:** `init estructura` → `add data source` → `add detección X` → `test atomic T1059` → `add alerta Sentinel` → `docs README`. Nada de un único commit gigante.
- **README por repo** con: resumen, diagrama, stack, estructura, cómo reproducirlo, "qué demuestra".
- Mantener este `ROADMAP.md` como índice del portfolio (enlazar cada repo cuando esté publicado).

---

## 8. ✅ Checklist maestro (orden de ejecución)

**Bloqueante previo**
- [x] Resolver disco — **liberado C: a ~56 GB** (opción 2). Tras ISOs quedan ~40 GB; discos VHDX dinámicos. (2026-06-13)

**Fase 0**
- [ ] 0.A Cuaderno de comandos Windows (repo)
- [x] Habilitar Hyper-V (servicio `vmms` corriendo). (2026-06-13)
- [x] ISOs descargados a `C:\Lab\ISOs\`: Win11 25H2 Pro (7.89 GB) + Server 2025 Eval Desktop Experience (7.59 GB). (2026-06-13)
- [x] Script de montaje listo: `C:\Lab\build-lab.ps1` (vSwitch interno aislado + DC01 + WIN11 con vTPM). **Ejecutar en consola ELEVADA.**
- [x] 0.B Ejecutado `build-lab.ps1` → vSwitch `LAB-Net` (Internal, 10.10.10.0/24) + VMs **DC01** (40 GB) y **WIN11** (64 GB, vTPM) creadas. (2026-06-13)
- [x] 0.B `DC01`: Server 2025 Desktop Experience instalado → **promovido a DC `corp.local`** (NetBIOS CORP) + DNS + estructura AD/señuelos. *(boot del instalador arreglado; promoción por PowerShell Direct — 2026-06-13)*
- [x] 0.B `WIN11` (Win11 Pro, instalación **desatendida**) unido al dominio `corp.local` (2026-06-13). GPOs base → FASE 4.
- [ ] 0.B `KALI` atacante (diferido: tras liberar más disco / SSD externo)

**Fase 1**
- [x] Sysmon en `WIN11` (config afinada) — 2026-06-13
- [x] **SIEM decidido: Wazuh** + kit en `wazuh/` (reglas, ingesta, runbook) — 2026-06-14
- [ ] Levantar VM `WAZUH` (Ubuntu + Wazuh AIO) + agentes en DC01/WIN11
- [ ] Cargar reglas + **alerta real** (`Invoke-DetectionTests.ps1`)
- [ ] *(opcional)* Sentinel/Defender XDR cloud (kit en `sentinel/`)

**Fase 2 — los 7 proyectos**
- [x] Proyecto 3 — Detection Engineering *(5 detecciones Sigma+KQL, 4 validadas por simulación; AS-REP a falta de KALI — 2026-06-14)*
- [ ] Proyecto 2 — Threat Hunting Case Study
- [ ] Proyecto 1 — SOC Automation Playbook
- [ ] Proyecto 4 — Incident Response (ransomware)
- [ ] Proyecto 5 — Purple Team Simulation
- [ ] Proyecto 6 — Threat Intelligence Report
- [ ] Proyecto 7 — SOC Metrics Dashboard

**Track redes (paralelo)**
- [ ] VLANs Packet Tracer (inter-VLAN, trunking, ACLs)
- [ ] Replicar segmentación en red de casa

---

## 9. Próximos pasos inmediatos
1. **Decidir cómo resolver el disco** (sección 2) — es lo único que bloquea el lab.
2. Mientras tanto, **arrancar 0.A (cuaderno de comandos Windows)**: no necesita lab, se puede hacer ya en tu propio equipo.
3. En paralelo, **crear el tenant E5 de desarrollador** (gratis, sin gastar disco) para tener Sentinel/Defender XDR listos.
