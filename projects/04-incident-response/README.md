# Proyecto 4 — Incident Response Case Study

> Respuesta a incidentes de extremo a extremo (PICERL) sobre una cadena de intrusion simulada en un endpoint Windows: Kerberoasting -> ejecucion ofuscada -> evasion de Defender -> descarga de payload -> "ransomware". Ejercicio benigno y contenido en lab aislado `corp.local`.

---

## 1. Escenario

Simulacion de un compromiso de endpoint con **acceso a credenciales y ransomware** en el laboratorio `corp.local` (Hyper-V, red **LAB-Net aislada, sin internet**). El objetivo no es el ataque, sino **ejecutar el ciclo de respuesta a incidentes completo** sobre telemetria real generada en el lab.

**Ejercicio 100% benigno y contenido** (2026-06-15). Nada destructivo ni real:

- PowerShell ofuscado que **solo imprime** un marcador.
- Exclusion de Microsoft Defender **revertida en el acto**.
- `certutil` contra una **URL local** (`http://127.0.0.1/...`), sin salida a internet.
- "Ransomware" que **solo renombro 6 ficheros DUMMY** a `*.locked` en un sandbox (`C:\soc-ir-sim\victim-data`) y dejo una nota marcada como **SIMULACION**.
- **Sin** cifrado real, **sin** borrado de shadow copies, **sin** propagacion.

### Infraestructura del lab

| Host | Rol | IP | Notas |
|------|-----|-----|-------|
| DC01 | Windows Server 2025 — DC / KDC / DNS | 10.10.10.10 | Dominio `corp.local` |
| WIN11 | Windows 11 Pro unido al dominio (endpoint) | 10.10.10.21 | Sysmon + Microsoft Defender |
| Wazuh manager | SIEM Wazuh 4.13.1 | 10.10.10.20 | Reglas, Active Response, casebook |

Operacion por **PowerShell Direct** desde el host Hyper-V. Cuentas: endpoint `WIN11\labadmin`; admin de dominio `CORP\Administrator`; usuarios `j.perez`/`m.lopez`/`a.garcia`/`helpdesk`. Senuelos (honeypots) en AD: `svc_sql` (SPN `MSSQLSvc/sql01.corp.local:1433`, RC4, pw debil) y `a.garcia` (`DONT_REQ_PREAUTH`).

---

## 2. Resumen del incidente

Cadena de intrusion detectada el **2026-06-15** (horas en UTC). Cada deteccion disparo su regla Wazuh y el Active Response abrio un caso automaticamente.

| Hora (UTC) | Etapa MITRE | Que paso | Deteccion |
|------------|-------------|----------|-----------|
| 19:21:39 | Credential Access — **T1558.003** | Kerberoasting: solicitud TGS del senuelo `svc_sql` en DC01 | Regla **100110** (n12) -> caso |
| 19:50:08 | Execution — **T1059.001 / T1027** | PowerShell `-EncodedCommand` decodifica a `IEX "...IR-SIM-EXEC-MARKER"` | Regla **100120** (n12) -> caso |
| 19:50:08 | Defense Evasion — **T1562.001** | `Add-MpPreference -ExclusionPath C:\soc-ir-sim` (revertido) | Regla **100130** (n12) -> caso |
| 19:50:09–14 | Ingress Tool Transfer — **T1105** | `certutil -urlcache -f http://127.0.0.1/ir-sim-payload` | Regla **100150** (n10) -> caso (x2) |
| 19:50:19 | EDR | Defender **DETECTA** el certutil = `Trojan:Win32/Ceprolad.A` (ThreatID 2147726914, EID 1116) | Regla **100160** (n12) -> caso |
| 19:50:32 | EDR | Defender **BLOQUEA / cuarentena** (EID 1117) | Regla **100161** (n10) -> caso |
| ~19:50:35 | Impact — **T1486** | "Ransomware": 6 ficheros dummy -> `*.locked` + nota `RECOVER-FILES.txt` | **Ninguna deteccion** (gap) |

---

## 3. Metodologia — PICERL

Este proyecto ejecuta el ciclo **PICERL** completo (Prepare / Identify / Contain / Eradicate / Recover / Lessons learned). El **Proyecto 1** entrega el caso ya triado por el Active Response; este **Proyecto 4** ejecuta la respuesta de principio a fin y la mapea a **MITRE ATT&CK**. El formato del informe sigue el del caso real previo del autor (incidente **Lumma**, repo `Threat Hunting on my own PC`).

Acciones de respuesta disponibles y usadas en el lab:

- **Contain** — aislar WIN11 (`Disconnect-VMNetworkAdapter` / quitar de LAB-Net por Hyper-V); deshabilitar/resetear cuentas AD (`Disable-ADAccount` / `Set-ADAccountPassword` en DC01).
- **Eradicate** — revertir exclusiones de Defender (`Remove-MpPreference`); `Get-MpThreat` / `Get-MpComputerStatus` para confirmar cuarentena.
- **Recover** — restaurar desde el checkpoint Hyper-V `pre-wazuh-agent_20260615` de WIN11.

### Documentacion del proyecto

| Documento | Contenido |
|-----------|-----------|
| [`ir-report.md`](ir-report.md) | Informe PICERL completo |
| [`timeline.md`](timeline.md) | Kill chain con horas reales |
| [`evidence/incident-evidence.md`](evidence/incident-evidence.md) | Telemetria cruda: alertas, casebook del Active Response, eventos Defender, evidencia del impacto |

---

## 4. Hallazgos clave

### (a) El Active Response abrio los casos solo

La automatizacion del **Proyecto 1** (`open-soc-case`, lado-manager, grupo `soc_lab`) abrio **un caso por cada deteccion** sin intervencion de analista. El casebook `/var/ossec/logs/soc-cases.log` recibio un caso JSON por alerta (campos: `case`, `opened`, `rule`, `level`, `agent`, `mitre`, `status=NEW`, `description`, `alert_ts`), con el **mismo timestamp** que la alerta. El analista recibe el caso ya triado y empieza directamente en la fase de respuesta.

### (b) Defensa en profundidad — el `certutil` cayo dos veces

La etapa de **Ingress Tool Transfer** disparo **dos controles independientes sobre el mismo evento**:

1. **Regla propia 100150** (Security EID 4688, analisis de `commandLine`).
2. **EDR Microsoft Defender** (reglas 100160 / 100161), que ademas **lo bloqueo**.

Si una capa hubiera fallado, la otra habria cubierto el hueco. Esto valida el diseno de deteccion en capas frente a un unico punto de fallo.

### (c) El GAP — el impacto (T1486) no se detecto

Las etapas tempranas (execution -> evasion -> ingress) se detectaron, y Defender **freno el `certutil`**. Pero la etapa de **Impact (T1486)** — el renombrado masivo a `*.locked` + nota de rescate — **no disparo ninguna regla ni Defender**.

Defender freno el certutil **porque era un LOLBin ya conocido**. En un ataque real con un binario propio (no firmado como amenaza conocida), el cifrado habria completado **sin alerta**. Conclusion accionable: **regla candidata 100180** para detectar renombrado/creacion masiva de extensiones sospechosas y notas de rescate. Esto cierra el ciclo **IR -> nueva deteccion**: el incidente alimenta de vuelta al pipeline de detecciones (Proyecto 3).

---

## 5. Encaje con el portfolio

Este proyecto es la fase de **ejecucion** de un portfolio SOC construido por capas:

| Proyecto | Aporta | Rol en este incidente |
|----------|--------|-----------------------|
| **P2 — Threat Hunting** | Baseline de known-good | Permite distinguir lo anomalo de lo normal |
| **P3 — Detecciones Wazuh** | Reglas 100110–100161 | Generaron las alertas de la cadena |
| **P1 — Playbook + Runbooks + Active Response** | RB-100110/120/130/150/160 + `open-soc-case` | Entrega el caso ya triado y automatiza la apertura |
| **P4 — Incident Response** *(este)* | Ejecucion PICERL completa | Responde, erradica, recupera y **realimenta** una nueva deteccion |

El formato del informe esta inspirado en el **caso real Lumma** del repo `Threat Hunting on my own PC` (compromiso del PC propio del autor), llevando el mismo rigor de un incidente real a un escenario de lab controlado.

---

## 6. Estructura de carpetas

```
projects/04-incident-response/
├── README.md                      # este documento
├── ir-report.md                   # informe PICERL completo
├── timeline.md                    # kill chain con horas reales (UTC)
└── evidence/
    └── incident-evidence.md       # telemetria cruda: alertas, casebook, Defender, impacto
```

---

## 7. Que demuestra este proyecto

- **Respuesta a incidentes de extremo a extremo** con metodologia formal (PICERL) sobre telemetria real.
- **Mapeo a MITRE ATT&CK** de toda la kill chain (T1558.003, T1059.001/T1027, T1562.001, T1105, T1486).
- **Automatizacion de SOC en accion**: el Active Response abrio los casos sin analista.
- **Pensamiento de defensa en profundidad**: validacion de controles redundantes (regla propia + EDR) sobre el mismo evento.
- **Mentalidad de mejora continua**: identificacion de un gap de cobertura real (T1486) y propuesta de deteccion concreta (regla 100180), cerrando el ciclo IR -> deteccion.
- **Operacion segura**: todo el ejercicio fue benigno, contenido y reversible en un lab aislado, sin riesgo para sistemas reales.
