# 🧠 Proyecto 6 — Threat Intelligence Report (Akira Ransomware)

> Entregable del [portfolio SOC Blue Team](../../README.md). Convertir **inteligencia real** de un
> adversario activo en **acción defensiva** sobre el lab `corp.local`: extraer sus TTPs, mapearlos a
> ATT&CK y **derivar detecciones desplegables**. Cierra el círculo con el [Proyecto 3](../03-detection-engineering/README.md).

## Flujo

```
   COLLECT                  ANALYZE                         DELIVER
(aviso CISA/FBI    →   (TTPs → ATT&CK; cruce contra   →   (informe + matriz de cobertura +
 AA24-109A, Akira)      la cobertura del lab: ¿qué        6 detecciones nuevas Sigma/KQL/Wazuh
                        cubro? ¿qué me evade? ¿huecos?)    listas para desplegar y validar)
```

## Qué hay aquí

| Fichero | Contenido |
|---|---|
| [`intel-report.md`](intel-report.md) | **Informe CTI**: resumen ejecutivo + perfil + ciclo de ataque + **tabla ATT&CK completa** + IOCs + mitigaciones, con citas |
| [`attack-coverage-matrix.md`](attack-coverage-matrix.md) | **Matriz** TTP-de-Akira ↔ detección-del-lab (cubierto / evadido / hueco→nueva / residual) |
| [`detections/sigma/`](detections/sigma/) | 6 reglas **Sigma** portables (vendor-agnostic) |
| [`detections/kql/`](detections/kql/akira-derived-detections.kql) | Equivalentes **KQL** (Sentinel / Defender XDR) |
| [`detections/wazuh/`](detections/wazuh/akira-local-rules.xml) | Reglas **Wazuh** `100181`, `100190`–`100230` (desplegables) |
| [`tests/Invoke-AkiraSimulation.ps1`](tests/Invoke-AkiraSimulation.ps1) | Simulación **benigna** de los TTPs (PowerShell Direct) para validar |
| [`evidence/deployment-and-validation.md`](evidence/deployment-and-validation.md) | Runbook de despliegue + resultados esperados + estado honesto |

## Resumen del análisis (16 técnicas de Akira vs. el lab)

| Resultado | Nº | Detalle |
|---|---|---|
| ✅ Ya cubierto | 3 | Kerberoasting (100110), tamper Defender (100130 — casa la firma exacta de Akira), PowerShell (100120) |
| ⚠️ **Evadido** → refinar | 1 | **T1490**: Akira borra shadows por WMI y **esquiva la regla 100180** → nueva **100181** |
| 🟥 Hueco → detección nueva | 6 téc. / 5 reglas | LSASS, recon AD, BloodHound, crear cuenta, habilitar RDP |
| ⬜ Riesgo residual (no representable en el lab) | 6 | acceso inicial, cifrado, exfil cloud, SSH… documentados, no fingidos |

**Ganancia:** cobertura de la cadena *intra-dominio* de Akira (lo observable en el lab) del **~33 % → ~100 %**.

## Detecciones derivadas

| Regla | Técnica | Qué caza |
|---|---|---|
| **100181** | T1490 | Borrado de shadow copies por WMI (`Get-WmiObject Win32_Shadowcopy …Delete`) — cierra la evasión de 100180 |
| **100190/191** | T1003.001 | Volcado de LSASS (`comsvcs.dll MiniDump`, `procdump -ma lsass`) |
| **100200** | T1018 / T1482 | Recon de dominio (`nltest /dclist`, `/domain_trusts`, `net group "Domain Admins"`) |
| **100210/211** | T1087.002 | BloodHound / SharpHound (`Invoke-BloodHound`, `-CollectionMethod`) |
| **100220** | T1136.001 | Creación de cuenta (`net user /add`) |
| **100230** | T1021.001 / T1562.004 | Habilitación de RDP (`netsh advfirewall`, `fDenyTSConnections=0`) |

Todas casan **`commandLine`** (campo común a Security 4688 y Sysmon EID 1) → detección agnóstica del sensor y resistente a tamper de Sysmon (lección del ciclo Purple #1 del P5).

## Cómo reproducir

```powershell
# 1) Desplegar las reglas en el manager Wazuh y reiniciar (ver evidence/deployment-and-validation.md)
# 2) Desde el HOST (admin, WIN11 encendida), lanzar la simulación benigna:
.\tests\Invoke-AkiraSimulation.ps1
# 3) En el manager: verificar las alertas (buscar el tag SOC-AKIRA-SIM)
```

## Estado de despliegue

- ✅ Inteligencia recopilada de **fuente autoritativa** (CISA/FBI AA24-109A) y mapeada a ATT&CK.
- ✅ Análisis de cobertura: **3 cubiertas, 1 evasión detectada, 6 huecos → 7 reglas nuevas**.
- ✅ Detecciones **Sigma + KQL + Wazuh** autoradas + simulación benigna reproducible.
- ⏳ Despliegue + validación en vivo en el manager: **pendiente** (requiere lab encendido + autorización; runbook listo).

## Qué demuestra

- **Ciclo de inteligencia completo** (Collect → Analyze → Deliver): de un aviso público a **detecciones accionables**.
- **CTI-driven detection engineering**: la inteligencia no es un PDF que se archiva, sino **reglas que se despliegan**.
- **Pensamiento adversarial honesto**: contrastar las detecciones propias con **cómo lo hace el adversario real** descubrió que una regla ya validada (100180) **era evadible** — y se corrigió. Una detección no está "completa" hasta probarla contra el TTP real, no contra la PoC más cómoda.
- **Priorización por telemetría disponible**: se derivan detecciones para lo que el lab **puede ver**, y se documenta como riesgo residual lo que no — sin inventar cobertura.
