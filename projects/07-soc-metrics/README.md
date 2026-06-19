# 📊 Proyecto 7 — SOC Metrics & Reporting Dashboard *(capstone)*

> Entregable final del [portfolio SOC Blue Team](../../README.md). Convierte los datos crudos generados por
> todos los proyectos anteriores en **insights para equipo y dirección**: detecciones, cobertura MITRE ATT&CK,
> fuentes de datos, respuesta automática y ciclos de mejora — en una sola vista.

## Flujo

```
   datos crudos                 agregación                    reporte
(ruleset Wazuh, alerts.json,  →  (métricas: inventario,    →  (dashboard HTML + metodología
 matrices P5/P6, casos AR)        cobertura, MTTD/MTTR, FP)     reproducible contra el SIEM)
```

## Qué hay aquí

| Fichero | Contenido |
|---|---|
| [`dashboard.html`](dashboard.html) | **El dashboard** (HTML self-contained, se abre en cualquier navegador) |
| [`metrics-methodology.md`](metrics-methodology.md) | Definición de **cada métrica** + la **query Wazuh** para computarla en el SIEM real |

## Verlo

- **Abrir** `dashboard.html` en el navegador (no necesita servidor ni el lab encendido), o publicarlo en GitHub Pages.
- Versión publicada (Artifact): el dashboard renderizado, listo para enseñar en 2 minutos.

## Qué agrega (datos reales de P1–P6)

| Métrica | Valor | De dónde sale |
|---|---|---|
| Reglas de detección activas | **19** | ruleset Wazuh (`grep -c '<rule id='`) |
| Reglas Sigma portables | **11** | `projects/0{3,6}/.../sigma/*.yml` |
| Técnicas ATT&CK cubiertas | **14** | `<mitre><id>` únicos del ruleset |
| Tácticas ATT&CK | **8 / 14** | mapeo técnica→táctica |
| Fuentes de datos | **6** | 4769/4768/4688/4104, Sysmon EID1, Defender |
| Casos SOC automáticos | **7** | `soc-cases.log` (Active Response del P1) |
| Cobertura del bucle Purple | **85.7%** | matriz [P5](../05-purple-team/attack-detection-matrix.md) (6/7 emuladas detectadas) |
| Ciclos de mejora | **3** | 2 del P5 (certutil, T1490) + 1 CTI-driven del P6 (evasión 100180→100181) |
| MTTD / MTTR | **≈ segundos** | ejercicios del lab (ver metodología; **no** SLAs de producción) |

## Reproducirlo contra el SIEM real

Cada número del dashboard tiene su query en [`metrics-methodology.md`](metrics-methodology.md) (jq sobre `alerts.json`
o agregaciones sobre el índice `wazuh-alerts-*`). El dashboard de Wazuh trae además el módulo **MITRE ATT&CK** nativo.

## Qué demuestra

- **Visión de gestión SOC**: traducir telemetría y detecciones en métricas que un responsable entiende (MTTD, MTTR, cobertura, severidad, FP).
- **Pensamiento de portfolio**: el capstone **agrega** el trabajo de los 6 proyectos en una historia coherente — no 7 cosas sueltas, sino un programa de detección con cobertura medible y mejora continua.
- **Honestidad con los datos**: cifras exactas donde se pueden contar; latencias etiquetadas como valores de lab; **reproducibilidad** documentada en vez de números mágicos.

---

> 🏁 Con este proyecto, el portfolio queda **7/7 completo**: del montaje del lab AD a un programa SOC con detección, caza, respuesta, IR, purple team, inteligencia y métricas — todo demostrable y mapeado a ATT&CK.
