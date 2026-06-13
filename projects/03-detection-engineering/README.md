# 🎯 Proyecto 3 — Detection Engineering

> Entregable del [portfolio SOC Blue Team](../../README.md). Construir detecciones, **probarlas atacando** el lab y dejarlas listas para desplegar.

## Flujo

```
Data Source            Detection Logic         Test & Validate          Deploy & Monitor
(Sysmon / Security  →  (Sigma + KQL)       →   (simulo el ataque    →   (alerta en SIEM,
 logs, GPO FASE 4)                              y capturo el evento)     pendiente del tenant)
```

El lab ya aporta la **telemetría** (auditoría avanzada por GPO + Sysmon, FASE 4) y los **objetivos**
(`svc_sql` con SPN, `a.garcia` sin preauth). Aquí se cierra el círculo: lógica → ataque → evidencia.

## Detecciones

| # | Detección | ATT&CK | Fuente de datos | Sigma | Probada |
|---|---|---|---|---|---|
| 1 | Kerberoasting (honeypot `svc_sql` + RC4) | T1558.003 | Security `4769` | [sigma](sigma/kerberoasting_4769.yml) | ✅ |
| 2 | PowerShell ofuscado / download cradle | T1059.001, T1027 | PowerShell `4104` + `4688` | [sigma](sigma/powershell_obfuscation_4104.yml) | ✅ |
| 3 | Manipulación de Defender (exclusiones) | T1562.001 | Sysmon `EID 1` / `4688` | [sigma](sigma/defender_tampering_cmdline.yml) | ✅ |
| 4 | AS-REP Roasting | T1558.004 | Security `4768` | [sigma](sigma/asrep_roasting_4768.yml) | ⏳ (KALI) |
| 5 | LOLBin de descarga (certutil/bitsadmin) | T1105 | Security `4688` | [sigma](sigma/lolbin_download_t1105.yml) | ✅ |

KQL equivalente (Sentinel / Defender XDR) en [`kql/detections.kql`](kql/detections.kql).
Evidencia de cada test en [`evidence/test-results.md`](evidence/test-results.md).

## Matriz ATT&CK cubierta

| Táctica | Técnica |
|---|---|
| Credential Access | T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting) |
| Execution | T1059.001 (PowerShell) |
| Defense Evasion | T1562.001 (Impair Defenses), T1027 (Obfuscation) |
| Command & Control | T1105 (Ingress Tool Transfer) |

## Hallazgos (lo que enseña hacerlo de verdad)

1. **Server 2025 emite AES (`0x12`), no RC4 (`0x17`).** La detección clásica de Kerberoasting "solo RC4"
   ya **no dispara**. Solución: tratar `svc_sql` como **honeypot/canary** — no presta servicio real, así
   que *cualquier* `4769` hacia él es malicioso (detección **enc-agnóstica** y de bajísimo ruido).
2. **Sysmon y la auditoría de Windows son complementarios.** La config de Sysmon es de alta señal y no
   incluye `certutil`; esa técnica la cazó el **Security 4688**. Cubrir bien = combinar ambas fuentes.

## Cómo reproducir

```powershell
# En el HOST, PowerShell como Administrador (lanza los ataques simulados por PowerShell Direct):
.\tests\Invoke-DetectionTests.ps1
# Luego revisa los eventos en DC01/WIN11 (Visor de eventos o Get-WinEvent) y compáralos con evidence/.
```

## Estado de despliegue

- ✅ Lógica de detección (Sigma) + equivalentes KQL.
- ✅ Validación por simulación con evidencia (4 de 5 disparadas; AS-REP a falta de KALI).
- ⏳ Alerta en **Microsoft Sentinel** (regla analítica) — pendiente de conectar el tenant E5 dev (fase SIEM).

## Qué demuestra

- Capacidad de **escribir detecciones portables (Sigma) y consultas KQL** mapeadas a MITRE ATT&CK.
- **Mentalidad de validación**: no basta con escribir la regla; hay que **atacar y comprobar** que dispara.
- Criterio real: ajustar la lógica a cómo se comporta el SO actual (AES vs RC4) y entender **qué fuente**
  de datos cubre cada técnica.
