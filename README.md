# 🛡️ SOC Blue Team — Laboratorio y Portfolio

Portfolio de proyectos **concretos y demostrables** para acreditar el perfil de **Analista SOC (Blue Team)**.
La idea que lo unifica todo: **UN laboratorio** (Hyper-V, aislado) que, corriendo escenarios distintos, **produce 7 entregables** (Detection Engineering, Threat Hunting, IR, Purple Team, CTI, Playbooks, Métricas).

> **Autor:** José Quintero · **Inicio:** 2026-06-13

---

## 🧱 Laboratorio (dominio `corp.local`, aislado)

```
   vSwitch "LAB-Net" (Internal, 10.10.10.0/24, SIN internet)
   ┌────────────────────┬───────────────────────┬──────────────────────┐
   │       DC01         │        WIN11          │        KALI          │
   │ Windows Server 2025│   Windows 11 Pro      │   Kali Linux         │
   │ 10.10.10.10        │   10.10.10.21         │   (diferido)         │
   │ AD DS + DNS + GPO  │ Endpoint de dominio   │ Atacante             │
   └────────────────────┴───────────────────────┴──────────────────────┘
```

## ✅ Estado actual

| Fase | Descripción | Estado |
|---|---|---|
| 0 | Host Hyper-V + vSwitch aislado + VMs | ✅ |
| 1 | **DC01** → AD DS + DNS + bosque `corp.local` | ✅ |
| 2 | Estructura AD (OUs, usuarios, grupos) + **señuelos** Kerberoasting/AS-REP | ✅ |
| 3 | **WIN11 Pro** (instalación desatendida) unido al dominio | ✅ |
| 4 | GPO + Auditoría (4688/4624-25/4769/4768, PowerShell logging) | ✅ |
| 1b | Telemetría: **Sysmon en WIN11** ✅ · Microsoft Sentinel / Defender XDR (KQL) ⏳ |
| 2b | Los 7 entregables (1 repo cada uno) | ⏳ |

Evidencia de validación: [`evidence/lab-validation.md`](evidence/lab-validation.md).

## 📂 Estructura

| Ruta | Qué es |
|---|---|
| [`ROADMAP.md`](ROADMAP.md) | Plan maestro del portfolio (fases + los 7 proyectos). |
| [`LAB-BUILD.md`](LAB-BUILD.md) | Guía paso a paso del montaje del lab AD (con gotchas reales). |
| [`lab-tools/`](lab-tools/) | Automatización del lab en PowerShell (ver abajo). |
| [`cuaderno-windows-soc/`](cuaderno-windows-soc/) | Fase 0.A: cuaderno de triage de endpoint Windows con herramientas nativas. |
| [`evidence/`](evidence/) | Capturas y salidas de validación. |

## 🤖 Automatización (`lab-tools/`)

Todo el lab se monta sin abrir la consola gráfica de las VMs, usando **PowerShell Direct** (host→VM por VMBus) y **WMI de Hyper-V**:

| Script | Para qué |
|---|---|
| `build-lab.ps1` | Crea el vSwitch aislado + VMs DC01 y WIN11 (Gen2, vTPM). |
| `Provision-DC01.ps1` | Promociona DC01 a `corp.local` + estructura AD + señuelos (maneja los reinicios). |
| `Recreate-WIN11.ps1` | (Re)crea la VM WIN11 limpia. |
| `New-AutounattendIso.ps1` | Empaqueta `configs/win11-autounattend.xml` en ISO (IMAPI2, sin ADK). |
| `Boot-VMUntilSetup.ps1` | Arranca al instalador de forma fiable (supera "Press any key", reintentos). |
| `Boot-VMPressAnyKey.ps1` / `Capture-VMConsole.ps1` | Inyectar teclas / capturar la pantalla de una VM headless. |
| `Wait-VMReady.ps1` | Espera a que una VM responda por PowerShell Direct. |
| `Join-WIN11.ps1` | Une WIN11 al dominio y verifica la confianza. |

## 🎯 Qué demuestra

- Montaje **reproducible y automatizado** de un dominio Active Directory aislado (infra como código).
- Conocimiento de **Windows Server / AD / DNS / Hyper-V** y de la operación headless con PowerShell.
- Base lista para **Detection Engineering, Threat Hunting, IR y Purple Team** con objetivos de ataque reales.

> 🔒 Lab con licencias de **evaluación** — nada de software pirata (lección de un incidente real de malware previo).
