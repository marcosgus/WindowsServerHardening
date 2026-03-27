# Guía de Implementación Técnica — Windows Server 2022 Hardening
**Estándar:** DISA STIG V2R2 | Microsoft Security Baseline 22H2  
**Versión:** 2.0 — 2025  
Claude Artifact: [[aka.ms/SCT](https://claude.ai/public/artifacts/7264b302-fc47-4f98-9ae5-970a81f0b8d9)]([https://aka.ms/SCT](https://claude.ai/public/artifacts/7264b302-fc47-4f98-9ae5-970a81f0b8d9))


---

## Índice

1. [Introducción y Alcance](#1-introducción-y-alcance)
2. [Prerequisitos y Preparación](#2-prerequisitos-y-preparación)
3. [Fase 1 — Gestión de Cuentas y Autenticación](#3-fase-1-gestión-de-cuentas-y-autenticación)
4. [Fase 2 — Política de Auditoría y Logging](#4-fase-2-política-de-auditoría-y-logging)
5. [Fase 3 — Configuración de Servicios y Features](#5-fase-3-configuración-de-servicios-y-features)
6. [Fase 4 — Seguridad de Red y Firewall](#6-fase-4-seguridad-de-red-y-firewall)
7. [Fase 5 — Configuraciones de Seguridad del Sistema](#7-fase-5-configuraciones-de-seguridad-del-sistema)
8. [Fase 6 — Hardening de Remote Desktop y Acceso Remoto](#8-fase-6-hardening-de-remote-desktop-y-acceso-remoto)
9. [Fase 7 — Protección de Datos y Cifrado](#9-fase-7-protección-de-datos-y-cifrado)
10. [Fase 8 — Aplicación de Microsoft Security Baseline](#10-fase-8-aplicación-de-microsoft-security-baseline)
11. [Verificación y Validación de Cumplimiento](#11-verificación-y-validación-de-cumplimiento)
12. [Checklist de Cumplimiento Final](#12-checklist-de-cumplimiento-final)
13. [Referencias](#13-referencias)

---

## 1. Introducción y Alcance

Esta guía establece los procedimientos técnicos paso a paso para implementar el hardening de **Windows Server 2022**, cumpliendo simultáneamente con:

- **DISA STIG** (Security Technical Implementation Guide) — Windows Server 2022 V2R2
- **Microsoft Security Baseline** para Windows Server 2022 versión 22H2

El objetivo es llevar los servidores a un estado de cumplimiento verificable antes de su puesta en producción, reduciendo la superficie de ataque al mínimo operativo necesario.

### 1.1 Estándares de referencia

| Estándar | Organismo | Versión | Referencia |
|---|---|---|---|
| DISA STIG WN22 | DISA / DoD | V2R2 (2024) | public.cyber.mil/stigs |
| MS Security Baseline | Microsoft | 22H2 (2023) | aka.ms/baselines |
| CIS Benchmark | CIS Controls | v2.0 (2024) | cisecurity.org |
| NIST SP 800-53 | NIST | Rev 5 | csrc.nist.gov |

### 1.2 Clasificación de severidades STIG

| Categoría | CVSS Score | Descripción | Plazo de remediación |
|---|---|---|---|
| **CAT I** 🔴 | 7.0 – 10.0 | Crítico. Permite acceso no autorizado privilegiado o compromete confidencialidad/integridad | Inmediato |
| **CAT II** 🟠 | 4.0 – 6.9 | Alto. Degrada medidas de seguridad o puede ser explotado para acceso no autorizado | 30 días |
| **CAT III** 🟡 | 0.0 – 3.9 | Bajo. Vulnerabilidad menor que reduce la postura de seguridad | 90 días |

---

## 2. Prerequisitos y Preparación

### 2.1 Requisitos del entorno

| Componente | Requisito mínimo | Recomendado |
|---|---|---|
| Sistema Operativo | Windows Server 2022 Standard/Datacenter | WS 2022 Datacenter |
| Patch level | Todas las actualizaciones de seguridad aplicadas | Última CU disponible |
| PowerShell | 5.1 o superior | PowerShell 7.x |
| Acceso | Administrador local | Administrador de Dominio + LAPS |
| Backup | Snapshot / backup previo | Backup verificado + punto de restauración |
| GPO Infrastructure | Active Directory disponible | AD con jerarquía OU definida |

### 2.2 Herramientas necesarias

- **Microsoft Security Compliance Toolkit 1.0** → [aka.ms/SCT](https://aka.ms/SCT)
  - Incluye: Policy Analyzer, LGPO.exe, GP Reports
- **DISA SCC Tool** (SCAP Compliance Checker) → [public.cyber.mil](https://public.cyber.mil)
- **Windows SCAP Benchmark** (XCCDF) — DISA WN22 V2R2
- **Microsoft Baseline Security Analyzer** (reemplazado por Policy Analyzer)
- **PowerShell DSC** — opcional para automatización

### 2.3 Backup y snapshot previo

> ⚠️ **ADVERTENCIA CRÍTICA:** Crear un snapshot o backup completo del servidor ANTES de aplicar cualquier configuración. El hardening puede interrumpir servicios si no se adapta al rol específico del servidor.

**Paso 1:** Crear snapshot en el hipervisor (VMware/Hyper-V) o backup en Azure.

**Paso 2:** Ejecutar el siguiente script de inventario pre-hardening:

```powershell
# Inventario pre-hardening — ejecutar como Administrador
$outputPath = "C:\Hardening\pre_hardening_state.json"
New-Item -ItemType Directory -Force -Path "C:\Hardening" | Out-Null

$report = @{
    Timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Hostname     = $env:COMPUTERNAME
    Services     = Get-Service | Where-Object { $_.StartType -ne 'Disabled' } |
                   Select-Object Name, Status, StartType
    Features     = Get-WindowsFeature | Where-Object { $_.Installed -eq $true } |
                   Select-Object Name, DisplayName
    LocalAdmins  = Get-LocalGroupMember -Group 'Administrators' |
                   Select-Object Name, ObjectClass
    OpenPorts    = netstat -an
    AuditPolicy  = (auditpol /get /category:* 2>&1)
    OSInfo       = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer
}

$report | ConvertTo-Json -Depth 5 | Out-File $outputPath -Encoding UTF8
Write-Host "[OK] Inventario guardado en: $outputPath" -ForegroundColor Green
```

**Paso 3:** Verificar que el backup sea restaurable antes de continuar.

**Paso 4:** Notificar a los equipos de operaciones y ejecutar el proceso de change management correspondiente.

---

## 3. Fase 1 — Gestión de Cuentas y Autenticación

### 3.1 Política de contraseñas

> 📋 **Nota:** Si el servidor es miembro de dominio, estas políticas deben aplicarse vía GPO desde el Domain Controller.  
> **Ruta GPO:** `Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy`

| STIG ID | Configuración | Valor requerido | Severidad |
|---|---|---|---|
| WN22-AC-000030 | Enforce password history | 24 o más contraseñas | CAT II |
| WN22-AC-000040 | Maximum password age | 60 días máximo | CAT II |
| WN22-AC-000050 | Minimum password age | 1 día mínimo | CAT II |
| WN22-AC-000060 | Minimum password length | 14 caracteres | CAT II |
| WN22-AC-000070 | Password complexity requirements | Enabled | CAT II |
| WN22-AC-000080 | Store passwords using reversible encryption | Disabled | **CAT I** |

```powershell
# Aplicar política de contraseñas (servidores standalone)
net accounts /minpwlen:14 /maxpwage:60 /minpwage:1 /uniquepw:24

# Verificar configuración aplicada
net accounts
```

### 3.2 Política de bloqueo de cuenta

| STIG ID | Configuración | Valor requerido | Severidad |
|---|---|---|---|
| WN22-AC-000010 | Account lockout duration | 15 minutos mínimo | CAT II |
| WN22-AC-000020 | Account lockout threshold | 3 intentos máximo | CAT II |
| WN22-AC-000025 | Reset account lockout counter after | 15 minutos mínimo | CAT II |

```powershell
# Configurar política de bloqueo de cuenta
net accounts /lockoutthreshold:3 /lockoutduration:15 /lockoutwindow:15

# Verificar
net accounts
```

### 3.3 Hardening de cuentas locales

#### 3.3.1 Cuenta de Administrador y Guest (WN22-SO-000030 / WN22-SO-000040)

```powershell
# Renombrar la cuenta de administrador local (CAT II)
$newName = "LocalAdm_$(Get-Random -Minimum 1000 -Maximum 9999)"
Rename-LocalUser -Name 'Administrator' -NewName $newName
Write-Host "[OK] Administrador renombrado a: $newName" -ForegroundColor Green

# Deshabilitar cuenta Guest (CAT II)
Disable-LocalUser -Name 'Guest'
Write-Host "[OK] Cuenta Guest deshabilitada" -ForegroundColor Green

# Verificar estado de cuentas locales
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Format-Table -AutoSize
```

#### 3.3.2 Microsoft LAPS (Local Administrator Password Solution)

> 📋 **Requisito STIG:** WN22-00-000030 — Obligatorio para todos los servidores miembro de dominio.

**Paso 1:** Instalar LAPS en el servidor:

```powershell
# Instalar LAPS (Windows Server 2022 — LAPS nativo en versiones recientes)
# Si usas LAPS legacy:
# Descargar desde: https://www.microsoft.com/en-us/download/details.aspx?id=46899

# LAPS nativo (Windows LAPS — disponible desde KB5025230)
# Verificar disponibilidad
Get-Command Get-LapsAADPassword -ErrorAction SilentlyContinue
```

**Paso 2:** Extender el esquema de AD (ejecutar en Domain Controller como Enterprise Admin):

```powershell
# LAPS Legacy
Import-Module AdmPwd.PS
Update-AdmPwdADSchema
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Servers,DC=corp,DC=local"

# Windows LAPS nativo
Update-LapsADSchema
Set-LapsADComputerSelfPermission -Identity "OU=Servers,DC=corp,DC=local"
```

**Paso 3:** Configurar GPO para LAPS:

| Configuración | Ruta GPO | Valor |
|---|---|---|
| Enable local admin password management | Computer Config > Admin Templates > LAPS | Enabled |
| Password complexity | LAPS Settings | Letters+Numbers+Specials |
| Password length | LAPS Settings | 15 caracteres mínimo |
| Password age | LAPS Settings | 30 días |

### 3.4 Control de acceso con privilegios (UAC)

| STIG ID | Configuración | Valor requerido | Severidad |
|---|---|---|---|
| WN22-SO-000250 | UAC — Admin approval mode for built-in admin | Enabled | CAT II |
| WN22-SO-000260 | UAC — Behavior for elevation prompt (admins) | Prompt for credentials | CAT II |
| WN22-SO-000270 | UAC — Behavior for elevation prompt (standard) | Automatically deny | CAT II |
| WN22-SO-000280 | UAC — Detect application installations | Enabled | CAT II |
| WN22-SO-000290 | UAC — Run all admins in Admin Approval Mode | Enabled | **CAT I** |

```powershell
# Configurar UAC vía registro
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

Set-ItemProperty -Path $uacPath -Name "EnableLUA"                      -Value 1
Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin"     -Value 2  # Prompt for credentials
Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorUser"      -Value 0  # Automatically deny
Set-ItemProperty -Path $uacPath -Name "EnableInstallerDetection"       -Value 1
Set-ItemProperty -Path $uacPath -Name "FilterAdministratorToken"       -Value 1  # Admin approval mode
Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop"          -Value 1

Write-Host "[OK] UAC configurado correctamente" -ForegroundColor Green
```

---

## 4. Fase 2 — Política de Auditoría y Logging

### 4.1 Configuración de auditoría avanzada

> ⚠️ **IMPORTANTE:** Usar SIEMPRE la Política de Auditoría Avanzada (`auditpol`). NO mezclar con la auditoría básica de GPO.  
> **Referencia STIG:** WN22-AU-000500 al WN22-AU-000570

```powershell
# ================================================================
# STIG Audit Policy Configuration — Windows Server 2022
# Ejecutar como Administrador en PowerShell elevado
# ================================================================

Write-Host "Configurando política de auditoría avanzada..." -ForegroundColor Cyan

# Account Logon
auditpol /set /subcategory:"Credential Validation"              /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service"    /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"Computer Account Management"        /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events"    /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management"          /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management"            /success:enable /failure:enable

# Detailed Tracking
auditpol /set /subcategory:"Plug and Play Events"               /success:enable
auditpol /set /subcategory:"Process Creation"                   /success:enable /failure:enable

# Logon/Logoff
auditpol /set /subcategory:"Account Lockout"                    /success:enable /failure:enable
auditpol /set /subcategory:"Group Membership"                   /success:enable
auditpol /set /subcategory:"Logoff"                             /success:enable
auditpol /set /subcategory:"Logon"                              /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events"          /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon"                      /success:enable /failure:enable

# Object Access
auditpol /set /subcategory:"Removable Storage"                  /success:enable /failure:enable
auditpol /set /subcategory:"File Share"                         /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share"                /failure:enable

# Policy Change
auditpol /set /subcategory:"Audit Policy Change"                /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change"       /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change"        /success:enable

# Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use"            /success:enable /failure:enable

# System
auditpol /set /subcategory:"IPsec Driver"                       /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events"                /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change"              /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension"          /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity"                   /success:enable /failure:enable

Write-Host "[OK] Política de auditoría configurada" -ForegroundColor Green

# Verificar configuración
auditpol /get /category:*
```

### 4.2 Tamaño y retención de logs de eventos (WN22-AU-000500)

```powershell
# Configurar tamaño y retención de Event Logs
$logConfig = @{
    "Security"    = 1024MB  # STIG: mínimo 1 GB
    "System"      = 32MB
    "Application" = 32MB
}

foreach ($log in $logConfig.GetEnumerator()) {
    $maxSize = $log.Value / 1KB  # Convertir a KB para wevtutil
    wevtutil sl $log.Key /ms:($log.Value.ToString().Replace("MB","") + "000000")
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$($log.Key)" `
                     -Name "MaxSize" -Value ([int]($log.Value / 1KB * 1024)) -ErrorAction SilentlyContinue
    Write-Host "[OK] Log '$($log.Key)' configurado a $($log.Value)" -ForegroundColor Green
}

# Configurar retención: sobrescribir eventos antiguos si es necesario
wevtutil sl Security /rt:false   # Overwrite as needed
wevtutil sl System   /rt:false
wevtutil sl Application /rt:false
```

### 4.3 Habilitación de Command Line Auditing (WN22-AU-000030)

```powershell
# Habilitar auditoría de línea de comandos en Process Creation
$auditKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $auditKey -Force | Out-Null
Set-ItemProperty -Path $auditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

Write-Host "[OK] Command Line Auditing habilitado" -ForegroundColor Green
```

### 4.4 Centralización de logs — Windows Event Forwarding

```powershell
# Configurar WEF (Windows Event Forwarding) para centralización
# En el servidor colector (Collector):
winrm quickconfig -quiet
wecutil qc -quiet

# En los servidores fuente (configurar vía GPO):
# Computer Config > Admin Templates > Windows Components > Event Forwarding
# "Configure target Subscription Manager" → Enabled
# Value: Server=http://SIEM-COLLECTOR:5985/wsman/SubscriptionManager/WEC
```

---

## 5. Fase 3 — Configuración de Servicios y Features

### 5.1 Deshabilitar servicios innecesarios

> ⚠️ **Adaptar según el rol del servidor.** Un servidor de archivos requiere servicios distintos a un servidor web.

```powershell
# Lista de servicios a deshabilitar según DISA STIG
$servicesToDisable = @(
    @{ Name = "Browser";        STIG = "WN22-00-000310"; Desc = "Computer Browser" },
    @{ Name = "iprip";          STIG = "WN22-00-000320"; Desc = "Routing and Remote Access (RIPv1)" },
    @{ Name = "simptcp";        STIG = "WN22-00-000330"; Desc = "Simple TCP/IP Services" },
    @{ Name = "sacsvr";         STIG = "WN22-00-000350"; Desc = "Special Administration Console Helper" },
    @{ Name = "SSDPSRV";        STIG = "WN22-00-000360"; Desc = "SSDP Discovery" },
    @{ Name = "upnphost";       STIG = "WN22-00-000370"; Desc = "UPnP Device Host" },
    @{ Name = "WMSvc";          STIG = "WN22-00-000380"; Desc = "Web Management Service (IIS)" },
    @{ Name = "WinRM";          STIG = "WN22-00-000390"; Desc = "Windows Remote Management (si no se usa)" },
    @{ Name = "Fax";            STIG = "WN22-00-000400"; Desc = "Fax Service" },
    @{ Name = "TelnetC";        STIG = "WN22-00-000410"; Desc = "Telnet Client" },
    @{ Name = "FTPSVC";         STIG = "WN22-00-000420"; Desc = "FTP Service" },
    @{ Name = "SNMPTRAP";       STIG = "WN22-00-000430"; Desc = "SNMP Trap" },
    @{ Name = "RasAuto";        STIG = "WN22-00-000440"; Desc = "Remote Access Auto Connection Manager" }
)

foreach ($svc in $servicesToDisable) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc.Name -StartupType Disabled
        Write-Host "[OK] [$($svc.STIG)] Servicio '$($svc.Desc)' deshabilitado" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Servicio '$($svc.Name)' no encontrado (puede no estar instalado)" -ForegroundColor Yellow
    }
}
```

### 5.2 Deshabilitar Windows Features innecesarias

```powershell
# Remover features innecesarias según STIG
$featuresToRemove = @(
    "SMB1Protocol",                # WN22-00-000160 — CAT I: SMBv1 debe estar deshabilitado
    "Telnet-Client",               # WN22-00-000200 — CAT II
    "TFTP",                        # WN22-00-000210 — CAT II
    "Internet-Explorer-Optional-amd64",  # WN22-00-000230 — CAT I
    "MicrosoftWindowsPowerShellV2", # WN22-00-000020 — CAT II: PowerShell v2
    "MicrosoftWindowsPowerShellV2Root"
)

foreach ($feature in $featuresToRemove) {
    $state = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
    if ($state -and $state.State -eq "Enabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
        Write-Host "[OK] Feature '$feature' deshabilitada" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Feature '$feature' ya deshabilitada o no encontrada" -ForegroundColor Yellow
    }
}
```

### 5.3 Deshabilitar SMBv1 (WN22-00-000160 — CAT I)

> 🔴 **CAT I CRÍTICO:** SMBv1 permite ataques como EternalBlue/WannaCry. Debe eliminarse en todos los servidores sin excepción.

```powershell
# Deshabilitar SMBv1 completamente
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart

# Deshabilitar también vía registro
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                 -Name "SMB1" -Value 0 -Type DWORD

# Verificar
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol
Write-Host "[OK] SMBv1 deshabilitado" -ForegroundColor Green
```

### 5.4 Hardening de SMBv2/v3

```powershell
# Configuraciones de seguridad para SMBv2/v3
Set-SmbServerConfiguration -EnableSMB2Protocol                $true   -Force
Set-SmbServerConfiguration -RequireSecuritySignature          $true   -Force
Set-SmbServerConfiguration -EnableSecuritySignature           $true   -Force
Set-SmbServerConfiguration -EncryptData                       $true   -Force  # Requiere clientes Win 8+
Set-SmbServerConfiguration -RejectUnencryptedAccess           $true   -Force
Set-SmbServerConfiguration -RestrictNullSessAccess            $true   -Force
Set-SmbServerConfiguration -AutoShareServer                   $false  -Force  # Deshabilitar shares admin
Set-SmbServerConfiguration -AutoShareWorkstation              $false  -Force

Write-Host "[OK] SMBv2/v3 configurado con firma y cifrado requeridos" -ForegroundColor Green
```

---

## 6. Fase 4 — Seguridad de Red y Firewall

### 6.1 Windows Defender Firewall (WN22-NM-000010)

```powershell
# Habilitar el firewall en todos los perfiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Configurar comportamiento por defecto
Set-NetFirewallProfile -Profile Domain  -DefaultInboundAction Block -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Public  -DefaultInboundAction Block -DefaultOutboundAction Allow

# Logging del firewall (requerido por STIG)
Set-NetFirewallProfile -Profile Domain  -LogBlocked True -LogMaxSizeKilobytes 16384 -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall-domain.log"
Set-NetFirewallProfile -Profile Private -LogBlocked True -LogMaxSizeKilobytes 16384 -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall-private.log"
Set-NetFirewallProfile -Profile Public  -LogBlocked True -LogMaxSizeKilobytes 16384 -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall-public.log"

Write-Host "[OK] Windows Defender Firewall configurado" -ForegroundColor Green
```

### 6.2 Reglas de firewall — Bloqueo de protocolos inseguros

```powershell
# Bloquear Telnet entrante (puerto 23)
New-NetFirewallRule -DisplayName "STIG-Block-Telnet" -Direction Inbound `
    -Protocol TCP -LocalPort 23 -Action Block -Profile Any -Enabled True

# Bloquear FTP sin cifrar (puerto 21)
New-NetFirewallRule -DisplayName "STIG-Block-FTP" -Direction Inbound `
    -Protocol TCP -LocalPort 21 -Action Block -Profile Any -Enabled True

# Bloquear NetBIOS (puertos 137-139)
New-NetFirewallRule -DisplayName "STIG-Block-NetBIOS-137" -Direction Inbound `
    -Protocol UDP -LocalPort 137 -Action Block -Profile Any -Enabled True
New-NetFirewallRule -DisplayName "STIG-Block-NetBIOS-138" -Direction Inbound `
    -Protocol UDP -LocalPort 138 -Action Block -Profile Any -Enabled True
New-NetFirewallRule -DisplayName "STIG-Block-NetBIOS-139" -Direction Inbound `
    -Protocol TCP -LocalPort 139 -Action Block -Profile Any -Enabled True

Write-Host "[OK] Reglas de bloqueo de protocolos inseguros aplicadas" -ForegroundColor Green
```

### 6.3 Configuración de red — Deshabilitar protocolos inseguros

```powershell
# Deshabilitar NetBIOS over TCP/IP (WN22-MS-000015)
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disabled
}

# Deshabilitar LLMNR (Link-Local Multicast Name Resolution) — CAT II
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
New-Item -Path $llmnrPath -Force | Out-Null
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0

# Deshabilitar IPv6 si no se usa (ajustar según entorno)
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
#                  -Name "DisabledComponents" -Value 0xFF -Type DWORD

Write-Host "[OK] Configuración de red endurecida" -ForegroundColor Green
```

### 6.4 Deshabilitar protocolos de autenticación débiles

```powershell
# Deshabilitar LM y NTLMv1 — mantener NTLMv2 mínimo (WN22-SO-000050)
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5
# Valores: 5 = Solo NTLMv2, rechazar LM y NTLM

# Deshabilitar almacenamiento de hash LM (WN22-SO-000060)
Set-ItemProperty -Path $lsaPath -Name "NoLMHash" -Value 1

# Requerir NTLMv2 en el cliente
Set-ItemProperty -Path $lsaPath -Name "RestrictSendingNTLMTraffic" -Value 2

Write-Host "[OK] LM/NTLMv1 deshabilitado — solo NTLMv2 permitido" -ForegroundColor Green
```

---

## 7. Fase 5 — Configuraciones de Seguridad del Sistema

### 7.1 Protección de la pantalla de inicio de sesión

```powershell
# Ocultar último usuario en pantalla de inicio de sesión (WN22-SO-000140)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "DontDisplayLastUserName" -Value 1

# Mensaje legal en pantalla de inicio (WN22-SO-000150 / WN22-SO-000160) — CAT II
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LegalNoticeCaption" -Value "SISTEMA DE ACCESO RESTRINGIDO"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LegalNoticeText" -Value "Este sistema es de uso exclusivo para personal autorizado. Todas las actividades son monitoreadas y registradas. El acceso no autorizado está prohibido y será perseguido conforme a la legislación vigente."

# No mostrar nombre de usuario hasta que ingrese contraseña
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "DontDisplayUserName" -Value 1

Write-Host "[OK] Pantalla de inicio de sesión configurada" -ForegroundColor Green
```

### 7.2 Protección de memoria y kernel

```powershell
# Habilitar DEP (Data Execution Prevention) para todos los programas
bcdedit /set nx AlwaysOn

# Habilitar Structured Exception Handler Overwrite Protection (SEHOP)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -Name "DisableExceptionChainValidation" -Value 0

# Credential Guard — requiere hardware compatible (WN22-00-000010)
# Habilitar Virtualization Based Security
$lsaRunPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaRunPath -Name "LsaCfgFlags" -Value 1  # Credential Guard con UEFI lock

# Verificar Credential Guard
$cgStatus = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
Write-Host "[INFO] Credential Guard estado: $cgStatus"

# Habilitar Secure Boot y UEFI (verificar en BIOS/UEFI)
Confirm-SecureBootUEFI
```

### 7.3 Windows Defender Antivirus (WN22-00-000210)

```powershell
# Verificar que Defender está habilitado y activo
$defenderStatus = Get-MpComputerStatus

if ($defenderStatus.AMServiceEnabled -eq $true) {
    Write-Host "[OK] Windows Defender habilitado" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Windows Defender NO está habilitado — remediar inmediatamente" -ForegroundColor Red
}

# Configurar actualizaciones de definiciones
Set-MpPreference -SignatureUpdateInterval 1          # Actualizar cada 1 hora
Set-MpPreference -DisableRealtimeMonitoring $false   # Asegurar protección en tiempo real
Set-MpPreference -DisableIOAVProtection $false        # Protección de descargas
Set-MpPreference -DisableScriptScanning $false        # Escaneo de scripts
Set-MpPreference -EnableNetworkProtection Enabled     # Protección de red
Set-MpPreference -PUAProtection Enabled               # Protección contra PUA
Set-MpPreference -SubmitSamplesConsent SendSafeSamples

# Habilitar Cloud Protection
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -CloudBlockLevel High

# Forzar actualización de firmas
Update-MpSignature
Write-Host "[OK] Windows Defender configurado correctamente" -ForegroundColor Green
```

### 7.4 Windows Update y gestión de parches

```powershell
# Configurar Windows Update (WN22-00-000050)
$wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
New-Item -Path $wuPath -Force | Out-Null

Set-ItemProperty -Path $wuPath -Name "NoAutoUpdate"        -Value 0  # Habilitar auto-update
Set-ItemProperty -Path $wuPath -Name "AUOptions"           -Value 4  # Auto download and schedule install
Set-ItemProperty -Path $wuPath -Name "ScheduledInstallDay" -Value 0  # Every day
Set-ItemProperty -Path $wuPath -Name "ScheduledInstallTime"-Value 3  # 3:00 AM

# Si se usa WSUS, configurar el servidor
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
#     -Name "WUServer" -Value "http://wsus-server.corp.local:8530"
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
#     -Name "WUStatusServer" -Value "http://wsus-server.corp.local:8530"

Write-Host "[OK] Windows Update configurado" -ForegroundColor Green
```

### 7.5 Restricciones de ejecución — AppLocker / WDAC

```powershell
# Configurar reglas básicas de AppLocker (WN22-00-000140)
# Habilitar el servicio Application Identity
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service AppIDSvc

# Crear reglas de AppLocker por defecto
$policy = Get-AppLockerPolicy -Local
if ($policy.RuleCollections.Count -eq 0) {
    # Crear reglas predeterminadas para Exe, MSI, Scripts
    New-AppLockerPolicy -RuleType Publisher,Path,Hash -User Everyone `
        -RuleNamePrefix "STIG" | Set-AppLockerPolicy -Local
    Write-Host "[OK] AppLocker configurado con reglas predeterminadas" -ForegroundColor Green
}

# Configurar PowerShell Constrained Language Mode (para sistemas de alta seguridad)
# [System.Environment]::SetEnvironmentVariable("__PSLockdownPolicy", "4", "Machine")
```

---

## 8. Fase 6 — Hardening de Remote Desktop y Acceso Remoto

### 8.1 Remote Desktop Protocol (RDP)

```powershell
# Configurar nivel de seguridad RDP (WN22-CC-000270)
$rdpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
New-Item -Path $rdpPath -Force | Out-Null

# Nivel de seguridad y cifrado
Set-ItemProperty -Path $rdpPath -Name "SecurityLayer"         -Value 2    # SSL/TLS requerido
Set-ItemProperty -Path $rdpPath -Name "MinEncryptionLevel"    -Value 3    # High encryption (128-bit)
Set-ItemProperty -Path $rdpPath -Name "UserAuthentication"    -Value 1    # NLA obligatorio (CAT II)
Set-ItemProperty -Path $rdpPath -Name "fAllowUnsolicited"     -Value 0    # Deshabilitar Remote Assistance
Set-ItemProperty -Path $rdpPath -Name "fAllowToGetHelp"       -Value 0    # Deshabilitar Remote Assistance
Set-ItemProperty -Path $rdpPath -Name "DisablePasswordSaving" -Value 1    # No guardar contraseñas RDP
Set-ItemProperty -Path $rdpPath -Name "fEncryptRPCTraffic"    -Value 1    # Cifrar tráfico RPC
Set-ItemProperty -Path $rdpPath -Name "MaxIdleTime"           -Value 900000   # 15 min timeout (ms)
Set-ItemProperty -Path $rdpPath -Name "MaxDisconnectionTime"  -Value 900000   # 15 min disconnected

Write-Host "[OK] RDP configurado con NLA y TLS requeridos" -ForegroundColor Green
```

### 8.2 Cambiar puerto RDP (recomendación adicional)

```powershell
# Cambiar puerto RDP del predeterminado 3389 (defensa en profundidad)
$newPort = 3390  # Cambiar según política interna
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "PortNumber" -Value $newPort -Type DWORD

# Actualizar regla de firewall
New-NetFirewallRule -DisplayName "RDP-Custom-Port" -Direction Inbound `
    -Protocol TCP -LocalPort $newPort -Action Allow -Profile Domain -Enabled True

Write-Host "[OK] Puerto RDP cambiado a $newPort — Actualizar reglas de firewall" -ForegroundColor Yellow
```

### 8.3 WinRM — Windows Remote Management

```powershell
# Si WinRM es necesario, asegurar con HTTPS y autenticación Kerberos
# Si NO es necesario, deshabilitar:
Stop-Service WinRM -Force
Set-Service WinRM -StartupType Disabled
Write-Host "[OK] WinRM deshabilitado" -ForegroundColor Green

# Si WinRM ES necesario:
<#
winrm quickconfig -transport:HTTPS
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\Auth\Digest -Value $false
Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true
Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
#>
```

---

## 9. Fase 7 — Protección de Datos y Cifrado

### 9.1 BitLocker (WN22-00-000030)

```powershell
# Verificar y configurar BitLocker en volúmenes del sistema
# Requiere TPM 2.0 o superior

# Verificar TPM
$tpm = Get-Tpm
if ($tpm.TpmPresent -and $tpm.TpmEnabled) {
    Write-Host "[OK] TPM disponible — Versión: $($tpm.ManufacturerVersion)" -ForegroundColor Green
} else {
    Write-Host "[WARN] TPM no disponible — BitLocker requerirá contraseña de inicio" -ForegroundColor Yellow
}

# Habilitar BitLocker en la unidad del sistema (C:)
# Prerrequisito: Instalar feature BitLocker
Install-WindowsFeature BitLocker -IncludeManagementTools

# Configurar BitLocker con TPM + PIN (alta seguridad)
# Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 `
#     -TpmAndPinProtector -Pin (ConvertTo-SecureString "TuPIN" -AsPlainText -Force)

# Verificar estado de cifrado
Get-BitLockerVolume | Select-Object MountPoint, EncryptionMethod, VolumeStatus, ProtectionStatus
```

### 9.2 Cifrado TLS — Deshabilitar protocolos inseguros

```powershell
# Función helper para configurar protocolos TLS/SSL
function Set-CryptoProtocol {
    param(
        [string]$Protocol,
        [string]$Role,        # Server o Client
        [bool]$Enabled
    )
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    $path = "$basePath\$Protocol\$Role"
    New-Item -Path $path -Force | Out-Null
    Set-ItemProperty -Path $path -Name "Enabled"        -Value ([int]$Enabled) -Type DWORD
    Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value ([int](-not $Enabled)) -Type DWORD
    Write-Host "$(if($Enabled){'[ON]'}else{'[OFF]'}) $Protocol ($Role)" -ForegroundColor $(if($Enabled){'Green'}else{'Red'})
}

# ═══ Deshabilitar protocolos inseguros ═══
Set-CryptoProtocol "SSL 2.0"   "Server" $false
Set-CryptoProtocol "SSL 2.0"   "Client" $false
Set-CryptoProtocol "SSL 3.0"   "Server" $false
Set-CryptoProtocol "SSL 3.0"   "Client" $false
Set-CryptoProtocol "TLS 1.0"   "Server" $false
Set-CryptoProtocol "TLS 1.0"   "Client" $false
Set-CryptoProtocol "TLS 1.1"   "Server" $false
Set-CryptoProtocol "TLS 1.1"   "Client" $false

# ═══ Habilitar protocolos seguros ═══
Set-CryptoProtocol "TLS 1.2"   "Server" $true
Set-CryptoProtocol "TLS 1.2"   "Client" $true
Set-CryptoProtocol "TLS 1.3"   "Server" $true
Set-CryptoProtocol "TLS 1.3"   "Client" $true

# ═══ Deshabilitar cipher suites débiles ═══
$weakCiphers = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL"
)

foreach ($cipher in $weakCiphers) {
    New-Item -Path $cipher -Force | Out-Null
    Set-ItemProperty -Path $cipher -Name "Enabled" -Value 0 -Type DWORD
}

Write-Host "[OK] Protocolos TLS configurados — Reinicio requerido" -ForegroundColor Yellow
```

---

## 10. Fase 8 — Aplicación de Microsoft Security Baseline

### 10.1 Descarga y preparación del SCT

```powershell
# 1. Descargar Microsoft Security Compliance Toolkit desde:
#    https://www.microsoft.com/en-us/download/details.aspx?id=55319
# 2. Extraer en C:\SCT

$sctPath = "C:\SCT"
$baselinePath = "$sctPath\Windows Server 2022 Security Baseline\GPOs"

# Verificar que el SCT está disponible
if (Test-Path $sctPath) {
    Write-Host "[OK] Security Compliance Toolkit encontrado en $sctPath" -ForegroundColor Green
    Get-ChildItem $sctPath
} else {
    Write-Host "[ERROR] Descargar SCT desde aka.ms/SCT y extraer en $sctPath" -ForegroundColor Red
}
```

### 10.2 Aplicar baseline vía LGPO.exe

```powershell
# Aplicar la Microsoft Security Baseline usando LGPO.exe
# LGPO.exe está incluido en el Security Compliance Toolkit

$lgpoPath = "$sctPath\LGPO\LGPO.exe"
$gpoPath  = "$sctPath\Windows Server 2022 Security Baseline\GPOs"

if (Test-Path $lgpoPath) {
    # Aplicar Computer Configuration
    & $lgpoPath /g "$gpoPath\{DOMAIN-CONTROLLER-GPO}\DomainSysvol\GPO\Machine"

    Write-Host "[OK] Microsoft Security Baseline aplicada vía LGPO" -ForegroundColor Green
} else {
    Write-Host "[WARN] LGPO.exe no encontrado — Aplicar baseline manualmente vía Group Policy" -ForegroundColor Yellow
}

# Forzar actualización de políticas
gpupdate /force
```

### 10.3 Configuraciones adicionales del MS Baseline

```powershell
# Configuraciones complementarias de la Microsoft Security Baseline

# Deshabilitar autoplay/autorun (WN22-CC-000080)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoDriveTypeAutoRun" -Value 255

# Deshabilitar Remote Registry (WN22-SO-000200)
Stop-Service RemoteRegistry -Force
Set-Service RemoteRegistry -StartupType Disabled

# Deshabilitar administración remota anónima
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymous" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymousSAM" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "EveryoneIncludesAnonymous" -Value 0

# Deshabilitar enumeración de cuentas SAM por anónimos
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymous" -Value 1

# Deshabilitar WDigest authentication (prevenir credenciales en memoria)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -Value 0

# Habilitar Protected Users security group enforcement
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "TokenLeakDetectDelaySecs" -Value 30

Write-Host "[OK] Configuraciones adicionales del MS Baseline aplicadas" -ForegroundColor Green
```

---

## 11. Verificación y Validación de Cumplimiento

### 11.1 Script de verificación STIG — Check rápido

```powershell
# ================================================================
# Script de Verificación STIG — Windows Server 2022
# Genera reporte de cumplimiento básico
# ================================================================

$results = @()

function Check-STIG {
    param($ID, $Description, $Check, $Expected, $Severity)
    $actual = & $Check
    $pass = $actual -eq $Expected -or $actual -like "*$Expected*"
    $results += [PSCustomObject]@{
        STIG_ID     = $ID
        Description = $Description
        Severity    = $Severity
        Status      = if ($pass) { "PASS" } else { "FAIL" }
        Expected    = $Expected
        Actual      = $actual
    }
}

# Verificar SMBv1
Check-STIG "WN22-00-000160" "SMBv1 deshabilitado" `
    { (Get-SmbServerConfiguration).EnableSMB1Protocol } `
    "False" "CAT I"

# Verificar UAC habilitado
Check-STIG "WN22-SO-000290" "UAC habilitado" `
    { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA } `
    "1" "CAT I"

# Verificar NLA en RDP
Check-STIG "WN22-CC-000270" "NLA requerida en RDP" `
    { (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services").UserAuthentication } `
    "1" "CAT II"

# Verificar deshabilitación Guest
Check-STIG "WN22-SO-000040" "Cuenta Guest deshabilitada" `
    { (Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled } `
    "False" "CAT II"

# Verificar política contraseñas
Check-STIG "WN22-AC-000060" "Longitud mínima de contraseña 14" `
    { (net accounts | Select-String "Minimum password length").ToString().Trim() } `
    "14" "CAT II"

# Verificar WDigest
Check-STIG "WN22-MS-000075" "WDigest deshabilitado" `
    { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest").UseLogonCredential } `
    "0" "CAT II"

# Mostrar reporte
Write-Host "`n═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  REPORTE DE CUMPLIMIENTO STIG — Windows Server 2022" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Servidor : $env:COMPUTERNAME"
Write-Host "  Fecha    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan

$pass  = ($results | Where-Object { $_.Status -eq "PASS" }).Count
$fail  = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
$total = $results.Count

$results | Format-Table -AutoSize

Write-Host "`n RESULTADOS: $pass PASS | $fail FAIL | $total TOTAL" -ForegroundColor $(if($fail -eq 0){'Green'}else{'Yellow'})

# Exportar reporte
$reportFile = "C:\Hardening\stig_compliance_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $reportFile -NoTypeInformation
Write-Host " Reporte exportado: $reportFile`n" -ForegroundColor Green
```

### 11.2 Verificación con DISA SCC Tool

```
PROCEDIMIENTO MANUAL — DISA SCAP Compliance Checker:

1. Descargar SCC Tool desde: https://public.cyber.mil/stigs/scap/
2. Descargar el contenido SCAP/XCCDF para Windows Server 2022 (DISA WN22 V2R2)
3. Instalar SCC Tool con privilegios de administrador
4. Ejecutar el SCC Tool:
   a. Seleccionar: "Start a new scan"
   b. Contenido: "U_MS_Windows_Server_2022_V2R2_STIG_SCAP_1-3_Benchmark.zip"
   c. Target: "Local Computer" o especificar hosts remotos
   d. Perfil: "MAC-1_Classified" o "MAC-2_Sensitive" según clasificación
5. Ejecutar el escaneo (20-30 min aprox.)
6. Revisar el reporte HTML/XML generado en:
   %USERPROFILE%\SCC\Results\
7. Remediar todos los findings CAT I (críticos) antes de pasar a producción
```

### 11.3 Verificación con Policy Analyzer (MS Security Baseline)

```
PROCEDIMIENTO — Policy Analyzer:

1. Abrir PolicyAnalyzer.exe desde el SCT
2. File > Add > "Files from GPOs in a folder"
3. Seleccionar la carpeta del MS Security Baseline descargado
4. Comparar contra: "Effective Policy" (política actual del servidor)
5. Exportar diferencias a Excel para documentar gaps
6. Aplicar correcciones mediante LGPO.exe o GPO de dominio
```

---

## 12. Checklist de Cumplimiento Final

### Fase de Cuentas y Autenticación

| # | Control | STIG ID | Severidad | Verificado |
|---|---|---|---|:---:|
| 1 | Historial de contraseñas ≥ 24 | WN22-AC-000030 | CAT II | ☐ |
| 2 | Antigüedad máxima contraseña ≤ 60 días | WN22-AC-000040 | CAT II | ☐ |
| 3 | Longitud mínima contraseña ≥ 14 caracteres | WN22-AC-000060 | CAT II | ☐ |
| 4 | Complejidad de contraseña habilitada | WN22-AC-000070 | CAT II | ☐ |
| 5 | Sin almacenamiento reversible de contraseñas | WN22-AC-000080 | **CAT I** | ☐ |
| 6 | Bloqueo de cuenta ≤ 3 intentos | WN22-AC-000020 | CAT II | ☐ |
| 7 | Cuenta Administrator renombrada | WN22-SO-000030 | CAT II | ☐ |
| 8 | Cuenta Guest deshabilitada | WN22-SO-000040 | CAT II | ☐ |
| 9 | LAPS configurado y activo | WN22-00-000030 | CAT II | ☐ |
| 10 | UAC en modo Admin Approval | WN22-SO-000290 | **CAT I** | ☐ |

### Fase de Auditoría y Logging

| # | Control | STIG ID | Severidad | Verificado |
|---|---|---|---|:---:|
| 11 | Auditoría de Account Logon habilitada | WN22-AU-000030 | CAT II | ☐ |
| 12 | Auditoría de Account Management habilitada | WN22-AU-000040 | CAT II | ☐ |
| 13 | Auditoría de Logon/Logoff habilitada | WN22-AU-000050 | CAT II | ☐ |
| 14 | Auditoría de Process Creation habilitada | WN22-AU-000060 | CAT II | ☐ |
| 15 | Command Line Auditing habilitado | WN22-AU-000030 | CAT II | ☐ |
| 16 | Event Log Security ≥ 1 GB | WN22-AU-000500 | CAT II | ☐ |

### Fase de Servicios y Protocolos

| # | Control | STIG ID | Severidad | Verificado |
|---|---|---|---|:---:|
| 17 | SMBv1 completamente deshabilitado | WN22-00-000160 | **CAT I** | ☐ |
| 18 | PowerShell v2 deshabilitado | WN22-00-000020 | CAT II | ☐ |
| 19 | Internet Explorer desinstalado | WN22-00-000230 | **CAT I** | ☐ |
| 20 | Telnet Client no instalado | WN22-00-000200 | CAT II | ☐ |
| 21 | LM/NTLMv1 deshabilitado | WN22-SO-000050 | **CAT I** | ☐ |
| 22 | WDigest Authentication deshabilitado | WN22-MS-000075 | CAT II | ☐ |

### Fase de Red y Acceso Remoto

| # | Control | STIG ID | Severidad | Verificado |
|---|---|---|---|:---:|
| 23 | Firewall habilitado en todos los perfiles | WN22-NM-000010 | CAT I | ☐ |
| 24 | NLA requerida en RDP | WN22-CC-000270 | CAT II | ☐ |
| 25 | Cifrado RDP en nivel High (128-bit) | WN22-CC-000280 | CAT II | ☐ |
| 26 | Timeout de sesión RDP ≤ 15 minutos | WN22-CC-000300 | CAT II | ☐ |
| 27 | LLMNR deshabilitado | WN22-MS-000015 | CAT II | ☐ |

### Fase de Sistema y Cifrado

| # | Control | STIG ID | Severidad | Verificado |
|---|---|---|---|:---:|
| 28 | Credential Guard habilitado | WN22-00-000010 | CAT II | ☐ |
| 29 | DEP habilitado (AlwaysOn) | WN22-EP-000001 | CAT II | ☐ |
| 30 | Windows Defender habilitado y actualizado | WN22-00-000210 | **CAT I** | ☐ |
| 31 | BitLocker en volúmenes del sistema | WN22-00-000030 | CAT II | ☐ |
| 32 | TLS 1.0/1.1 deshabilitados | WN22-SC-000010 | CAT II | ☐ |
| 33 | SSL 2.0/3.0 deshabilitados | WN22-SC-000020 | **CAT I** | ☐ |
| 34 | Mensaje legal en pantalla de inicio | WN22-SO-000150 | CAT II | ☐ |
| 35 | Microsoft Security Baseline aplicada | MS-BASELINE | CAT II | ☐ |

---

## 13. Referencias

| Recurso | URL |
|---|---|
| DISA STIG — Windows Server 2022 V2R2 | https://public.cyber.mil/stigs/downloads/ |
| DISA SCC Tool (SCAP Compliance Checker) | https://public.cyber.mil/stigs/scap/ |
| Microsoft Security Compliance Toolkit | https://aka.ms/SCT |
| Microsoft Security Baseline WS2022 | https://aka.ms/baselines |
| CIS Benchmark Windows Server 2022 | https://cisecurity.org/benchmark/microsoft_windows_server |
| NIST SP 800-53 Rev 5 | https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final |
| NIST SP 800-123 (Server Security Guide) | https://csrc.nist.gov/publications/detail/sp/800-123/final |
| Windows LAPS Documentation | https://aka.ms/laps |
| Microsoft Defender for Endpoint | https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint |

---

> **Nota de revisión:** Esta guía debe revisarse con cada nueva versión del STIG (publicadas trimestralmente por DISA) y con cada actualización de la Microsoft Security Baseline. Verificar siempre en public.cyber.mil y aka.ms/baselines para la versión más reciente.  
> Última revisión: 2025 | DISA STIG WN22 V2R2 | MS Baseline 22H2
