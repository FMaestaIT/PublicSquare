<#
Richiede .NET Framework 4.7.2 or higher e i seguenti moduli Azure:
 - Az.Accounts
 - Az.Resources
 - Az.ConnectedMachine
#>


param(
	[Parameter(Mandatory=$true)]
	[string]$SubID
)


# Verifica la presenza dei moduli PowerShell necessari
$requiredModules = @('Az.Accounts', 'Az.Resources', 'Az.ConnectedMachine')
$missingModules = @()

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        $missingModules += $module
    }
}

if ($missingModules.Count -gt 0) {
    Write-Host "I seguenti moduli PowerShell richiesti non sono installati: $($missingModules -join ', ')"
    Write-Host "Procedo alla installazione dei moduli mancanti"
	foreach ($mod in $missingModules){
		install-module -name $mod -AllowClobber -Force
		import-module -name $mod -Force
	}
}

# Connessione all'account Azure
Connect-AzAccount

set-AzContext -Subscription $SubID

# Ottieni tutte le VM Azure Arc-enabled Server
$arcServers = Get-AzConnectedMachine

# Ciclo su ogni VM e installa l'estensione di script personalizzato in base al tipo di sistema operativo
foreach ($server in $arcServers) {
    $resourceGroupName = $server.ResourceGroupName
    $serverName = $server.Name
    $osType = $server.OSName

    # Determina l'estensione di script personalizzato e il comando in base al tipo di sistema operativo
    $extensionName = ''
    $extensionVersion = ''
    $command = ''

    switch ($osType) {
        "Windows" {
            $extensionName = 'CustomScriptExtensionForWindows'
            $extensionVersion = '2.1'
            $command = '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; invoke-WebRequest -URI https://stgaccwswe001.blob.core.windows.net/omsagent/MOMAgent.msi -OutFile "MOMAgent.msi"; cmd.exe /c "C:\Windows\System32\msiexec.exe /x MOMAgent.msi /qb"'
        }
        "Linux" {
            $extensionName = 'CustomScriptExtensionForLinux'
            $extensionVersion = '2.1'
            $command = 'wget https://raw.githubusercontent.com/Microsoft/OMS-Agent-for-Linux/master/installer/scripts/onboard_agent.sh && sh onboard_agent.sh --purge'
        }
        # Aggiungi altri casi per altri tipi di sistema operativo, se necessario
        default {
            Write-Host "Tipo di sistema operativo non supportato: $osType"
            continue
        }
    }

    # Installa l'estensione di script personalizzato
    $extensionParams = @{
        ResourceGroupName = $resourceGroupName
        VMName = $serverName
        Name = $extensionName
        Publisher = 'Microsoft.Azure.Extensions'
        ExtensionType = 'CustomScript'
        TypeHandlerVersion = $extensionVersion
    }
    
    Set-AzVMExtension -ExtensionName $extensionParams.Name `
        -ResourceGroupName $extensionParams.ResourceGroupName `
        -VMName $extensionParams.VMName `
        -Publisher $extensionParams.Publisher `
        -ExtensionType $extensionParams.ExtensionType `
        -TypeHandlerVersion $extensionParams.TypeHandlerVersion `
        -SettingString "{ `"$command`" }" `
        -Location $server.Location
}
