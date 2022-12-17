param (
    [Parameter (Mandatory= $false)] 
    [string] $SubId, 
    [Parameter (Mandatory= $false)]
    [string] $Server, 
    [Parameter (Mandatory= $false)]
    [PSCredential] $Cred, 
    [Parameter (Mandatory= $false)]
    [string] $Database, 
    [Parameter (Mandatory= $false)]
    [string] $FilePath, 
    [Parameter (Mandatory= $false)]
    [bool] $UseInRunbook = $false, 
    [Parameter (Mandatory= $false)]
    [bool] $ShowEC = $false,
    [Parameter (Mandatory= $false)]
    [bool] $ShowUnregistered = $false
)

#$Subs = Import-Csv -Path sub.csv

function AddVCores {
    # This function breaks down vCores into the $subtotal columns
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$Tier,
        [Parameter(Mandatory=$false)]
        [string]$LicenseType,
        [Parameter(Mandatory)]
        $CoreCount
    )
    #write-host $Tier "," $LicenseType "," $CoreCount
    switch ($Tier) {
        "BusinessCritical" {
            switch ($LicenseType) {
                "BasePrice" { return "AHB Ent vCores "}
                "LicenseIncluded" {return "PAYG Ent vCores"} 
                default {return "PAYG Ent vCores"} 
            }
        }
        "GeneralPurpose" {
            switch ($LicenseType) {
                "BasePrice" {return "AHB Std vCores "}
                "LicenseIncluded" {return "PAYG Std vCores "} 
                default {return "PAYG Std vCores "}
            }
        }
        "Hyperscale" {
            switch ($LicenseType) {
                "BasePrice" {return "AHB Std vCores "}
                "LicenseIncluded" {return "PAYG Std vCores "} 
                default {return "PAYG Std vCores "} 
            }
        }
        "Enterprise" {
            switch ($LicenseType) {
                "BasePrice" {return "AHB Ent vCores "}
                "LicenseIncluded" {return "PAYG Ent vCores"} 
                "AHUB" {return "AHB Ent vCores "}
                "DR" {return "hadr_ent"}
                "PAYG" {return "PAYG Ent vCores"} 
                default {return "PAYG Ent vCores"} 
            }
        }
        "Standard" {
            switch ($LicenseType) {
                "BasePrice" {return "AHB Std vCores "}
                "LicenseIncluded" {return "PAYG Std vCores "} 
                "AHUB" {return "AHB Std vCores "}
                "DR" {return "hadr_std"}
                "PAYG" {return "PAYG Std vCores "} 
                default {return "PAYG Std vCores "}
            }
        }
        "Developer" {            
            return "developer"
        }
        "Express" {
            return "express"
        }
        default {
            return "unknown_tier"
        }
    }   
}


function AddVSqlResourceDetails {
    # This function insert SQL resource details in $SqlObj Object 
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory=$false)]
        [string]$ResourceType,
        [Parameter(Mandatory=$false)]
        [string]$Status,
        [Parameter(Mandatory=$false)]
        [string]$Core,
        [Parameter(Mandatory=$false)]
        [string]$LicenseType,
        [Parameter(Mandatory=$false)]
        [string]$Sku,
        [Parameter(Mandatory=$false)]
        [string]$TimeCreated,
        [Parameter(Mandatory=$false)]
        [string]$subName,
        [Parameter(Mandatory=$false)]
        [string]$subId
    )

        $Obj = @{
            Name = $Name; 
            ResourceGroupName = $ResourceGroupName;
            ResourceType = $ResourceType;
            Status = $Status;
            Core =  $Core;
            LicenseType = $LicenseType; 
            Sku = $Sku;
            TimeCreated = $TimeCreated;  
            SubName = $subName;
            SubId = $subId;
        }
        $SqlObj.add((New-Object psobject -Property $Obj)) | Out-Null  
}


function CheckModule ($m) {

    # This function ensures that the specified module is imported into the session
    # If module is already imported - do nothing

    if (!(Get-Module | Where-Object {$_.Name -eq $m})) {
         # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object {$_.Name -eq $m}) {
            Import-Module $m 
        }
        else {

            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $m | Where-Object {$_.Name -eq $m}) {
                Install-Module -Name $m -Force -Verbose -Scope CurrentUser
                Import-Module $m
            }
            else {

                # If module is not imported, not available and not in online gallery then abort
                write-host "Module $m not imported, not available and not in online gallery, exiting."
                EXIT 1
            }
        }
    }
}

function GetVCores {
    # This function translates each VM or Host sku type and name into vCores
    
     [CmdletBinding()]
     param (
         [Parameter(Mandatory)]
         [string]$type,
         [Parameter(Mandatory)]
         [string]$name
     )
     
     if ($global:VM_SKUs.Count -eq 0){
         $global:VM_SKUs = Get-AzComputeResourceSku  "westus" | where-object {$_.ResourceType -in 'virtualMachines','hostGroups/hosts'}
     }
     # Select first size and get the VCPus available
     $size_info = $global:VM_SKUs | Where-Object {$_.ResourceType.Contains($type) -and ($_.Name -eq $name)} | Select-Object -First 1
                         
     # Save the VCPU count
     switch ($type) {
         "hosts" {$vcpu = $size_info.Capabilities | Where-Object {$_.name -eq "Cores"} }
         "virtualMachines" {$vcpu = $size_info.Capabilities | Where-Object {$_.name -eq "vCPUsAvailable"} }
     }
     
     if ($vcpu){
         return $vcpu.Value
     }
     else {
         return 0
     }      
 }

 function DiscoveryOnWindows {
    
    # This script checks if SQL Server is installed on Windows
        
        [bool] $SqlInstalled = $false 
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'
        if (Test-Path $regPath) {
            $inst = (get-itemproperty $regPath).InstalledInstances
            $SqlInstalled = ($inst.Count -gt 0)
        }
        Write-Output $SqlInstalled
    }
    
    #
    # This script checks if SQL Server is installed on Linux
    # 
    #    
    $DiscoveryOnLinux =
        'if ! systemctl is-active --quiet mssql-server.service; then 
        echo "False" 
        exit 
        else 
            echo "True" 
        fi'
    
    
 # Ensure that the required modules are imported
    # In Runbooks these modules must be added to the automation account manually

    $requiredModules = @(
        "Az.Accounts",
        "Az.Compute",
        "Az.DataFactory",
        "Az.Resources",
        "Az.Sql",
        "Az.SqlVirtualMachine"
    )
    $requiredModules | Foreach-Object {CheckModule $_} 


if (!$PSBoundParameters.ContainsKey("FilePath")) {
    $FilePath = '.\sql-license-usage-details.csv'
}

# Save the function definitions to run in parallel loops
$GetVCoresDef = $function:GetVCores.ToString()
#$AddVCoresDef = $function:AddVCores.ToString()
$AddVSqlResourceDetailsDef = $Function:AddVSqlResourceDetails.ToString()

$SqlObj = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
# Subscriptions to scan
if($SubId){
    write-host -ForegroundColor Green "Singola Subscription"
    #$subscriptions = [PSCustomObject]@{SubscriptionId = $SubId} | Get-AzSubscription 
    $subscription = Get-AzSubscription -SubscriptionId $SubId
    $subscriptions = [PSCustomObject]@{
                                        Id = $subscription.Id
                                        Name = $subscription.Name
                                        State = $subscription.State
                                    }
}else{
    write-host -ForegroundColor Green "Multi Subscription"
    #$subscriptions = Get-AzSubscription
    #$subscriptions = [PSCustomObject]@{}
    $subscriptions = Get-AzSubscription
}

#Write-Output $subscriptions


foreach ($sub in $subscriptions){
    #Write-Output $sub.Id
    #Write-Output $sub.Name
    #Write-Output $sub.Enabled
if ($sub.State -ne "Enabled") {continue}
    try {
        Set-AzContext -SubscriptionId $sub.Id | Out-Null
    }catch {
        write-host "Invalid subscription: " $sub.Id
        {continue}
    }


    Write-host -ForegroundColor Green "Analizzo la Subscription $($sub.Name) con ID: $($sub.ID)"
    # Reset the subtotals     
    #$subtotal.psobject.properties.name | Foreach-object {$subtotal.$_ = 0}
        
    # Get all resource groups in the subscription
    $rgs = Get-AzResourceGroup
    
    # Get all logical servers
    $servers = Get-AzSqlServer 

    
    # Scan all vCore-based SQL database resources in the subscription
    $servers | Get-AzSqlDatabase -WarningAction SilentlyContinue |  Where-Object { $_.SkuName -ne "ElasticPool" -and $_.Edition -in "GeneralPurpose", "BusinessCritical", "Hyperscale"} | Foreach-Object {
        $licenseType = AddVCores -Tier $_.Edition -LicenseType $_.LicenseType -CoreCount $_.Capacity
        AddVSqlResourceDetails -Name $_.DatabaseName -ResourceGroupName $_.ResourceGroupName -ResourceType "SQL_Database" -Status $_.Status -Core $_.Capacity -LicenseType $licenseType -Sku $_.SkuName -TimeCreated $_.CreationDate -SubName $sub.Name -SubId $sub.Id        
    }
    #[system.gc]::Collect()

    # Scan all vcOre-based SQL elastic pool resources in the subscription
    $servers | Get-AzSqlElasticPool -WarningAction SilentlyContinue  | Where-Object { $_.Edition -in "GeneralPurpose", "BusinessCritical", "Hyperscale"} | Foreach-Object {
        $licenseType = AddVCores -Tier $_.Edition -LicenseType $_.LicenseType -CoreCount $_.Capacity
        AddVSqlResourceDetails -Name $_.ServerName -ResourceGroupName $_.ResourceGroupName -ResourceType "SQL_ElasticPools" -Status $_.State -Core $_.Capacity -LicenseType $licenseType -Sku $_.SkuName -TimeCreated $_.CreationDate -SubName $sub.Name -SubId $sub.Id 
    }
    #[system.gc]::Collect()
    # Scan all SQL managed instance resources in the subscription
    Get-AzSqlInstance -WarningAction SilentlyContinue | Where-Object { $_.InstancePoolName -eq $null} | Foreach-Object { 
        $licenseType = AddVCores -Tier $_.Edition -LicenseType $_.LicenseType -CoreCount $_.Capacity
        AddVSqlResourceDetails -Name $_.ManagedInstanceName -ResourceGroupName $_.ResourceGroupName -ResourceType "SQL_ManagedInstance" -Status "" -Core $_.VCores -LicenseType $licenseType -Sku $_.Sku.Tier -TimeCreated "" -SubName $sub.Name -SubId $sub.Id 
    }
    #[system.gc]::Collect()

    # Scan all instance pool resources in the subscription
    Get-AzSqlInstancePool -WarningAction SilentlyContinue | Foreach-Object {
        $licenseType = AddVCores -Tier $_.Edition -LicenseType $_.LicenseType -CoreCount $_.Capacity
        AddVSqlResourceDetails -Name $_.InstancePoolName -ResourceGroupName $_.ResourceGroupName -ResourceType "SQL_InstancePool" -Status "" -Core $_.VCores -LicenseType $LicenseType -Sku $_.Edition -TimeCreated "" -SubName $sub.Name -SubId $sub.Id 
    }
    #[system.gc]::Collect()
    # Scan all SSIS imtegration runtime resources in the subscription
    $rgs | Get-AzDataFactoryV2 | Get-AzDataFactoryV2IntegrationRuntime -WarningAction SilentlyContinue |  Where-Object { $_.State -eq "Started" -and $_.Nodesize -ne $null } | Foreach-Object {
        $vCores = GetVCores -type "virtualMachines" -name $_.NodeSize
        $licenseType = AddVCores -Tier $_.Edition -LicenseType $_.LicenseType -CoreCount $_.Capacity
        AddVSqlResourceDetails -Name $_.DataFactoryName -ResourceGroupName $_.ResourceGroupName -ResourceType "SQL_SISS" -Status $_.State -Core $VCores -LicenseType $LicenseType -Sku $_.NodeSize -TimeCreated "" -SubName $sub.Name -SubId $sub.Id 
    }
    #[system.gc]::Collect()

    # Scan all VMs with SQL server installed using a parallel loop (up to 10 at a time). For that reason function AddVCores is not used 
    # NOTE: ForEach-Object -Parallel is not supported in Runbooks (requires PS v7.1)
    if ($PSVersionTable.PSVersion.Major -ge 7){
        $VMs = Get-AzVM -Status <#| Where-Object { $_.powerstate -eq 'VM running' } #> | ForEach-Object -ThrottleLimit 10 -Parallel { 
            $error.Clear()
            $subInfo            =  $using:sub
            $SqlObj             = $using:SqlObj


            $function:AddVSqlResourceDetails = $using:AddVSqlResourceDetailsDef
            $function:GetVCores = $using:GetVCoresDef  
            
            $i=1
            for(;$i -le 3;$i++){
                try {
                    $vCores = GetVCores -type 'virtualMachines' -name $_.HardwareProfile.VmSize
                $sql_vm = Get-AzSqlVm -ResourceGroupName $_.ResourceGroupName -Name $_.Name -ErrorAction Ignore

                if ($sql_vm) {
                    switch ($sql_vm.Sku) {
                        "Enterprise" {
                            switch ($sql_vm.LicenseType) {
                                "AHUB" {$licenseType = "AHB Ent vCores "}
                                "DR" {$licenseType = "hadr_ent"}
                                "PAYG" {$licenseType = "PAYG Ent vCores"} 
                                default {$licenseType = "PAYG Ent vCores"} 
                            }
                        }
                        "Standard" {
                            switch ($sql_vm.LicenseType) {
                                "AHUB" {$licenseType = "AHB Std vCores "}
                                "DR" {$licenseType = "hadr_std"}
                                "PAYG" {$licenseType = "PAYG Std vCores "} 
                                default {$licenseType = "PAYG Std vCores "}
                            }
                        }
                        "Developer" {                        
                            $licenseType = "developer"
                        }
                        "Express" {
                            $licenseType = "express"
                        }        
                    }     
                    $vm = Get-AzVM -ResourceGroupName $_.ResourceGroupName -Name $_.Name

                    AddVSqlResourceDetails -Name $_.Name -ResourceGroupName $_.ResourceGroupName -ResourceType "SQL_VM" -Status $_.PowerState -Core $VCores -LicenseType $licenseType -Sku $sql_vm.Sku -TimeCreated $vm.TimeCreated -SubName $subInfo.Name -SubId $subInfo.Id
                } else {
                    <#
                    if ($($using:ShowUnregistered)){
                        if ($_.StorageProfile.OSDisk.OSType -eq "Windows"){            
                            $params =@{
                                ResourceGroupName = $_.ResourceGroupName
                                Name = $_.Name
                                CommandId = 'RunPowerShellScript'
                                ScriptPath = 'DiscoverSql.ps1'
                                ErrorAction = 'Stop'
                            } 
                        }
                        else {
                            $params =@{
                                ResourceGroupName = $_.ResourceGroupName
                                Name = $_.Name
                                CommandId = 'RunShellScript'
                                ScriptPath = 'DiscoverSql.sh'
                                ErrorAction = 'Stop'
                            }                       
                        }
                        try {                    
                            $out = Invoke-AzVMRunCommand @params            
                            if ($out.Value[0].Message.Contains('True')){                
                                $($using:subtotal).unreg_sqlvm += $vCores            
                            }                
                        }
                        catch {          
                            write-host $params.Name "No acceaa"
                        }
                    }#>
                }

                $i=4
                
                }
                catch {
                    write-host $Error
                }
            }
        
            
        }      
    }
    else {
        Get-AzVM -Status <# | Where-Object { $_.powerstate -eq 'VM running' } #>| ForEach-Object {
            $error.Clear()
            #$subInfo            =  $using:sub
            #$SqlObj             = $using:SqlObj


            #$function:AddVSqlResourceDetails = $using:AddVSqlResourceDetailsDef
            #$function:GetVCores = $using:GetVCoresDef  
            
            $i=1
            for(;$i -le 3;$i++){
                try {
                    $vCores = GetVCores -type 'virtualMachines' -name $_.HardwareProfile.VmSize
                $sql_vm = Get-AzSqlVm -ResourceGroupName $_.ResourceGroupName -Name $_.Name -ErrorAction Ignore

                if ($sql_vm) {
                    switch ($sql_vm.Sku) {
                        "Enterprise" {
                            switch ($sql_vm.LicenseType) {
                                "AHUB" {$licenseType = "AHB Ent vCores "}
                                "DR" {$licenseType = "hadr_ent"}
                                "PAYG" {$licenseType = "PAYG Ent vCores"} 
                                default {$licenseType = "PAYG Ent vCores"} 
                            }
                        }
                        "Standard" {
                            switch ($sql_vm.LicenseType) {
                                "AHUB" {$licenseType = "AHB Std vCores "}
                                "DR" {$licenseType = "hadr_std"}
                                "PAYG" {$licenseType = "PAYG Std vCores "} 
                                default {$licenseType = "PAYG Std vCores "}
                            }
                        }
                        "Developer" {                        
                            $licenseType = "developer"
                        }
                        "Express" {
                            $licenseType = "express"
                        }        
                    }     
                    $vm = Get-AzVM -ResourceGroupName $_.ResourceGroupName -Name $_.Name

                    AddVSqlResourceDetails -Name $_.Name -ResourceGroupName $_.ResourceGroupName -ResourceType "SQL_VM" -Status $_.PowerState -Core $VCores -LicenseType $licenseType -Sku $sql_vm.Sku -TimeCreated $vm.TimeCreated -SubName $sub.Name -SubId $sub.Id
                } else {
                    <#
                    if ($($using:ShowUnregistered)){
                        if ($_.StorageProfile.OSDisk.OSType -eq "Windows"){            
                            $params =@{
                                ResourceGroupName = $_.ResourceGroupName
                                Name = $_.Name
                                CommandId = 'RunPowerShellScript'
                                ScriptPath = 'DiscoverSql.ps1'
                                ErrorAction = 'Stop'
                            } 
                        }
                        else {
                            $params =@{
                                ResourceGroupName = $_.ResourceGroupName
                                Name = $_.Name
                                CommandId = 'RunShellScript'
                                ScriptPath = 'DiscoverSql.sh'
                                ErrorAction = 'Stop'
                            }                       
                        }
                        try {                    
                            $out = Invoke-AzVMRunCommand @params            
                            if ($out.Value[0].Message.Contains('True')){                
                                $($using:subtotal).unreg_sqlvm += $vCores            
                            }                
                        }
                        catch {          
                            write-host $params.Name "No acceaa"
                        }
                    }#>
                }

                $i=4
                
                }
                catch {
                    write-host $Error
                }
            }
        }        
    }    
    #[system.gc]::Collect()
    
    # Scan the VMs hosts in the subscription
    $host_groups = Get-AzHostGroup 

    # Get the dedicated host size, match it with the corresponding VCPU count and add to VCore count
    
    foreach ($host_group in $host_groups){
        
        $vm_hosts = $host_group | Select-Object -Property @{Name = 'HostGroupName'; Expression = {$_.Name}},@{Name = 'ResourceGroupName'; Expression = {$_.ResourceGroupName}} | Get-AzHost
    
        foreach ($vm_host in $vm_hosts){

            $token = (Get-AzAccessToken).Token
            $params = @{
                Uri         = "https://management.azure.com/subscriptions/" + $sub.Id + 
                            "/resourceGroups/" + $vm_host.ResourceGroupName.ToLower() + 
                            "/providers/Microsoft.Compute/hostGroups/" + $host_group.Name + 
                            "/hosts/" + $vm_host.Name + 
                            "/providers/Microsoft.SoftwarePlan/hybridUseBenefits/SQL_" + $host_group.Name + "_" + $vm_host.Name + "?api-version=2019-06-01-preview"
                Headers     = @{ 'Authorization' = "Bearer $token" }
                Method      = 'GET'
                ContentType = 'application/json'
            }
            
            try {
                $softwarePlan = Invoke-RestMethod @params
                if ($softwarePlan.Sku.Name -like "SQL*"){     
                    $VCores = GetVCores -type 'hosts' -name $vm_host.Sku.Name
                    AddVSqlResourceDetails -Name $host_group.Name -ResourceGroupName $host_group.ResourceGroupName -ResourceType "SQL_HostGroup" -Status "" -Core $VCores -LicenseType "" -Sku "" -TimeCreated "" -SubName $sub.Name -SubId $sub.Id 
                }
            }
            catch {                
                $sub.Id
                $vm_host.ResourceGroupName.ToLower()
                $host_group.Name
                $vm_host.Name
                $params
            }            
        }
    }
    #[system.gc]::Collect()



}


Write-Output $SqlObj | ft

(ConvertFrom-Csv ($SqlObj | %{$_ -join ','})) | Export-Csv $FilePath -Append -NoType -Force
Write-Host ([Environment]::NewLine + "-- Added the usage data to $FilePath --")
