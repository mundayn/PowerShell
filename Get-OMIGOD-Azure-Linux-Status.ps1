<#
.SYNOPSIS
    Checks all Linux Machines in all Azure Subscriptions for the 'OMIGOD' vulnerability
.DESCRIPTION
    Checks for:
    - OMI Version
    - What Extensions are Installed
    - If OMI is listening on any ports
.REF
    https://www.wiz.io/blog/secret-agent-exposes-azure-customers-to-unauthorized-code-execution
    https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38647
    https://msrc-blog.microsoft.com/2021/09/16/additional-guidance-regarding-omi-vulnerabilities-within-azure-vm-management-extensions/

.EXAMPLE
    Run: 'Connect-AzAccount -TenantId <Tenant ID>' first
    
    '.\Get-OMIGOD-Azure-Linux-Status.ps1'

    The script should do the rest once logged in

    The output will be in C:\temp\omigod in .csv format

#>

# Create log dir
IF (!(Test-Path C:\temp\omigod)) {New-Item -ItemType Directory -Path "C:\temp\omigod" -Force}

# Log Files
$Outfile = "C:\temp\omigod\AZ_Linux_OMI_Results_$(Get-Date -format yyyyMMddHHmmss).txt"
$CSVfile = "C:\temp\omigod\AZ_Linux_OMI_Results_$(Get-Date -format yyyyMMddHHmmss).csv"

# Debian Checks
$DebianScript = @"
dpkg -l omi | grep "omi"
egrep "httpport|httpsport" /etc/opt/omi/conf/omiserver.conf
"@

# RHEL Checks
$RedHatScript = @"
rpm -qa omi
yum list installed | grep omi
egrep "httpport|httpsport" /etc/opt/omi/conf/omiserver.conf
"@

# Script location
$DebianScriptFile = "C:\temp\omigod\omigod-debianscript.sh" 
$RedHatScriptFile = "C:\temp\omigod\omigod-rhelscript.sh" 

# Put script into file
$DebianScript | Out-File $DebianScriptFile -Force
$RedHatScript | Out-File $RedHatScriptFile -Force

# Create a report list
$FullReport = [System.Collections.Generic.List[Object]]::new()

# Script to run in each sub
$Script = {

    # Get all powered on Linux VMs that are not Databricks
    $LinuxVMs = Get-AZVM -Status | Where {($_.StorageProfile.OsDisk.OsType -eq "Linux") `
        -and ($_.PowerState -eq "VM running") `
            -and ($_.StorageProfile.ImageReference.Offer -ne "Databricks")}

    ForEach ($VM in $LinuxVMs) {

        $ScriptPath = $NULL
        $VulnerableRemote = $NULL
        $OMIVersion_BAD = $NULL
        $OMIhttpListening = $NULL
        $OMIhttpsListening = $NULL
        $VersionLine = $NULL
        $httpLine = $NULL
        $httpsLine = $NULL
        $ErrorMessage= $NULL
        $ExtensionsAll = $NULL
        $ExtensionsAllJoin = $NULL

        Write-Host "Checking $($VM.Name)"
        $VM.StorageProfile.ImageReference.Offer

        # Checking OS variant
        IF ($VM.StorageProfile.ImageReference.Offer -like "*ubuntu*") {
            $ScriptPath = $DebianScriptFile
        } ELSE { 
            $ScriptPath = $RedHatScriptFile
        }

        # If there is not an extension, finish the script here
        IF ($VM.extensions.id) {
		    $ExtensionsAll = @()
		    ForEach ($ID in $VM.extensions.id) {
			    $Extension = $ID -split "/" | Select -Last 1
			    $ExtensionsAll += $Extension
            }
		    $ExtensionsAllJoin = $ExtensionsAll -join ','
        } ELSE {
            $ExtensionsAllJoin = "No Extensions - not vulnerable"

                $ReportLine = [PSCustomObject]@{
                VMName = $VM.Name
                ScriptError = "N/A"
                Extensions = $ExtensionsAllJoin
                VulnerableRemote = "N/A"
                VulnerableLocal = "N/A"
                OMIVersion_BAD = "N/A"
                httplistening = "N/A"
                httpslistening = "N/A"
                ResourceGroupName = $VM.ResourceGroupName
                OS = $VM.StorageProfile.ImageReference.Offer
                OMIVersion = "N/A"
                httplisten = "N/A"
                httpslisten = "N/A"
            }

            # Add line to report
            $FullReport.Add($ReportLine) 

            continue

        }

        # Variables for the AzVMRunCommand
        $Splat = @{
            ResourceGroupName = $VM.ResourceGroupName
            VMName = $VM.Name
            CommandId = "RunShellScript"
            ScriptPath = $ScriptPath
        }

        # Invoke the command on the VM
        TRY {

            $Command = Invoke-AzVMRunCommand @Splat 
            # Dump command output in log file if needed
            "#####" | Out-File $Outfile -Append
            "Working on: $($VM.Name)" | Out-File $Outfile -Append
            $Command.Value.message | Out-File $Outfile -Append

            # Select-String not working the same as findstr, Select-String seems to get the whole output still
            # Gets the omi version and the details from the .conf file
            $VersionLine = $Command.Value.message | findstr "omi"
            $httpLine = $Command.Value.message | findstr "httpport="
            $httpsLine = $Command.Value.message | findstr "httpsport="

            # Check if using patched version
            IF ($VersionLine) {
                IF (($VersionLine -like "*1.6.8.1*") -or ($VersionLine -like "*1.6.8-1*")) {
                    $OMIVersion_BAD = $FALSE
                } ELSEIF ($VersionLine -like "*1.*") {
                    $OMIVersion_BAD = $TRUE
                } ELSE {
                    $OMIVersion_BAD = "Unknown"
                }
            } ELSE {
                $OMIVersion_BAD = "Unknown"
            }

            # Check if omiserver.conf is configured to listen on any ports for http and https 
            
            IF ($httpLine) {
                IF ($httpLine -like "*,*") {
                    $OMIhttpListening = $TRUE
                } ELSE {
                    $OMIhttpListening = $FALSE
                }
            } ELSE {
                $OMIhttpListening = "Unknown"
            }

            IF ($httpsLine) {
                IF ($httpsLine -like "*,*") {
                    $OMIhttpsListening = $TRUE
                } ELSE {
                    $OMIhttpsListening = $FALSE
                }
            } ELSE {
                $OMIhttpsListening = "Unknown"
            }

            # If listening and running a bad version, set vulnerable to remote
            IF (($OMIhttpListening -eq $TRUE -or $OMIhttpsListening -eq $TRUE) -and ($OMIVersion_BAD -eq $TRUE)) {
                $VulnerableRemote = $TRUE
            } ELSEIF (($OMIhttpListening -eq $FALSE -or $OMIhttpsListening -eq $FALSE) -or ($OMIVersion_BAD -eq $FALSE)) {
                $VulnerableRemote = $FALSE
            } ELSE {
                $VulnerableRemote = "Unknown"
            }

            $OMIVersion_BAD
            $VulnerableRemote


            # Create entry for report
            $ReportLine = [PSCustomObject]@{
                VMName = $VM.Name
                ScriptError = "N/A"
                Extensions = $ExtensionsAllJoin
                VulnerableRemote = $VulnerableRemote
                VulnerableLocal = $OMIVersion_BAD
                OMIVersion_BAD = $OMIVersion_BAD
                httplistening = $OMIhttpListening
                httpslistening = $OMIhttpsListening
                ResourceGroupName = $VM.ResourceGroupName
                OS = $VM.StorageProfile.ImageReference.Offer
                OMIVersion = $VersionLine
                httplisten = $httpLine
                httpslisten = $httpsLine
            }

            # Add line to report
            $FullReport.Add($ReportLine) 


        } CATCH {

            $ErrorMessage = $_.Exception.Message
            "#####" | Out-File $Outfile -Append
            "Working on: $($VM.Name)" | Out-File $Outfile -Append
            "Error: $ErrorMessage" | Out-File $Outfile -Append

            $ReportLine   = [PSCustomObject]@{
                VMName = $VM.Name
                ScriptError = $ErrorMessage
                Extensions = $ExtensionsAllJoin
                VulnerableRemote = "N/A"
                VulnerableLocal = "N/A"
                OMIVersion_BAD = "N/A"
                httplistening = "N/A"
                httpslistening = "N/A"
                ResourceGroupName = $VM.ResourceGroupName
                OS = $VM.StorageProfile.ImageReference.Offer
                OMIVersion = "N/A"
                httplisten = "N/A"
                httpslisten = "N/A"
            }

            # Add line to report
            $FullReport.Add($ReportLine) 
            
        }

    }

}

function Invoke-AzureCommand {
<#

.Invoke-AzureCommand Module (Thanks)
    Code to run on all subscriptions - Author:  Paul Harrison - Invoke-AzureCommand
    https://www.powershellgallery.com/packages/AzureHelper/1.0.13/Content/Functions%5CInvoke-AzureCommand.ps1

#>

    [CmdletBinding()]
    param (
        [ScriptBlock]
        $ScriptBlock,
    
        [Parameter(ValueFromPipeline = $true)]
        $Subscription,
    
        [switch]
        $AllSubscriptions,

        [switch]
        $IncludeDisabledSubscriptions,

        [array]
        $ArgumentList
    )

    process {
        Test-AHEnvironment
        if (-not $AllSubscriptions -and -not $Subscription) {
            return $ScriptBlock.Invoke($ArgumentList)
        }
    
        $currentSub = Get-AzContext
    
        if ($Subscription) { $subs = $Subscription }
        else { $subs = Get-AzSubscription }
        If (!($IncludeDisabledSubscriptions)) {
            $subs = $subs | Where-Object { 'Enabled' -eq $_.State }
        }
    
        $subCount = 0
        foreach ($sub in $subs) {
            Write-Host "In $($sub.name)"
            $Null = Set-AzContext $sub
            Write-Progress -Activity "Checking each subscription" -Status (Get-AzContext).Subscription.Name -PercentComplete (100 * $subCount / $($subs.count))
            $ScriptBlock.Invoke($ArgumentList)
            $subCount++
        }
        $null = Set-AzContext $currentSub
        
    }
}

Function Test-AHEnvironment {
    If ($Null -eq (Get-AzContext)) {
        throw { "Not connected to Azure - Run Connect-AzAccount before running using this cmdlet" }
    }
}

# Run the above script on all subscriptions
#Invoke-AzureCommand -AllSubscriptions -ScriptBlock $Script
Invoke-AzureCommand -AllSubscriptions -ScriptBlock $Script

# Export Report contents
$FullReport | Export-CSV $CSVfile -NoTypeInformation

# View on screen
$FullReport
