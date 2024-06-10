function Get-QualysHost {
    [CmdletBinding()]
    param(
        [ValidateSet('Basic', 'Basic/AGs', 'All', 'All/AGs', 'None')][string] $Details = 'All',
        [DateTime] $ScanDateBefore,
        [DateTime] $ScanDateAfter,
        [int] $MaximumRecords,
        [switch] $Native
    )
    # https://docs.qualys.com/en/vm/api/assets/index.htm#t=host_lists%2Fhost_list.htm

    if (-not $Script:PowerQualys) {
        if ($ErrorActionPreference -eq 'Stop') {
            throw 'You must first connect to Qualys using Connect-Qualys'
        }
        Write-Warning -Message 'Get-QualysHost - You must first connect to Qualys using Connect-Qualys'
        return
    }

    $invokeQualysQuerySplat = @{
        RelativeUri = 'asset/host/'
        Method      = 'GET'
        Body        = [ordered] @{
            action           = 'list'
            details          = $Details
            truncation_limit = $MaximumRecords
        }
    }
    if ($ScanDateBefore) {
        $invokeQualysQuerySplat.Body['vm_scan_date_before'] = $ScanDateBefore.ToString('yyyy-MM-dd')
    }
    if ($ScanDateAfter) {
        $invokeQualysQuerySplat.Body['vm_scan_date_after'] = $ScanDateAfter.ToString('yyyy-MM-dd')
    }

    $Query = Invoke-QualysQuery @invokeQualysQuerySplat
    if ($Query.HOST_LIST_OUTPUT.RESPONSE.WARNING) {
        Write-Warning -Message "Get-QualysHost - Please be aware: $($Query.HOST_LIST_OUTPUT.RESPONSE.WARNING)"
    }
    if ($Query.HOST_LIST_OUTPUT.RESPONSE.HOST_LIST.HOST) {
        if (-not $Native) {
            $Properties = $Query.HOST_LIST_OUTPUT.RESPONSE.HOST_LIST.HOST[0] | Get-Member -Type Properties
            $Query.HOST_LIST_OUTPUT.RESPONSE.HOST_LIST.HOST | Select-Object -Property $Properties.Name
        } else {
            $Query.HOST_LIST_OUTPUT.RESPONSE.HOST_LIST.HOST
        }
    }
}