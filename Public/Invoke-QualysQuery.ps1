function Invoke-QualysQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $RelativeUri,
        [string] $Method = 'GET',
        [System.Collections.IDictionary] $Body = [ordred] @{},
        [ValidateSet('list', 'edit', 'reset', 'custom')][string] $Action,
        [string] $MaximumRecords
    )

    if (-not $Script:PowerQualys) {
        if ($ErrorActionPreference -eq 'Stop') {
            throw 'You must first connect to Qualys using Connect-Qualys'
        }
        Write-Warning -Message 'Invoke-QualysQuery - You must first connect to Qualys using Connect-Qualys'
        return
    }

    $Settings = @{
        Headers     = @{
            'X-Requested-With' = 'PowerQualys PowerShell Module'
            'Authorization'    = $Script:PowerQualys.Authorization
        }
        Method      = $Method
        Body        = $Body
        ErrorAction = 'Stop'
        Verbose     = $false
    }

    $joinUriQuerySplat = @{
        BaseUri               = $Script:PowerQualys.Uri + "/api/2.0/fo/"
        RelativeOrAbsoluteUri = $RelativeUri
    }
    if ($QueryParameter) {
        $joinUriQuerySplat['QueryParameter'] = $QueryParameter
    }

    $Settings['Uri'] = Join-UriQuery @joinUriQuerySplat

    if ($Action) {
        $Settings['Body']['action'] = $Action.ToLower()
    }
    if ($MaximumRecords) {
        $Settings['Body']['truncation_limit'] = $MaximumRecords
    }

    Write-Verbose -Message "Invoke-QualysQuery - Settings used: $($Settings | Out-String)"
    Write-Verbose -Message "Invoke-QualysQuery - Url queried: $($Settings['Uri'])"
    try {
        Invoke-RestMethod @Settings
    } catch {
        if ($ErrorActionPreference -eq 'Stop') {
            throw $_
        }
        if ($_.ErrorDetails.Message) {
            $Details = ($_.ErrorDetails.Message -split "`n" | ForEach-Object { if ($_.Trim() -ne "") { $_.Trim() } } | Select-Object -Skip 1) -join " "
            Write-Warning -Message "Invoke-QualysQuery - Error when querying ($Method): $Details"
        } else {
            Write-Warning -Message "Invoke-QualysQuery - Error when querying ($Method): $($_.Exception.Message)"
        }
    }
}