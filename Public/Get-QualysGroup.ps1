function Get-QualysGroup {
    [CmdletBinding()]
    param(
        [int] $MaximumRecords
    )

    if (-not $Script:PowerQualys) {
        if ($ErrorActionPreference -eq 'Stop') {
            throw 'You must first connect to Qualys using Connect-Qualys'
        }
        Write-Warning -Message 'Get-QualysGroup - You must first connect to Qualys using Connect-Qualys'
        return
    }

    $invokeQualysQuerySplat = @{
        RelativeUri = 'asset/group/'
        Method      = 'GET'
        Body        = [ordered] @{
            action           = 'list'
            truncation_limit = $MaximumRecords
        }
    }

    $Query = Invoke-QualysQuery @invokeQualysQuerySplat
    if ($Query.ASSET_GROUP_LIST_OUTPUT.RESPONSE.WARNING) {
        Write-Warning -Message "Get-QualysGroup - Please be aware: $($Query.ASSET_GROUP_LIST_OUTPUT.RESPONSE.WARNING)"
    }
    $Query.ASSET_GROUP_LIST_OUTPUT.RESPONSE.ASSET_GROUP_LIST.ASSET_GROUP
}