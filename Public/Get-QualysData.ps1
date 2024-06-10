function Get-QualysData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet(
            'HostSummary',
            'LocalAdmins'
        )][string] $Type,
        [int] $MaximumRecords
    )

    if ($Type -eq 'HostSummary') {
        Get-QualysReportInformation -MaximumRecords $MaximumRecords
    } elseif ($Type -eq 'LocalAdmins') {
        Get-QualysReportLocalAdmins -MaximumRecords $MaximumRecords
    } else {
        throw 'Invalid Type'
    }
}