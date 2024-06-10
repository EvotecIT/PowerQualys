function Connect-Qualys {
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'SecurePassword')]
        [Parameter(Mandatory, ParameterSetName = 'Password')]
        [Parameter(Mandatory, ParameterSetName = 'Credential')]
        [string] $Url,
        [Parameter(Mandatory, ParameterSetName = 'SecurePassword')]
        [Parameter(Mandatory, ParameterSetName = 'Password')][string] $Username,
        [Parameter(Mandatory, ParameterSetName = 'Password')][string] $Password,
        [Parameter(Mandatory, ParameterSetName = 'Credential')][pscredential] $Credential,

        [alias('SecurePassword')][Parameter(Mandatory, ParameterSetName = 'SecurePassword')][string] $EncryptedPassword
    )

    if ($EncryptedPassword) {
        try {
            $Password = $EncryptedPassword | ConvertTo-SecureString -ErrorAction Stop
        } catch {
            if ($ErrorActionPreference -eq 'Stop') {
                throw
            }
            Write-Warning -Message "Connect-Qualys - Unable to convert password to secure string. Error: $($_.Exception.Message)"
            return
        }
    } elseif ($Credential) {
        $UserName = $Credential.UserName
        $Password = $Credential.GetNetworkCredential().Password
    }

    $Script:PowerQualys = @{
        'Uri'           = $Url
        'Authorization' = 'Basic {0}' -f ([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $UserName, $Password))))
    }
}