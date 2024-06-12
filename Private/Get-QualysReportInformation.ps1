function Get-QualysReportInformation {
    [CmdletBinding()]
    param(
        [int] $MaximumRecords
    )
    $Hosts = Get-QualysHostDetection -ShowIgs -QID '45027,45302,90924,91074,91328' -MaximumRecords $MaximumRecords

    $FilteredHosts = [ordered] @{}
    foreach ($Computer in $Hosts) {
        $Name = $Computer.DNS_DATA.HOSTNAME.'#cdata-section'
        $Computer.LAST_SCAN_DATETIME = [datetime]::ParseExact($Computer.LAST_SCAN_DATETIME, 'yyyy-MM-dd\THH:mm:ss\Z', $null)
        $Computer.LAST_VM_AUTH_SCANNED_DATE = [datetime]::ParseExact($Computer.LAST_VM_AUTH_SCANNED_DATE, 'yyyy-MM-dd\THH:mm:ss\Z', $null)
        $Computer.LAST_VM_SCANNED_DATE = [datetime]::ParseExact($Computer.LAST_VM_SCANNED_DATE, 'yyyy-MM-dd\THH:mm:ss\Z', $null)

        if (-not $FilteredHosts[$Name]) {
            $FilteredHosts[$Name] = $Computer
        } else {
            if ($Computer.LAST_SCAN_DATETIME -gt $FilteredHosts[$Name].LAST_SCAN_DATETIME) {
                $FilteredHosts[$Name] = $Computer
            }
        }
    }

    $Output = foreach ($Computer in $FilteredHosts.Values) {
        $CacheDetection = [ordered] @{}
        foreach ($Detection in $Computer.DETECTION_LIST.DETECTION) {
            $CacheDetection[$Detection.QID] = $Detection
        }

        $HostName = $Computer.DNS_DATA.HOSTNAME.'#cdata-section'
        $Domain = $Computer.DNS_DATA.DOMAIN.'#cdata-section'

        if ($CacheDetection['91074'].RESULTS.'#cdata-section') {
            $InstallationDate = $CacheDetection['91074'].RESULTS.'#cdata-section'.Replace("Microsoft Windows install date retrieved from the registry: ", "")
        } else {
            $InstallationDate = $null
        }
        if ($CacheDetection['91328'].RESULTS.'#cdata-section') {
            $HotFixes = ($CacheDetection['91328'].RESULTS.'#cdata-section' -replace "&apos;", "" -replace "HotfixID", "" -split "\n") | ForEach-Object { if ($_.Trim()) { "KB$_" } }
        } else {
            $HotFixes = $null
        }

        if ($CacheDetection['90924'].RESULTS.'#cdata-section') {
            $LastReboot = $CacheDetection['90924'].RESULTS.'#cdata-section'.Replace("Last Reboot Date and Time(yyyy/mm/dd hh:mm:ss): ", "")
        } else {
            $LastReboot = $null
        }

        if ($CacheDetection['45027'].RESULTS.'#cdata-section') {
            $Disabled = $CacheDetection['45027'].RESULTS.'#cdata-section'.Replace("Disabled User/Machine Accounts: ", "") | ForEach-Object { if ($_.Trim()) { $_.Trim() -split " " } }
        } else {
            $Disabled = $null
        }

        if ($CacheDetection['45302'].RESULTS.'#cdata-section') {
            $LocalAccountsBefore = $CacheDetection['45302'].RESULTS.'#cdata-section'
            $LocalAccounts = foreach ($Local in $LocalAccountsBefore -split "\n") {
                # Get everything before { }, and then split it on space
                $First = $Local -replace "\{.*", ""
                $First = $First -split " "
                # Get string between { }
                $Second = $Local -replace ".*\{(.*)\}.*", '$1'
                $Second = $Second -split ","

                $Name = $Second[1].Trim() -replace "Name=", ""

                $SplittedName = $Name.Split("\")
                $ObjectDomain = $SplittedName[0]
                $ObjectName = $SplittedName[1]


                $Type = $Second[0].Trim() -replace "siduse=", ""

                if ($ObjectDomain -eq $HostName) {
                    $IsLocal = $true
                    if ($Type -eq 'Group') {
                        $ObjectType = 'LocalGroup'
                    } elseif ($Type -eq 'Computer') {
                        $ObjectType = 'LocalComputer'
                    } elseif ($Type -eq 'User') {
                        $ObjectType = 'LocalUser'
                    } else {
                        $ObjectType = $Type
                    }
                } else {
                    $IsLocal = $false
                    if ($Type -eq 'Group') {
                        $ObjectType = 'DomainGroup'
                    } elseif ($Type -eq 'Computer') {
                        $ObjectType = 'DomainComputer'
                    } elseif ($Type -eq 'User') {
                        $ObjectType = 'DomainUser'
                    } else {
                        $ObjectType = $Type
                    }
                }


                [PSCustomObject] @{
                    HostName       = $HostName
                    Domain         = $Domain
                    GroupSID       = $First[0].Trim()
                    GroupName      = $First[1].Trim()
                    IsLocal        = $IsLocal
                    Type           = $ObjectType
                    ObjectDomain   = $ObjectDomain
                    ObjectName     = $ObjectName
                    ObjectFullName = $Name
                    SID            = $Second[2].Trim() -replace "SID=", ""
                }
            }

        } else {
            $LocalAccounts = $null
        }

        [PSCustomObject] @{
            Name             = $Computer.DNS.'#cdata-section'
            HostName         = $HostName
            Domain           = $Computer.DNS_DATA.DOMAIN.'#cdata-section'
            FQDN             = $Computer.DNS_DATA.FQDN.'#cdata-section'
            IP               = $Computer.IP
            ID               = $Computer.ID
            LAST_SCAN_DATE   = $Computer.LAST_SCAN_DATETIME
            OS               = $Computer.OS.'#cdata-section'
            TRACKING_METHOD  = $Computer.TRACKING_METHOD
            InstallationDate = $InstallationDate
            HotFixes         = $HotFixes
            LastReboot       = $LastReboot
            Disabled         = $Disabled
            LocalAccounts    = $LocalAccounts
        }
    }
    $Output
}