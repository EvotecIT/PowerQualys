function Get-QualysKB {
    [CmdletBinding()]
    param(
        [string] $Ids,
        [string] $IdMin,
        [string] $IdMax,
        [string] $CVE,
        [datetime] $LastModifiedAfter,
        [datetime] $LastModifiedBefore,
        [datetime] $PublishedAfter,
        [datetime] $PublishedBefore,
        [switch] $IsPatchable
        #[ValidateSet('basic', 'all', 'none')][string] $Details
    )

    if (-not $Script:PowerQualys) {
        if ($ErrorActionPreference -eq 'Stop') {
            throw 'You must first connect to Qualys using Connect-Qualys'
        }
        Write-Warning -Message 'Get-QualysKB - You must first connect to Qualys using Connect-Qualys'
        return
    }

    $SeverityLevels = [ordered] @{
        '1' = 'Minimal'
        '2' = 'Medium'
        '3' = 'Serious'
        '4' = 'Critical'
        '5' = 'Urgent'
    }

    $invokeQualysQuerySplat = @{
        RelativeUri = 'knowledge_base/vuln/'
        Method      = 'GET'
        Body        = [ordered] @{
            action = 'list'
            # Doesn't work for some reason
            #truncation_limit = $MaximumRecords
        }
    }
    if ($Ids) {
        $invokeQualysQuerySplat.Body['ids'] = $Ids
    }
    if ($null -ne $PSBoundParameters['IsPatchable']) {
        $invokeQualysQuerySplat.Body['is_patchable'] = $IsPatchable.IsPresent
    }
    if ($IdMin) {
        $invokeQualysQuerySplat.Body['id_min'] = $IdMin
    }
    if ($IdMax) {
        $invokeQualysQuerySplat.Body['id_max'] = $IdMax
    }
    if ($CVE) {
        $invokeQualysQuerySplat.Body['cve'] = $CVE
    }
    if ($LastModifiedAfter) {
        $invokeQualysQuerySplat.Body['last_modified_after'] = $LastModifiedAfter.ToString('yyyy-MM-dd')
    }
    if ($LastModifiedBefore) {
        $invokeQualysQuerySplat.Body['last_modified_before'] = $LastModifiedBefore.ToString('yyyy-MM-dd')
    }
    if ($PublishedAfter) {
        $invokeQualysQuerySplat.Body['published_after'] = $PublishedAfter.ToString('yyyy-MM-dd')
    }
    if ($PublishedBefore) {
        $invokeQualysQuerySplat.Body['published_before'] = $PublishedBefore.ToString('yyyy-MM-dd')
    }
    # if ($Details) {
    #     $Conversion = @{
    #         'basic' = 'Basic'
    #         'all'   = 'All'
    #         'none'  = 'None'
    #     }
    #     $invokeQualysQuerySplat.Body['details'] = $Conversion[$Details]
    # }
    $invokeQualysQuerySplat.Body['details'] = 'All'

    $Query = Invoke-QualysQuery @invokeQualysQuerySplat
    if ($Query.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.WARNING) {
        Write-Warning -Message "Get-QualysKB - Please be aware: $($Query.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.WARNING)"
    }
    if ($Query.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST) {
        foreach ($Vuln in $Query.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.vuln) {
            $Solution = $Vuln.SOLUTION.'#cdata-section'
            if ($Solution) {
                $Solution = $Solution.Replace("\", [System.Environment]::NewLine)
            }
            $Diagnosis = $Vuln.DIAGNOSIS.'#cdata-section'
            if ($Diagnosis) {
                $Diagnosis = $Diagnosis.Replace("\", [System.Environment]::NewLine)
            }
            $Consequence = $Vuln.CONSEQUENCE.'#cdata-section'
            if ($Consequence) {
                $Consequence = $Consequence.Replace("\", [System.Environment]::NewLine)
            }
            [PSCustomObject] @{
                QID                 = $Vuln.QID                                  #45002
                Type                = $Vuln.VULN_TYPE                            #Potential Vulnerability
                Severity            = $SeverityLevels[$Vuln.SEVERITY_LEVEL]                       #2
                SeverityLevel       = $Vuln.SEVERITY_LEVEL                            #Medium
                Title               = $Vuln.TITLE.'#cdata-section'                                #TITLE
                Category            = $Vuln.CATEGORY                             #Information gathering
                #WhenChanged         = $Vuln.LAST_SERVICE_MODIFICATION_DATETIME   #2021-11-23T09:43:19Z
                #WhenCreated         = $Vuln.PUBLISHED_DATETIME                   #1999-01-01T08:00:00Z
                WhenCreated         = [datetime]::ParseExact($Vuln.PUBLISHED_DATETIME, 'yyyy-MM-dd\THH:mm:ss\Z', $null)
                WhenChanged         = [datetime]::ParseExact($Vuln.LAST_SERVICE_MODIFICATION_DATETIME, 'yyyy-MM-dd\THH:mm:ss\Z', $null)
                Patchable           = if ($Vuln.PATCHABLE -eq "0") { $false } elseif ($Vuln.Patchable -eq "1") { $true } else { $Vuln.PATCHABLE }
                Diagnosis           = $Diagnosis
                Consequence         = $Consequence
                Solution            = $Solution
                PciFlag             = if ($Vuln.PCI_FLAG -eq "0") { $false } elseif ($Vuln.PCI_FLAG -eq "1") { $true }  else { $Vuln.PCI_FLAG }                          #1
                ThreatIntelligence  = $Vuln.THREAT_INTELLIGENCE.Threat_Intel.'#cdata-section'                  #THREAT_INTELLIGENCE
                DiscoveryRemote     = if ($Vuln.DISCOVERY.Remote -eq "1") { $true } elseif ($Vuln.DISCOVERY.Remote -eq "0") { $false } else { $Vuln.DISCOVERY.Remote }
                DiscoveryAdditional = $Vuln.DISCOVERY.ADDITIONAL_INFO
                DiscoveryAuthType   = $Vuln.DISCOVERY.AUTH_TYPE_LIST.AUTH_TYPE
                #DISCOVERY                          = $Vuln.DISCOVERY #.'#cdata-section'                            #DISCOVERY
                SoftwareList        = foreach ($Software in $Vuln.SOFTWARE_LIST.SOFTWARE) {
                    [PSCustomObject] @{
                        Product = $Software.PRODUCT.'#cdata-section'
                        Vendor  = $Software.VENDOR.'#cdata-section'
                    }
                }
            }
        }
    } else {
        Write-Warning -Message 'Get-QualysKB - No vulnerabilities found'
    }
}

<#
action=list allows: echo_request, ids, id_min, id_max, details, is_patchable, last_modified_after,
 last_modified_before, last_modified_by_user_after, last_modified_by_user_before, last_modified_by_service_after,
  last_modified_by_service_before, code_modified_after, code_modified_before, published_after, published_before,
   discovery_method, discovery_auth_types, show_qid_change_log, show_pci_reasons, show_disabled_flag, show_supported_modules_info, cv
#>

