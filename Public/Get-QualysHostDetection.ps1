function Get-QualysHostDetection {
    [CmdletBinding()]
    param(
        [int] $MaximumRecords,
        [string] $Ids,
        [string] $IdMin,
        [string] $IdMax,
        [string] $Ip,
        [switch] $Native,
        [ValidateSet('Confirmed', 'Potential')][string] $IncludeVulnerabilityType,
        [switch] $ShowAssetId,
        [string] $OSPattern,
        [alias('Qids')][string] $QID,
        [string] $Severities,
        [switch] $ShowIgs
    )
    # https://docs.qualys.com/en/vm/api/assets/index.htm#t=host_lists%2Fhost_list.htm

    if (-not $Script:PowerQualys) {
        if ($ErrorActionPreference -eq 'Stop') {
            throw 'You must first connect to Qualys using Connect-Qualys'
        }
        Write-Warning -Message 'Get-QualysHostDetection - You must first connect to Qualys using Connect-Qualys'
        return
    }

    $invokeQualysQuerySplat = @{
        RelativeUri = 'asset/host/vm/detection/'
        Method      = 'GET'
        Body        = [ordered] @{
            action           = 'list'
            #details          = $Details
            truncation_limit = $MaximumRecords
        }
    }
    if ($Ids) {
        $invokeQualysQuerySplat.Body['ids'] = $Ids
    }
    if ($IdMin) {
        $invokeQualysQuerySplat.Body['id_min'] = $IdMin
    }
    if ($IdMax) {
        $invokeQualysQuerySplat.Body['id_max'] = $IdMax
    }
    if ($Ip) {
        $invokeQualysQuerySplat.Body['ips'] = $Ip
    }
    if ($ScanDateBefore) {
        $invokeQualysQuerySplat.Body['vm_scan_date_before'] = $ScanDateBefore.ToString('yyyy-MM-dd')
    }
    if ($ScanDateAfter) {
        $invokeQualysQuerySplat.Body['vm_scan_date_after'] = $ScanDateAfter.ToString('yyyy-MM-dd')
    }
    if ($IncludeVulnerabilityType) {
        $invokeQualysQuerySplat.Body['include_vuln_type'] = $IncludeVulnerabilityType.ToLower()
    }
    if ($null -ne $PSBoundParameters['ShowAssetId']) {
        $invokeQualysQuerySplat.Body['show_asset_id'] = if ($ShowAssetId.IsPresent) { 1 } else { 0 }
    }
    if ($OSPattern) {
        $invokeQualysQuerySplat.Body['os_pattern'] = $OSPattern
    }
    if ($QID) {
        $invokeQualysQuerySplat.Body['qids'] = $QID
    }
    if ($Severities) {
        $invokeQualysQuerySplat.Body['severities'] = $Severities
    }
    if ($null -ne $PSBoundParameters['ShowIgs']) {
        $invokeQualysQuerySplat.Body['show_igs'] = if ($ShowIgs.IsPresent) { 1 } else { 0 }
    }

    $Query = Invoke-QualysQuery @invokeQualysQuerySplat
    if ($Query.HOST_LIST_OUTPUT.RESPONSE.WARNING) {
        Write-Warning -Message "Get-QualysHostDetection - Please be aware: $($Query.HOST_LIST_OUTPUT.RESPONSE.WARNING)"
    }
    if ($Query.HOST_LIST_VM_DETECTION_OUTPUT.RESPONSE.HOST_LIST.HOST) {
        if (-not $Native) {
            $Properties = $Query.HOST_LIST_VM_DETECTION_OUTPUT.RESPONSE.HOST_LIST.HOST[0] | Get-Member -Type Properties
            $Query.HOST_LIST_VM_DETECTION_OUTPUT.RESPONSE.HOST_LIST.HOST | Select-Object -Property $Properties.Name
        } else {
            $Query.HOST_LIST_VM_DETECTION_OUTPUT.RESPONSE.HOST_LIST.HOST
        }
    }
}

<#
<SIMPLE_RETURN> <RESPONSE> <DATETIME>2024-06-07T07:58:23Z</DATETIME> <CODE>1901</CODE>
 <TEXT>Unrecognized parameter(s): show_asset_ids (action=list allows: echo_request, ips, ids, id_min, id_max, ag_ids, ag_titles,
  os_pattern, truncation_limit, show_tags, show_asset_id, show_results, use_tags, no_vm_scan_since, vm_scan_since,
  vm_processed_after, vm_processed_before, vm_scan_date_before, vm_scan_date_after, vm_auth_scan_date_before,
   vm_auth_scan_date_after, compliance_enabled, include_ignored, include_disabled, show_host_services, qids,
   show_igs, show_reopened_info, host_metadata, host_metadata_fields, show_cloud_tags, cloud_tag_fields, show_qds,
   qds_min, qds_max, show_qds_factors, severities, include_search_list_titles, exclude_search_list_titles,
    include_search_list_ids, exclude_search_list_ids, output_format, max_days_since_last_vm_scan,
     max_days_since_detection_updated, detection_last_tested_since_days, detection_last_tested_before_days, status, include_vuln_type,
     active_kernels_only, arf_kernel_filter, arf_service_filter, arf_config_filter, suppress_duplicated_data_from_csv,
     detection_updated_since, detection_updated_before, detection_processed_after, detection_processed_before,
     detection_last_tested_since, detection_last_tested_before, filter_superseded_qids)</TEXT> </RESPONSE> </SIMPLE_RETURN>
#>