# PowerQualys - PowerShell Module

<p align="center">
  <!-- <a href="https://dev.azure.com/evotecpl/PowerQualys/_build/results?buildId=latest"><img src="https://img.shields.io/azure-devops/build/evotecpl/39c74615-8f34-4af0-a835-68dc33f9214f/14?label=Azure%20Pipelines&style=flat-square"></a> -->
  <a href="https://www.powershellgallery.com/packages/PowerQualys"><img src="https://img.shields.io/powershellgallery/v/PowerQualys.svg?style=flat-square"></a>
  <a href="https://www.powershellgallery.com/packages/PowerQualys"><img src="https://img.shields.io/powershellgallery/vpre/PowerQualys.svg?label=powershell%20gallery%20preview&colorB=yellow&style=flat-square"></a>
  <a href="https://github.com/EvotecIT/PowerQualys"><img src="https://img.shields.io/github/license/EvotecIT/PowerQualys.svg?style=flat-square"></a>
</p>

<p align="center">
  <a href="https://www.powershellgallery.com/packages/PowerQualys"><img src="https://img.shields.io/powershellgallery/p/PowerQualys.svg?style=flat-square"></a>
  <a href="https://github.com/EvotecIT/PowerQualys"><img src="https://img.shields.io/github/languages/top/evotecit/PowerQualys.svg?style=flat-square"></a>
  <a href="https://github.com/EvotecIT/PowerQualys"><img src="https://img.shields.io/github/languages/code-size/evotecit/PowerQualys.svg?style=flat-square"></a>
  <a href="https://www.powershellgallery.com/packages/PowerQualys"><img src="https://img.shields.io/powershellgallery/dt/PowerQualys.svg?style=flat-square"></a>
</p>

<p align="center">
  <a href="https://twitter.com/PrzemyslawKlys"><img src="https://img.shields.io/twitter/follow/PrzemyslawKlys.svg?label=Twitter%20%40PrzemyslawKlys&style=flat-square&logo=twitter"></a>
  <a href="https://evotec.xyz/hub"><img src="https://img.shields.io/badge/Blog-evotec.xyz-2A6496.svg?style=flat-square"></a>
  <a href="https://www.linkedin.com/in/pklys"><img src="https://img.shields.io/badge/LinkedIn-pklys-0077B5.svg?logo=LinkedIn&style=flat-square"></a>
</p>

`PowerQualys` is a PowerShell module to interact with Qualys API.

- [Qualys API PDF](https://cdn2.qualys.com/docs/qualys-api-vmpc-user-guide.pdf)


### Installation

```powershell
Install-Module -Name PowerQualys -Force -Verbose
```

### Examples

#### Connecting to Qualys

```powershell
Connect-Qualys -Url "https://qualysguard.apps.qualys.eu" -Username "username" -Password 'password!@'
```

#### Examples of usage

Different examples of usage.

```powershell
$Query = Invoke-QualysQuery -RelativeUri 'asset/ip/' -Method 'GET' -Body @{ action = 'list' } -Verbose
$Query | Get-Member -Type Property
```

```powershell
$Hosts1 = Get-QualysHost -Verbose -MaximumRecords 2 -ScanDateBefore (Get-Date).AddDays(-1) -Details All/AGs -Native
$Hosts1 | Format-Table
```

```powershell
$Hosts = Get-QualysHostDetection -Verbose -MaximumRecords 2 -ShowIgs -QID '105008,105009,125008', '125028', '45027,45302,90924,91074,91328'
$Hosts | Format-List
```

```powershell
$Query1 = Invoke-QualysQuery -RelativeUri 'report/' -Method 'GET' -Body @{ action = 'list'; id = '45302' } -Verbose
$Query1.REPORT_LIST_OUTPUT.RESPONSE
```

```powershell
$KB1 = Get-QualysKB -Verbose -Ids '106216'
$KB1 | Format-Table

$KBAfter = Get-QualysKB -Verbose -PublishedAfter (Get-Date).AddDays(-1)
$KBAfter | Format-Table

$List1 = @(
    Get-QualysKB -Verbose -Ids '45002'
    Get-QualysKB -Verbose -Ids '45302'
    Get-QualysKB -Verbose -Ids '105231'
    Get-QualysKB -Verbose -Ids '90235'
)
$List1

$KB = Get-QualysKB -Verbose
```

```powershell
$Groups = Get-QualysGroup -Verbose -MaximumRecords 2
$Groups
```

```powershell
$Users = Get-QualysData -Type LocalAdmins -Verbose #-MaximumRecords 2
$Users | Format-Table
```