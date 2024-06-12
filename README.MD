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

```
<table>
  <tr>
    <td colspan="4">
      Available
    </td>
    <td rowspan="2">
      Processes
    </td>
    <td colspan="4">
      Allocation
    </td>
    <td colspan="4">
      Max
    </td>
  </tr>
  <tr>
    <td>
      A
    </td>
    <td>
      B
    </td>
    <td>
      C
    </td>
    <td>
      D
    </td>
    <td>
      A
    </td>
    <td>
      B
    </td>
    <td>
      C
    </td>
    <td>
      D
    </td>
    <td>
      A
    </td>
    <td>
      B
    </td>
    <td>
      C
    </td>
    <td>
      D
    </td>
  </tr>
  <tr>
    <td>
      1
    </td>
    <td>
      5
    </td>
    <td>
      2
    </td>
    <td>
      0
    </td>
    <td>
      P0
    </td>
    <td>
      0
    </td>
    <td>
      0
    </td>
    <td>
      1
    </td>
    <td>
      2
    </td>
    <td>
      0
    </td>
    <td>
      0
    </td>
    <td>
      1
    </td>
    <td>
      2
    </td>
  </tr>
  <tr>
    <td colspan="4">
    </td>
    <td>
      P1
    </td>
    <td>
      1
    </td>
    <td>
      0
    </td>
    <td>
      0
    </td>
    <td>
      0
    </td>
    <td>
      1
    </td>
    <td>
      7
    </td>
    <td>
      5
    </td>
    <td>
      0
    </td>
  </tr>
</table>