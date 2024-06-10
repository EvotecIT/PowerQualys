@{
    AliasesToExport      = @()
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @()
    CompanyName          = 'Evotec'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2011 - 2024 Przemyslaw Klys @ Evotec. All rights reserved.'
    Description          = 'Helper module for Qualys'
    FunctionsToExport    = @('Connect-Qualys', 'Get-QualysData', 'Get-QualysGroup', 'Get-QualysHost', 'Get-QualysHostDetection', 'Get-QualysKB', 'Invoke-QualysQuery')
    GUID                 = '8c726ef2-6562-4325-a3c3-d26bec60b76c'
    ModuleVersion        = '0.1.0'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Security')
            ProjectUri                 = 'https://github.com/EvotecIT/PowerQualys'
            Tags                       = @('Windows', 'Qualys')
        }
    }
    RequiredModules      = @(@{
            Guid          = 'ee272aa8-baaa-4edf-9f45-b6d6f7d844fe'
            ModuleName    = 'PSSharedGoods'
            ModuleVersion = '0.0.291'
        }, 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Security')
    RootModule           = 'PowerQualys.psm1'
}