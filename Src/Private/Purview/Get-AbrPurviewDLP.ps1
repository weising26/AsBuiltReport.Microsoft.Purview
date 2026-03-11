function Get-AbrPurviewDLP {
    <#
    .SYNOPSIS
    Used to check the UPN format.
    .DESCRIPTION

    .NOTES
        Version:        0.0.1
        Author:         Pai Wei Sing

    .EXAMPLE

    .LINK

    #>
    $DLPPolicies = Get-DlpCompliancePolicy
    Section -Style Heading1 'Data Loss Prevention' {
        foreach ($Policy in $DLPPolicies) {
            Section -Style Heading2 $Policy.Name {
                $PolicyData = [PSCustomObject]@{
                    'Name'    = $Policy.Name
                    'Mode'    = $Policy.Mode
                    'Enabled' = $Policy.Enabled
                    'Workload'= $Policy.Workload
                }
                $PolicyData | Table -Name $Policy.Name
            }
        }
    }
}