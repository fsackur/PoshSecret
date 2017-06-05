Import-Module $PSScriptRoot\..\PoshSecret.psd1 -Force


Describe Add-Get-Remove {
    $AddGetRemoveScriptblock = {

        It AddsPWAndReturnsNull {
            Save-PoshSecret `
                -Name $Name `
                -Username $Username `
                -Password $Password `
                -Property $PropertyHashtable `
            | Should Be $null
        }
        
        It GetsPSObject {
            $PoshSecret = Get-PoshSecret `
                -Name $Name `
                -Username $Username `
                -AsPlaintext

            $PoshSecret.Name | Should BeExactly $Name
            $PoshSecret.Username | Should BeExactly $Username
            $PoshSecret.Password | Should BeExactly $Password
            $PropertyHashtable.Keys | foreach {
                $PoshSecret.$_ | Should BeExactly $PropertyHashtable.$_
            }
        }

        It GetsPSCred {
            $PSCred = Get-PoshSecret `
                -Name $Name `
                -Username $Username `
                -AsPSCredential
            ($PSCred.GetNetworkCredential().Domain, 
            $PSCred.GetNetworkCredential().UserName) -join '\' | Should BeExactly $Username
            $PSCred.GetNetworkCredential().Password | Should BeExactly $Password
        }

        It RemovesPW {
            Remove-PoshSecret `
                -Name $Name `
                -Username $Username;
            $(
                try {
                    Get-PoshSecret `
                        -Name $Name `
                        -Username $Username `
                        -AsPlaintext `
                } catch {}
            ) | Should BeExactly $null
        }

        It ReturnsNullForNonExistentEntry {
            Get-PoshSecret `
                -Name 'kjhsadjfhsdkjfhaljkdfhaljsfhljasfhlashflasjf' `
                -Username 'opiqwehqoierpqiwyepqoiwryqipywqiryqpwrypiry' `
            | Should Be $null
        }


    }

    $Username = "DOMAIN\test.testface"
    $Name = "Pestertesting"
    $Password = "hunter2"
    $PropertyHashtable = @{URL = 'http://stuff.do'; Tags = ('kevin', 'idiot')}

    Context SimplePW $AddGetRemoveScriptblock



    $Password = '{"Access":{"access":{"serviceCatalog":[],"user":{"RAX-AUTH:defaultRegion":"","roles":[{"name":"Racker","id":"9"},{"name":"Domain Users"},{"name":"dl_Incident_Alert"},{"name":"dl_Intensive Football - EUR"},{"name":"scb_uat_support"},{"name":"Portal - EMEA"},{"name":"dl_HPH Gym Members - UK"},{"name":"Rack - HPH"},{"name":"radar_support"},{"name":"FS - Support - Write - EUR"},{"name":"FS - Departmental Folders - READ"},{"name":"FS - Support Intensive TechScripts - WRITE"},{"name":"ip_cmndr_assigners"},{"name":"bpi_lbs_read"},{"name":"bpi_lbs_write"},{"name":"dns_rs_support"},{"name":"radar_mon_tech"},{"name":"RackAPISupport"},{"name":"RackCCSupport"},{"name":"RackImpersonation"},{"name":"dl_INT - ENT Windows Team A - EUR"},{"name":"DL_ENT Windows Team A - SD - INT"},{"name":"bastion"},{"name":"fs_support"},{"name":"scb_uat_internal"},{"name":"dns_cloud_support"},{"name":"FS - Powershell Tools Users - WRITE"},{"name":"lnx-CloudServer-WebConsole"},{"name":"encore_tier_1_managed_cloud_tech"},{"name":"af_hph"},{"name":"FS - Powershell Tools Developers - WRITE"},{"name":"github-users"},{"name":"FS - PowershellTools Owners - WRITE"},{"name":"Balabit_SUPPORT_gateway"},{"name":"MOSS - Intensive Implementation Tracker - CONTRIBUTE"},{"name":"dl_rack_global"},{"name":"lnx-cbastion"},{"name":"Balabit_DRAC_gateway"},{"name":"Windows Bastion Users"},{"name":"core-password-viewer"},{"name":"core-drac-viewer"},{"name":"DRO-Support"},{"name":"caspian-consumers"},{"name":"dl_RackGlobal"},{"name":"dl_Intensive - Fun Force - EUR"}],"name":"mich8638","id":"mich8638"},"token":{"expires":"2017-01-28T04:47:39.030Z","RAX-AUTH:authenticatedBy":["RSAKEY"],"id":"kgjsafgkjfsagdfpiahioqweoiutaoebcnkasvgfropwbfqwebifpqwbpqwnfpinqwepgnqpiwnegpnqwpign"}}},"XAuthToken":{"x-auth-token":"kljghadfl\akjgshfkjASkjfgakjhfljAs;kjAS:ljfLAJSf;kjA:Skljf;AKSf;kaSfasdg|DAgADg"}}'

    Context JSON $AddGetRemoveScriptblock


    Context Security {

        Mock Export-Clixml {
            return (
                $InputObject | Get-Member -MemberType Properties | foreach {
                    $InputObject.($_.Name) | Out-String
                }
            ) -join ''

        }

        
        $ObjectToSerialize = Save-PoshSecret -Name $Name -Username $Username -Password $Password

        It DoesNotStorePlaintext {
            Assert-MockCalled Export-Clixml -Times 1
            $ObjectToSerialize -match [regex]::Escape($Password) | Should Be $false
        }

    }


    Context Performance {
        It CompletesTenTimesFast {
            (Measure-Command {
                1..10 | %{
                    Save-PoshSecret -Username u -Name n -Password p; Get-PoshSecret -Username u -Name n; Remove-PoshSecret -Username u -Name n
                }
            }).TotalMilliseconds | Should BeLessThan 500
        }
    }


    Context Expiry {

        $Expiry = (Get-Date).AddHours(2)

        It AddsPWAndReturnsNull {
            Save-PoshSecret `
                -Name $Name `
                -Username $Username `
                -Password $Password `
                -Expiry $Expiry `
            | Should Be $null
        }
        
        It GetsPSObject {
            $PoshSecret = Get-PoshSecret `
                -Name $Name `
                -Username $Username `
                -AsPlaintext

            $PoshSecret.Name | Should BeExactly $Name
            $PoshSecret.Username | Should BeExactly $Username
            $PoshSecret.Password | Should BeExactly $Password
        }

        

        Mock Export-Clixml {$Global:DoomedPoshSecret = $InputObject}

        Mock Import-Clixml {
            $Global:DoomedPoshSecret.ExpiryTime = Get-Date -Format s;
            return $Global:DoomedPoshSecret
        }

        Mock Remove-PoshSecret -ModuleName PoshSecret {}

        It ReturnsNullAndDeletes {
            Save-PoshSecret `
                -Name $Name `
                -Username $Username `
                -Password $Password `
                -Expiry $Expiry `

            $PoshSecret = Get-PoshSecret `
                -Name $Name `
                -Username $Username `
                -AsPlaintext `

            $PoshSecret | Should Be $Null
            
            Assert-MockCalled Import-Clixml -Times 1
            Assert-MockCalled Remove-PoshSecret -Times 1 -ModuleName PoshSecret
            
        }
    }
}
