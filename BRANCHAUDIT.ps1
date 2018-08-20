#audit11

#select branch
#displays number of users and computers count


<#GetOUsForCOMPSandUSERS#>
$CompUserOUs = Get-ADObject -SearchBase "ou=hcma,dc=hcma,dc=com,dc=au" -filter * | where {
($_.objectclass -eq "organizationalunit") -and ($_.name -eq "Managed Users") -or ($_.name -eq "Managed Workstations")}

<#ManagedUsersOU#> #$CompUserOU.distinguishedname[0]
<#ManagedWorkstationsOU#> #$CompUserOU.distinguishedname[1]

#RUN IF WANT TO UPDATE BRANCH LIST |GetLatestBranches#>Get-ADObject -SearchBase "ou=managed workstations,ou=hcma,dc=hcma,dc=com,dc=au" -Filter * -Properties name,distinguishedname | where {($_.objectclass -like "organizationalUnit") -and ( $_.name -ne "generic")} | select name,distinguishedname | sort name | Out-GridView -Title "COMPUTERS AUDIT - Select a branch" -PassThru | Export-csv C:\Users\a-lay\Documents\PSExports\Branches.csv -NoTypeInformation

#notepad C:\Users\a-lay\Documents\PSExports\Branches.txt
#notepad C:\Users\a-lay\Documents\PSExports\Branches.csv

<#UserToSelectBranch#>$SelectedBranch = Import-Csv C:\Users\a-lay\Documents\PSExports\Branches.csv | Out-GridView  -Title "Select a branch to audit" -OutputMode Multiple
#$SelectedBranch.name
$SelectedBranch.distinguishedname
$branch = $SelectedBranch.name
<#Make use of outGridview Multiple - $Selectedbranch[0..100]#>
<#example - selected Mus[0], Gun[1], Glendell[2], then have loop that gets counts for each array entry#>

<#UserSearch#>$Users = Get-ADObject -SearchBase $CompUserOUs.distinguishedname[0] -Filter * | where {($_.distinguishedname -like "*$branch*") -and ($_.objectclass -eq "User")-and ($_.distinguishedname -notlike "*generic*")}
<#GenUserSearch#>$GenUsers = Get-ADObject -SearchBase $CompUserOUs.distinguishedname[0] -Filter * | where {($_.distinguishedname -like "*$branch*") -and ($_.objectclass -eq "User") -and ($_.distinguishedname -like "*generic*")}
<#CompSearch#>$Computers = Get-ADObject -SearchBase $CompUserOUs.distinguishedname[1] -Filter * | where {($_.distinguishedname -like "*$branch*") -and ($_.objectclass -eq "Computer")}
$branch + " Audit"
$Branch + " has " + $Users.Count + " users"
$Branch + " has " + $GenUsers.Count + " Generic users"
$Branch + " has " + $Computers.count + " computers"

#SUPERSEDED idea - get ou path
#cd ad: 
#cd '.\DC=hcma,DC=com,DC=au'

#cd .\OU=HCMA
#cd '.\OU=Managed Users'
#$Users = ls | select name | Out-GridView -Title "Select a branch" -PassThru
#
#Get-ADObject -SearchBase "ou=managed users,ou=hcma,dc=hcma,dc=com,dc=au" -Filter * -Properties DistinguishedName,objectclass | where {($_.objectclass -eq "user") -and ($_.DistinguishedName -like "*emerald*")}  | gm

#Superseded Idea - get users OU, get comps OU
#UserAudit
#$UserAuditBranch = Get-ADObject -SearchBase "ou=managed users,ou=hcma,dc=hcma,dc=com,dc=au" -Filter * -Properties name,distinguishedname | where {($_.objectclass -like "organizationalUnit") -and ( $_.name -ne "generic")} | select name,distinguishedname | sort name | Out-GridView -Title "USERS AUDIT - Select a branch" -PassThru
#$UserAuditUsers = Get-ADUser -Filter * -SearchBase $UserAuditBranch.distinguishedname
#$UserAuditBranch.name + " " + "branch has" + " " + $UserAuditUsers.Count + " " + "users"
#
##CompAudit
#$CompAuditBranch = Get-ADObject -SearchBase "ou=managed workstations,ou=hcma,dc=hcma,dc=com,dc=au" -Filter * -Properties name,distinguishedname | where {($_.objectclass -like "organizationalUnit") -and ( $_.name -ne "generic")} | select name,distinguishedname | sort name | Out-GridView -Title "COMPUTERS AUDIT - Select a branch" -PassThru
#$CompAuditComputers = Get-ADComputer -Filter * -SearchBase $CompAuditBranch.distinguishedname
#$CompAuditBranch.name + " " + "branch has" + " " + $CompAuditComputers.Count + " " + "computers"

