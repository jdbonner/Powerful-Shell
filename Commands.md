

































































## Extra Notes

### Random
(get-host).version – Retrieves the PowerShell version from the host.
$host.version – Displays the version of the PowerShell host.
$psversiontable.psversion – Retrieves the PowerShell version using the PSVersionTable.
pwsh.exe – Launches PowerShell Core after it's installed.
powershell.exe – Launches the built-in Windows PowerShell version.

### Logic
get-command – Lists all PowerShell cmdlets.
get-verb – Lists all available PowerShell verbs.
get-member – Lists all properties and methods of a PowerShell object.
get-alias – Lists PowerShell aliases.
get-childitem – Lists all contents of a directory.
get-help – Displays help about PowerShell cmdlets and concepts.
update-help – Updates PowerShell help files to the latest version.
start chrome – Starts the Chrome browser.
(get-process chrome).kill() – Stops Chrome using a PowerShell method.
stop-process -name chrome – Stops the Chrome process.
Get-WmiObject Win32_Processor – Retrieves information about the system's processor.
get-content – Reads a text file.
measure-object – Counts lines, averages numbers, and sums numbers.
select-string – Searches for text patterns in a string.
compare-object -referenceobject (get-content old.txt) -differenceobject (get-content new.txt) – Finds differences between two text files.
sort-object -descending | select-object -index 21 – Gets the 21st line from a sorted text file.
(get-content words.txt | sort-object | get-unique).count – Counts unique words in a text file.
(get-process | get-member -membertype property).count – Displays the number of properties for a process.
(get-process | get-member -membertype method).count – Displays the number of methods for a process.
(get-childitem -recurse | where-object {$_.PSIsContainer}).count – Counts folders in a directory.
(get-content words.txt | select-string -allmatches "gaab").count – Counts occurrences of "gaab" in a text file.
(get-content words.txt | where-object { $_ -match '(a|z)'}).count – Counts words that contain "a" or "z".
(get-content words.txt | where-object { $_ -match '(az)'}).count – Counts lines that contain "a" or "z".
for($i=1000;$i -gt 0; $i--){expand-archive -path ".\omega${i}.zip";mv "omega${i}\omega$($i-1).zip"} – Unzips a file 1,000 times.
(get-content words.txt | where-object { $_ -match '((aa)[a-g])}).count – Counts words where "aa" is followed by "a-g".


### Profiles
$HOME – Stores the current user’s home directory.
$PsHome – Stores the installation directory for PowerShell.
$Profile – Stores the path to the "Current User, Current Host" profile.
get-help about_profiles – Displays help information about PowerShell profiles.
test-path -path $PROFILE.AllUsersAllHosts – Checks if a profile is loaded for "All Users, All Hosts."

### Registry
HKLM\HARDWARE – The Windows registry path for the Volatile Hive.
HKEY_LOCAL_MACHINE\SOFTWARE – Registry key that creates Wow6432Node, representing 32-bit applications running on a 64-bit version of Windows.
HKLM\SYSTEM\CurrentControlSet\Services – Registry path where BOOT_START drivers are located.
0x0 – Start value for BOOT_START drivers in the registry.
HKLM\SYSTEM\CurrentControlSet\Services – Registry location read during kernel initialization that contains all SYSTEM_START drivers.
0x02 – Start value for SERVICE_AUTO_START drivers and services.
0x3 – Start value for SERVICE_DEMAND_START drivers and services.
HKLM, HKU – The only two accessible HKEYs when accessing a remote registry.
get-psdrive – PowerShell cmdlet to list currently mapped drives.
regedit – Native Windows GUI tool for managing the registry.


### Registry extra
HKLM – Registry hive containing all machine settings.
HKU – Registry hive containing all user settings.
HKCU – Registry hive containing only the currently logged-in user’s settings.
reg query HKU – Lists subkeys under HKEY_USERS, showing the symbolic link for HKEY_CURRENT_USER.
get-childitem – Lists all subkeys and contents in the current or specified registry directory.
get-item – Lists only the contents of a registry key or subkey.
HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN – Registry subkey that runs every time the machine reboots.
HKEY_CURRENT_USER\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN – Registry subkey that runs every time a user logs on.
HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE – Registry subkey that runs once and deletes its value upon reboot.
HKEY_CURRENT_USER\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE – Registry subkey that runs once and deletes its value upon user logon.
reg query hklm\software\microsoft\windows\currentversion\run – Queries the registry for programs running on startup from HKEY_LOCAL_MACHINE.
reg query hkcu\software\microsoft\windows\currentversion\run – Queries the registry for programs running on startup from HKEY_CURRENT_USER.
reg query HKLM:\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE – Queries startup programs that execute once from HKEY_LOCAL_MACHINE.
reg query hkcu\software\microsoft\windows\currentversion\runonce – Queries startup programs that execute once from HKEY_CURRENT_USER.
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR – Retrieves USB storage device information.

### NTFS
$DATA – Stores an alternate data stream.
$LOGGED_UTILITY_STREAM – Holds information about a file's encrypted attributes.
$SECURITY_DESCRIPTOR – Contains the file security and access control properties.
$STANDARD_INFORMATION – Stores the file times of an object.
0x80 – Type ID in hex of the attribute that stores an NTFS file’s contents.
fsutil fsinfo drives – Lists only the letters of attached drives.

### File system
d – Represents the directory attribute for files.
h – Represents the hidden attribute for files.
get-childitem -force – Lists all files in the current directory, including hidden and system files.
get-filehash -algorithm sha512 – Computes and returns the SHA-512 hash of a specified file.
get-acl – Retrieves the permissions assigned to a file.
hosts – The Windows file that maps hostnames to IP addresses.


### Boot Process
diskpart – CLI tool for managing partitions and volumes.
winload.exe – Starts BOOT_START device drivers with a registry value of 0x0.
NTOSKRNL.exe – Starts SYSTEM_START device drivers with a registry value of 0x1.
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices – Registry key that starts services on boot.
bcdedit – Command used to diagnose boot issues.
bcdedit /deletevalue {default} safeboot – Corrects Safe Mode boot setting.
shutdown /r – Reboots the system.
shutdown -a – Aborts a scheduled shutdown.
Hiberfil.sys – File that saves memory state for hibernation.
Winresume.exe – Bootloader responsible for restoring the system after hibernation.
services.exe – Parent process of all svchost.exe instances.
LSASS – Creates access tokens for authentication.
Kerberos – Default authentication protocol for Active Directory.
KDC – Key Distribution Center, providing authentication services.


### Process
IIS – Internet Information Server, associated with inetinfo.exe.
server – Host running dns.exe is likely a server.
client – Host running Firefox and Office 365 is likely a client machine.
System Call – How a user-mode service requests resources.
baselining – Copying running processes for future comparison.
thread – Executes any part of a process’s code.
32 – Number of Windows process priority levels.
autoruns – Sysinternals tool that shows malware persistence locations.
procexp – Sysinternals tool for investigating processes.
tcpview – Sysinternals tool for investigating network connection attempts.
AccessChk – Sysinternals tool for viewing permissions.
Handle – Sysinternals tool for viewing and modifying handles.
Downloads – Default Windows user directory for internet downloads.
C:\users\public\downloads – Default Windows download directory accessible to everyone.
LoadOrder – Sysinternals tool showing service load order.
MpsSvc – Service name for Windows Defender Firewall.
ListDLLs – Sysinternals tool that reports DLLs loaded into processes.


### User account control
Sigcheck – Sysinternals tool for viewing a file's manifest.
asInvoker – RequestedExecutionLevel that runs an application with the same permissions as the process that started it.
requireAdministrator – RequestedExecutionLevel that prompts the user for Administrator credentials if they are not in the Administrator group.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System – Registry key that holds UAC values.

### Windows Services 
sc query – Displays service information using the command line.
sc queryex type=service state=all – Lists all services, whether running or not.
Get-Service – PowerShell command that retrieves and displays all services.
HKLM\System\CurrentControlSet\Services – Registry location that holds all service data.
Parameters – Registry subkey containing a service's .dll location.


### Auditing, logging, and forensic related
Monitoring – Real-time analysis of security events, often performed using a SIEM system.
Auditing – Reviewing log files or records over a specified period.
%systemroot%\System32\WinEvt\Logs\System.evtx – Path to the Windows System Log.
Security – Windows log that records success or failures, including failed logon attempts.
System – The only account with WRITE-APPEND access to Windows event logs.
SACL – Security Access Control List, used by the Security Reference Monitor to determine audit entries.
HKEY_LOCAL_MACHINE\SECURITY\Policy\PolAdtEv – Registry key holding the audit policy configuration.
PsLogList – Sysinternals tool for parsing logs.
strings.exe – Sysinternals tool for reading SQLite3 database, including Chrome web history.
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs – Registry location storing recent files for the current user.
(Get-Item "C:\Windows\System32\drivers\etc\hosts").LastAccessTime – Retrieves the last access time of the hosts file.
C:\Windows\Prefetch – Literal path to the prefetch directory.
$R – Prefix for the actual contents of a file in the Recycle Bin.
$I – Prefix for the metadata file storing deleted file details in the Recycle Bin.
CEBFF5CD – First 8 characters of the GUID used for UserAssist registry entries.
ROT13 – Encoding method used for UserAssist files.
-Wrap – Format-table switch to fully display truncated log output.
https://www.exploit-db.com – Malicious website found in Chrome history.
C:\Windows\Temp\bad_intentions.exe – Path of an abnormal program execution.
DARK_FORCES-8F2869FC.pf – Name of a questionable prefetch file.
2/23/2022 – Creation date of the suspicious prefetch file.
$RZDAQ4U.txt,DontTrashMeyo – Filename and recovered contents from the Recycle Bin.


### Networking and Name Resolution
NDIS – Implements Windows networking stack for OSI layers.
netstat -r – Displays the local computer's routing table.
dns – Hierarchical protocol that translates hostnames to IP addresses.
nslookup – CLI tool for troubleshooting DNS issues and reconnaissance.
nbtstat – Displays NetBIOS transport statistics.
System32\drivers\etc\hosts – Full path to the Windows hosts file.

### Security and Access Control
- SID – Unique identifier for users, groups, and computers.
- whoami /all – Displays the SID of the current user.
- 1000 – RID assigned to the first user account.
- 500 – Well-known RID for the Windows Built-In Administrator account.
- Get-CimInstance Win32_UserAccount | Select-Object Name,SID – Lists all user SIDs by Name and SID.
- Get-Acl – Retrieves the security descriptor of a file or resource.
- net localgroup – Enumerates local Windows group accounts.
- iCACLS – Displays or modifies ACLs for files and folders.
- DEP – Memory protection feature preventing execution in certain memory pages.
- ASLR – Prevents exploitation by randomizing memory address space positions.
- Credential Guard – Protects against Pass-the-Hash and Pass-the-Ticket attacks.
- Windows Defender – Microsoft’s built-in antivirus solution.


### Auditing and Logging
```
PsLogList – Sysinternals tool for parsing logs.
Security – Windows log showing login attempts and security events.
System – Windows log recording startup, shutdown, and update events.
-Wrap – Format-table switch to display complete log output.
```

### Memory Analysis and Malware Detection
```
procdump – Dumps a process into an executable file for analysis.
cmdscan – Extracts command history.
driverscan – Displays driver objects.
imageinfo – Determines the memory profile for a given image.
sc query malware – Checks the status of a malware service.
1a498b8 – Last seven digits of the memory offset for the malware driver.
get-filehash .\executable.544.exe -Algorithm md5 – Retrieves the MD5 hash of a potentially malicious executable (6CEE14703054E226E87A963372F767AA).
172.16.98.1:6666 – Remote IP and port to which the malware connected.
```






