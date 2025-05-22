
## Random
(get-host).version – Retrieves the PowerShell version from the host.
$host.version – Displays the version of the PowerShell host.
$psversiontable.psversion – Retrieves the PowerShell version using the PSVersionTable.
pwsh.exe – Launches PowerShell Core after it's installed.
powershell.exe – Launches the built-in Windows PowerShell version.

## Logic
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


## Profiles
$HOME – Stores the current user’s home directory.
$PsHome – Stores the installation directory for PowerShell.
$Profile – Stores the path to the "Current User, Current Host" profile.
get-help about_profiles – Displays help information about PowerShell profiles.
test-path -path $PROFILE.AllUsersAllHosts – Checks if a profile is loaded for "All Users, All Hosts."

## Registry
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

## NTFS
$DATA – Stores an alternate data stream.
$LOGGED_UTILITY_STREAM – Holds information about a file's encrypted attributes.
$SECURITY_DESCRIPTOR – Contains the file security and access control properties.
$STANDARD_INFORMATION – Stores the file times of an object.
0x80 – Type ID in hex of the attribute that stores an NTFS file’s contents.
fsutil fsinfo drives – Lists only the letters of attached drives.

## File system
d – Represents the directory attribute for files.
h – Represents the hidden attribute for files.
get-childitem -force – Lists all files in the current directory, including hidden and system files.
get-filehash -algorithm sha512 – Computes and returns the SHA-512 hash of a specified file.
get-acl – Retrieves the permissions assigned to a file.
hosts – The Windows file that maps hostnames to IP addresses.







