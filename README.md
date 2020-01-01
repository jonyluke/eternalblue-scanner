# eternalblue-scanner
Scan your systems to see if they are vulnerable to eternalblue, or worse, if they are already infected.
This project is made in java with eclipse and is based in [nixawk's script](https://github.com/nixawk/labs/blob/master/MS17_010/smb_exploit.py)
## How to use
`java -jar scanner.java <ip>`

## Example output 
```
C:\Desktop> java -jar scanner.jar 192.168.0.17

----ETERNALBLUE SCANNER----

OS: Windows 5.1
Host is likely VULNERABLE to MS17-010!
```
