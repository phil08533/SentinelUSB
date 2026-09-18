rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        description = "Looks for PowerShell encoded-command usage"
        severity = "medium"
    strings:
        $a = "-EncodedCommand" ascii nocase
        $b = "-enc " ascii nocase
        $c = "FromBase64String" ascii nocase
    condition:
        1 of them
}

rule Suspicious_WScript_Shell
{
    meta:
        description = "Looks for common Windows script execution primitives"
        severity = "medium"
    strings:
        $a = "WScript.Shell" ascii nocase
        $b = "CreateObject(\"WScript.Shell\")" ascii nocase
        $c = "Shell.Application" ascii nocase
    condition:
        1 of them
}
