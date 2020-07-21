if hunt.env.is_windows() and hunt.env.has_powershell() then

batfile = [==[
@echo off
:: Install Infocyte Agent
:: For use in a GPO Startup Script (Note: Logon script will not work as it operates with the user's non-admin permissions)
:: Best Reference for steps: https://www.petri.com/run-startup-script-batch-file-with-administrative-privileges

:: Change "instancename" to your cname e.g. set instancename=myinstance
:: Change "regkey" to your registration key made in the Infocyte HUNT admin panel (or leave blank if not using) e.g. regkey=abcd1234

set instancename=demo1 
set regkey=

:: Uninstall old agent first, if any.
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -win 1 -executionpolicy bypass -nop -command "& {cat 'C:\Windows\Temp\uninstall_agent.ps1' | iex}"

:: Install agent with provided instance name and regkey (if any).
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -win 1 -executionpolicy bypass -nop -command "& { [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); (new-object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1') | iex; installagent %instancename% %regkey% }"

:: for testing, you can add a -interactive to the installagent command. The end of the above command would look like this:
:: ...installagent %instancename% %regkey% -interactive }"
]==]


file = io.open("C:\\Windows\\Temp\\install_agent.bat", "w")
io.output(file)
io.write(batfile)
io.close(file)


uninstallfile = [==[
$script = try {(get-childitem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"| where pschildname -eq "Infocyte HUNT Agent").GetValue('uninstallstring')} catch{(get-childitem "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"| where pschildname -eq "Infocyte HUNT Agent").GetValue('uninstallstring')} finally{}
"& $script"|iex  
]==]
  
file = io.open("C:\\Windows\\Temp\\uninstall_agent.ps1", "w")
io.output(file)
io.write(uninstallfile)
io.close(file)  

 
script = [==[
$time = [DateTime]::Now.AddMinutes(5)
$hourMinute=$time.ToString("HH:mm")
schtasks.exe /Create /RU SYSTEM /SC ONCE /TN "Reinstall Infocyte" /TR "C:\Windows\Temp\install_agent.bat" /ST $hourMinute /F
]==]

out, err = hunt.env.run_powershell(script)
if out then if string.len(out) > 0 then hunt.log(out) end end
if err then if string.len(err) > 0 then hunt.error(err) end end

end	