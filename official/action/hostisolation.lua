--[[
	Infocyte Extension
	Name: Host Isolation
	Type: Action
	Description: Performs a local network isolation of a Windows, Linux, or OSX
	 system using windows firewall, iptables, ipfw, or pf
	Author: Infocyte
	Created: 9-16-2019
	Updated: 9-16-2019 (Gerritz)

]]--

-- SECTION 1: Inputs (Variables)

whitelisted_ips = {
	"192.168.1.1",
	"192.167.1.2"
}



----------------------------------------------------
-- SECTION 2: Functions


----------------------------------------------------
-- SECTION 3: Actions

host_info = hunt.env.host_info()
os = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

whitelist = hunt.net.api_ipv4()
table.insert(whitelist, whitelisted_ips)

-- TO DO: Check for Agent and install if not present
-- agent will be the only thing able to communicate out
agentinstalled = true
if agentinstalled then
	-- Continue
else
	-- Install Infocyte Agent
	if string.find(OS, "xp") then
		-- TO DO: XP
	elseif hunt.env.is_windows() and hunt.env.has_powershell() then
	  -- Insert your Windows code
		psagentdeploycmd = [[
		& { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
		(new-object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1') |
			iex; installagent ]] .. myhuntinstance .." }"

		result = os.execute("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -nologo -win 1 -executionpolicy bypass -nop -command { "..psagentdeploycmd.." }")
		if not result then
			hunt.log("Powershell agent install script failed to run. [Error: "..result.."]")
			exit()
		end
	elseif hunt.env.is_macos() then
	    -- Insert your MacOS Code

	elseif hunt.env.is_linux() or hunt.env.has_sh() then
	    -- Insert your POSIX (linux) Code

	else
	    hunt.warn("WARNING: Not a compatible operating system for this extension [" .. host_info:os() .. "]")
		return
	end
end

if string.find(OS, "windows xp") then
	-- TO DO: XP's netsh
elseif hunt.env.is_windows() then
	os.execute("mkdir " .. workingfolder)
	os.execute("netsh advfirewall export " .. workingfolder .. "\\fwbackup.wfw")
	os.execute("netsh advfirewall firewall set rule all NEW enable=no")
	os.execute("netsh advfirewall firewall add rule name='Infocyte Host Isolation' dir=in action=allow protocol=ANY remoteip=" .. infocyteips)
	os.execute("netsh advfirewall reset")

elseif hunt.env.is_macos() then
	-- TO DO: ipfw (old) or pf (10.6+)

elseif  hunt.env.has_sh() then
	-- Assume linux-type OS and iptables
	-- TO DO: IPTables

end


----------------------------------------------------
-- SECTION 4: Output
log("Host has been isolated to " .. infocyteips)
