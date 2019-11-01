--[[
  Infocyte Extension
  Name: Host Isolation Restore
  Description: Reverses the local network isolation of a Windows, Linux, and OSX
   systems using windows firewall, iptables, ipfw, or pf respectively
  Author: Infocyte
  Created: 9-16-2019
  Updated: 9-16-2019 (Gerritz)

]]--

-- SECTION 1: Inputs (Variables)


----------------------------------------------------
-- SECTION 2: Functions



----------------------------------------------------
-- SECTION 3: Actions

host_info = hunt.env.host_info()
os = host_info:os()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())


if string.find(OS, "windows xp") then
	-- TO DO
elseif string.find(OS, "windows") then
	os.execute("netsh advfirewall firewall delete rule name='Infocyte Host Isolation'")
	os.execute("netsh advfirewall import " .. workingfolder .. "\\fwbackup.wfw")
	os.execute("netsh advfirewall reset")
elseif string.find(OS, "osx") or string.find(OS, "") then
	-- TO DO: ifw
else
	-- Assume linux-type OS and iptables
	-- TO DO: IPTables
end

----------------------------------------------------
-- SECTION 4: Output
log("Host has been restored and is no longer isolated")
