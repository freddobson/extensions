-- Warning! If you run this extension the survey will time out since it has to restart the agent service.
--[[
	Infocyte Extension
	Name: Enable Verbose Logging
	Type: Action
	Description: Enable Verbose Logging
	Author: Infocyte
	Created: 10-27-2020
	Updated: 10-27-2020 (Gerritz, Dobson)
]]--

-- SECTION 1: Inputs (Variables)
-- N/A
----------------------------------------------------
-- SECTION 2: Functions

function is_agent_installed()
	if hunt.env.is_windows() then
		key = '\\Registry\\Machine\\System\\CurrentControlSet\\Services\\HUNTAgent'
		if hunt.registry.list_values(key) then
			return true
		else
			return false
		end
	end	
end

function find_and_replace()
	if hunt.env.is_windows() and hunt.env.has_powershell() then
	  script = [==[
		(cat 'C:\Program Files\Infocyte\Agent\config.toml' -Raw) -replace "'info'","'verbose'" | Set-Content 'C:\Program Files\Infocyte\Agent\config.toml'
	  ]==]
	  out, err = hunt.env.run_powershell(script)
	  if out then if string.len(out) > 0 then hunt.log(out) end end
	  if err then if string.len(err) > 0 then hunt.error(err) end end
	end
end

function restart_agent()
	if hunt.env.is_windows() and hunt.env.has_powershell() then
	  script = [==[
		Restart-Service HUNTAgent
	  ]==]
	  out, err = hunt.env.run_powershell(script)
	  if out then if string.len(out) > 0 then hunt.log(out) end end
	  if err then if string.len(err) > 0 then hunt.error(err) end end
	end
end	
----------------------------------------------------
-- SECTION 3: Actions



if is_agent_installed() then
    hunt.log("Infocyte Agent is installed, attempting find and replace at C:\\Program Files\\Infocyte\\Agent\\config.toml")
	find_and_replace()
    hunt.log("Not sure if that worked, but restarting the agent anyways.")
	restart_agent()
else
	hunt.log("Still need to config script to deploy config.toml to temporary agent.")
	
end
 