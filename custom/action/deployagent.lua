--[[
	Infocyte Extension
	Name: Deploy Infocyte Agent
	Type: Action
	Description: Installs Infocyte agents on Windows
	Author: Infocyte
	Created: 9-19-2019
	Updated: 1-3-2020 (Gerritz, Dobson)
]]--

-- SECTION 1: Inputs (Variables)
regkey = nil -- Optional Registration Key for installation
force = true -- Force Reinstall with new config
instance = 'https://<MYINSTANCE>.infocyte.com' -- Replace <MYINSTANCE> with CNAME of Infocyte instance.
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

	elseif hunt.env.is_macos() then
		installpath = [[/bin/infocyte/agent.exe]]
		if hunt.fs.ls(installpath) then
			return true
		else
			return false
		end
	elseif hunt.env.is_linux() or hunt.env.has_sh() then
		installpath = [[/bin/infocyte/agent.exe]]
		if hunt.fs.ls(installpath) then
			return true
		else
			return false
		end
	else
		return false
	end
end

----------------------------------------------------
-- SECTION 3: Actions

host_info = hunt.env.host_info()
hunt.debug("Starting Extention. Hostname: " .. host_info:hostname() .. ", Domain: " .. host_info:domain() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())

install_command = ""
if is_agent_installed() then
    hunt.log("Infocyte Agent is already installed")
	
    if force then
		filedownload = assert(io.popen("powershell.exe -command \"Invoke-WebRequest https://s3.us-east-2.amazonaws.com/infocyte-support/executables/agent.windows.exe -outfile $env:TEMP\\agent.windows.exe\"" , "r")):read('*a')
		agent_path = assert(io.popen("powershell.exe -command \" echo $env:temp\\agent.windows.exe  \"" , "r")):read('*a')
		agent_path = string.gsub(agent_path, "\n", "")
		-- TODO overwrite existing config
		assert(io.popen("powershell.exe -command \"(Get-Process \"agent.windows*\"|Stop-Process -Force)" , "r")):read('*a')		
		if regkey then
			install_command = assert(io.popen("powershell.exe -command \"echo `'"..agent_path.."`' --install --url "..instance.." --key "..regkey.."\"", "r")):read('*a')
			uninstall_process = assert(io.popen("powershell.exe -command \"& '"..agent_path.."' --uninstall\"", "r"))
			uninstall_log = assert(uninstall_process):read('*a')
      		io.close(uninstall_process)
			hunt.log(uninstall_log)
		else
			install_command = assert(io.popen("powershell.exe -command \"echo '"..agent_path.."' --install --url "..instance.."\"", "r")):read('*a')
		end
	end
else

	filedownload = assert(io.popen("powershell.exe -command \"Invoke-WebRequest https://s3.us-east-2.amazonaws.com/infocyte-support/executables/agent.windows.exe -outfile $env:TEMP\\agent.windows.exe\"" , "r")):read('*a')
	agent_path = assert(io.popen("powershell.exe -command \" echo $env:temp\\agent.windows.exe  \"" , "r")):read('*a')

	if regkey then
			install_command = assert(io.popen("powershell.exe -command \"echo '"..agent_path.."' --install --url "..instance.." --key "..regkey.."\"", "r")):read('*a')
		else
			install_command = assert(io.popen("powershell.exe -command \"echo '"..agent_path.."' --install --url "..instance.."\"", "r")):read('*a')
	end
end
install_command = string.gsub(install_command, "\n", " ")
install_process = assert(io.popen("powershell.exe -command \"& "..install_command.."\"", "r"))
install_log = assert(install_process):read('*a')
io.close(install_process)
hunt.log(install_log)