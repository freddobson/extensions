host_info = hunt.env.host_info()

if hunt.env.is_windows() and hunt.env.has_powershell() then
  uptime = assert(io.popen("powershell.exe -command \"(Get-WmiObject win32_operatingsystem | select @{n='Uptime';e={$_.ConverttoDateTime($_.lastbootuptime)}}).Uptime.tostring().trim('`n`r')\" ", "r"))
  readdate = assert(uptime:read('*a'))
  
  result = "{\"Hostname\": \"" .. host_info:hostname() .. "\","
  result = result .. "\"Domain\": \"" .. host_info:domain() .. "\"," 
  result = result .. "\"OS\": \"" .. host_info:os() .. "\","
  result = result .. "\"Architecture\": \"" .. host_info:arch() .. "\","
  result = result .. "\"Uptime\": \"" .. readdate .. "\"}"
  hunt.log(result)
  hunt.status.good()

elseif hunt.env.is_linux() then
  uptime = assert(io.popen("who -b"))
  readdate = assert(uptime:read('*all'))
  result = "{\"Hostname\": \"" .. host_info:hostname() .. "\","
  result = result .. "\"Domain\": \"" .. host_info:domain() .. "\"," 
  result = result .. "\"OS\": \"" .. host_info:os() .. "\","
  result = result .. "\"Architecture\": \"" .. host_info:arch() .. "\","
  result = result .. "\"Uptime\": \"" .. readdate .. "\"}"
  hunt.log(result)
  hunt.status.good()
end
