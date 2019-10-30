-- Inputs
aws_id = nil
aws_secret = nil
s3_region = 'us-east-2' -- US East (Ohio)
s3_bucket = 'test-extensions'


-- functions

fs = {}
function fs.exists(path)
    local f=io.open(path,"r")
    if f~=nil then
        io.close(f)
        return true
    else
        return false
    end
end

function table.print (tbl, indent)
    if not indent then indent = 0 end
    local toprint = ""
    for k, v in pairs(tbl) do
        toprint = toprint .. string.rep(" ", indent)
        toprint = toprint .. tostring(k) .. ": "
        if (type(v) == "table") then
            toprint = toprint .. table.print(v, indent + 2) .. "\r\n"
        else
            toprint = toprint .. tostring(v) .. "\r\n"
        end
    end
    print(toprint)
end


function table.val_to_str ( v )
  if  type( v ) == "string" then
    v = string.gsub( v, "\n", "\\n" )
    if string.match( string.gsub(v,"[^'\"]",""), '^"+$' ) then
      return "'" .. v .. "'"
    end
    return '"' .. string.gsub(v,'"', '\\"' ) .. '"'
  else
    return type( v ) == "table" and table.tostring( v ) or
      tostring( v )
  end
end

function table.key_to_str ( k )
  if type( k ) == "string" and string.match( k, "^[_%a][_%a%d]*$" ) then
    return k
  else
    return "[" .. table.val_to_str( k ) .. "]"
  end
end

function table.tostring( tbl )
  local result, done = {}, {}
  for k, v in ipairs( tbl ) do
    table.insert( result, table.val_to_str( v ) )
    done[ k ] = true
  end
  for k, v in pairs( tbl ) do
    if not done[ k ] then
      table.insert( result,
        table.key_to_str( k ) .. "=" .. table.val_to_str( v ) )
    end
  end
  return "{" .. table.concat( result, "," ) .. "}"
end


-- Tests
--------------------------------------------------------------------------------

print("(os.print) Starting Tests at " .. os.date("%x"))

host_info = hunt.env.host_info()

hunt.print("(hunt.print) Starting tests at " .. os.date("%x"))
hunt.log("OS (hunt.log): " .. host_info:os())
hunt.warn("Architecture (hunt.warn): " .. host_info:arch())
hunt.debug("Hostname (hunt.debug): " .. host_info:hostname())
hunt.verbose("Domain (hunt.verbose): " .. host_info:domain())
hunt.error("Error (hunt.error): Great Succcess!")

hunt.log("is_windows(): " .. tostring(hunt.env.is_windows()))
hunt.log("is_linux(): " .. tostring(hunt.env.is_linux()))
hunt.log("is_macos(): " .. tostring(hunt.env.is_macos()))
hunt.log("has_powershell(): " .. tostring(hunt.env.has_powershell()))
hunt.log("has_python(): " .. tostring(hunt.env.has_python()))
hunt.log("has_python2(): " .. tostring(hunt.env.has_python2()))
hunt.log("has_python3(): " .. tostring(hunt.env.has_python3()))

hunt.log("OS (hunt.env.os): " .. hunt.env.os())
hunt.log("API: " .. tostring(hunt.net.api()))
hunt.log("APIv4: " .. table.tostring(hunt.net.api_ipv4()))
-- hunt.log("APIv4: " .. table.print(hunt.net.api_ipv4()))

hunt.log("os.getenv() temp: " .. os.getenv("TEMP"))
hunt.log("os.getenv() name: " .. os.getenv("COMPUTERNAME"))

hunt.log("DNS lookup: " .. table.tostring(hunt.net.nslookup("www.google.com")))
hunt.log("Reverse Lookup: " .. table.tostring(hunt.net.nslookup("8.8.8.8")))


-- client = hunt.web.new("https://infocyte-support.s3.us-east-2.amazonaws.com/developer/infocytedevkit.exe")
-- client:disable_tls_verification()
-- client:download_file("C:/windows/temp/devkit2.exe")
-- data = client:download_data()

procs = hunt.process.list()
hunt.log("ProcessList: " .. table.tostring(procs))
for _, proc in pairs(procs) do
    hunt.log("Found pid " .. proc:pid() .. " @ " .. proc:path())
    hunt.log("- Owned by: " .. proc:owner())
    hunt.log("- Started by: " .. proc:ppid())
    hunt.log("- Command Line: " .. proc:cmd_line())
end

hunt.log("Killing calc.exe")
print(hunt.process.kill_process('C:\\windows\\system32\\calc.exe'))
print(hunt.process.kill_process('Calculator'))

regkey = '\\Registry\\User'

r = hunt.registry.list_keys(regkey)
hunt.log("Registry: " .. table.tostring(r))

for name,value in pairs(hunt.registry.list_values(regkey)) do
    print(name .. ": " .. value)
end

rule = [[
rule OffsetExample {
	strings:
		$mz = "MZ"

	condition:
		$mz at 0
}
]]

yara = hunt.yara.new()
yara:add_rule(rule)
path = [[C:\windows\system32\calc.exe]]
for _, signature in pairs(yara:scan(path)) do
    hunt.log("Found " .. signature .. " in file!")
end


hunt.log("SHA1 file: " .. tostring(hunt.hash.sha1(path)))
data = hunt.unbase64("dGVzdA==")
-- t = hunt.hash.sha1_data(data)
-- hunt.log("Sha1 data: " .. tostring(t))
hunt.log('unbase64 ("test"): ' .. tostring(hunt.bytes_to_string(hunt.unbase64("dGVzdA=="))))


recovery = hunt.recovery.s3(aws_id, aws_secret, s3_region, s3_bucket)
print(recovery)
file = 'c:\\windows\\system32\\notepad.exe'
temppath = os.getenv("TEMP") .. '\\test1234.zip'
hunt.gzip(file, temppath)
if  fs.exists(temppath) then hunt.log("Zip Succeeded") else hunt.log('Zip Failed') end
hunt.log('Uploading ' .. temppath .. ' to S3 Bucket [' ..s3_region .. ':' .. s3_bucket .. ']' )
recovery.upload_file(temppath, 'evidence.bin')
