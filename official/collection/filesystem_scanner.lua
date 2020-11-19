--[=[
filetype = "Infocyte Extension"

[info]
name = "Filesystem Scanner"
type = "Collection"
description = """Scans system for filenames matching a set of regex patterns (like ransomware notes)"""
author = "Infocyte"
guid = "1775f23f-34a6-4f83-91e6-49c48faa66bb"
created = "2020-04-06"
updated = "2020-09-10"

## GLOBALS ##
# Global variables

    [[globals]]
    name = "filesystem_scanner_default_regex_bad"
    description = "Filesystem scanner regex to produce an alerting match against"
    type = "string"
    default = """DECRYPT"""

    [[globals]]
    name = "filesystemscanner_default_regex_suspicious"
    description = "Filesystem scanner regex to produce a non-alerting match against"
    type = "string"
    default = """readme.*txt$"""

    [[globals]]
    name = "trailing_days"
    type = "number"
    default = 60
    required = false


## ARGUMENTS ##
# Runtime arguments

    [[args]]
    name = "regex_bad"
    description = "Filesystem scanner regex to produce an alerting match against"
    type = "string"

    [[args]]
    name = "regex_suspicious"
    description = "Filesystem scanner regex to produce a non-alerting match against"
    type = "string"

    [[args]]
    name = "path"
    description = "Path or comma-seperated list of paths to search"
    type = "string"
    default = 'C:/users'

    [[args]]
    name = "recurse_depth"
    description = "Levels below the folder to search through"
    type = "number"
    default = 3


]=]

--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

regex_suspicious = hunt.arg.string("regex_suspicious") or hunt.global.string("filesystemscanner_default_regex_suspicious", false, [[readme.*\.txt$]])
regex_bad = hunt.arg.string("regex_bad") or 
hunt.global.string("filesystem_scanner_default_regex_bad", false, [[(^[0-9,A-Z,a-z]{4,6}-Readme\.txt$)|DECRYPT]])

path = hunt.global.string("path", false, "C:/Users")
paths = {}
if path ~= nil then
    -- Split comma-seperated values
	for val in string.gmatch(path, '[^,%s]+') do
		table.insert(paths, val)
	end
end

recurse_depth = hunt.arg.number("recurse_depth", false, 3)

--experimental (not in use)
powershell = not hunt.global.boolean("disable_powershell", false, false)
trailing_days = hunt.global.number("trailing_days", false, 30)


--[=[ SECTION 2: Functions ]=]

-- FileSystem Functions --
function path_exists(path)
    --[=[
        Check if a file or directory exists in this path. 
        Input:  [string]path -- Add '/' on end of the path to test if it is a folder
        Output: [bool] Exists
                [string] Error message -- only if failed
    ]=] 
   local ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

function get_filename(path)
    match = path:match("^.+[\\/](.+)$")
    return match
end
  
function get_fileextension(path)
    match = path:match("^.+(%..+)$")
    return match
end

function userfolders()
    --[=[
        Returns a list of userfolders to iterate through
        Output: [list]ret -- List of userfolders (_, path)
    ]=]
    local paths = {}
    local u = {}
    for _, userfolder in pairs(hunt.fs.ls("C:\\Users", {"dirs"})) do
        if (userfolder:full()):match("Users") then
            if not u[userfolder:full()] then
                -- filter out links like "Default User" and "All Users"
                u[userfolder:full()] = true
                table.insert(paths, userfolder:path())
            end
        end
    end
    return paths
end

function parse_csv(path, sep)
    --[=[
        Parses a CSV on disk into a lua list.
        Input:  [string]path -- Path to csv on disk
                [string]sep -- CSV seperator to use. defaults to ','
        Output: [list]
    ]=] 
    tonum = true
    sep = sep or ','
    local csvFile = {}
    local file,msg = io.open(path, "r")
    if not file then
        hunt.error(f"CSV Parser failed: ${msg}")
        return nil
    end
    local header = {}
    for line in file:lines() do
        local n = 1
        local fields = {}
        if not line:match("^#TYPE") then 
            for str in string.gmatch(line, "([^${sep}]+)") do
                s = str:gsub('"(.+)"', "%1")
                if not s then 
                    hunt.debug(line)
                    hunt.debug('column: '..v)
                end
                if #header == 0 then
                    fields[n] = s
                else
                    v = header[n]
                    fields[v] = tonumber(s) or s
                end
                n = n + 1
            end
            if #header == 0 then
                header = fields
            else
                table.insert(csvFile, fields)
            end
        end
    end
    file:close()
    return csvFile
end


--[=[ SECTION 3: Collection ]=]


-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

startdate = os.date("%x", os.time()-60*60*24*trailing_days)

hunt.status.good()

for _, path in pairs(paths) do 
    opts = {
        "files",
        f"recurse=${recurse_depth}"
    }
    for _, fi in pairs(hunt.fs.ls(path, opts)) do 
        file = fi
        fn = get_filename(file:path())
        if regex_bad and string.find(fn, regex_bad) then
            hunt.status.bad()
            hunt.log(f"[BAD]'${regex_bad}': ${file:path()}")
        end
        if regex_suspicious and string.find(fn, regex_suspicious) then 
            hunt.status.bad()
            hunt.log(f"[BAD]'${regex_suspicious}': ${file:path()}")
        end
    end
end

if powershell then
    for _, path in pairs(paths) do 
        cmd = f"Get-ChildItem -Path '${path}' -Recurse -Depth ${recurse_depth} -Filter *.txt | where-object { $_.Name -match '${regex_bad}' } | Select FullName -ExpandProperty FullName"
        out, err = hunt.env.run_powershell(cmd)
        if out then
            for line in out:gmatch("[^\n]+") do
                hunt.status.bad() -- Set Threat to Suspicious on finding
                hunt.log(f"[BAD]'${regex_bad}': ${line}") -- Send to Infocyte Extension Output
            end
        else
            hunt.error(f"Error running powershell: ${err}")
        end
    end

    if regex_suspicious then 
        cmd = "Get-ChildItem -Path '${path}' -Recurse -Depth ${recurse_depth} -Filter *.txt | where-object { $_.Name -match '${regex_suspicious}' } | Select FullName -ExpandProperty FullName"
        out, err = hunt.env.run_powershell(cmd)
        if out then
            for line in out:gmatch"[^\n]+" do
                hunt.status.suspicious() -- Set Threat to Suspicious on finding
                hunt.log(f"[SUSPICIOUS]'${regex_suspicious}': ${line}") -- Send to Infocyte Extension Output
            end
        else 
            hunt.error(f"Error running powershell: ${err}")
        end
    end
end

hunt.log("Result: Extension successfully executed")