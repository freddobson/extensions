if hunt.env.is_windows() and hunt.env.has_powershell() then
  script = [==[
	Get-Date # You can literally put ANY PowerShell Script here!!!
  ]==]
  out, err = hunt.env.run_powershell(script)
  if out then if string.len(out) > 0 then hunt.log(out) end end
  if err then if string.len(err) > 0 then hunt.error(err) end end
end