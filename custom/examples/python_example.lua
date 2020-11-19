host_info = hunt.env.host_info()

if hunt.env.has_python() then
  script = [==[
from datetime import datetime
import json
def whattimeisit():
	timestamp = datetime.now().isoformat(timespec='minutes')
	time_dictionary = {'The Time is Now':timestamp}	
	return json.dumps(time_dictionary)
whattimeisit()
  ]==]
  time=hunt.env.run_python(print("Hello World!"))

  hunt.log(time)
  hunt.status.good()

end
