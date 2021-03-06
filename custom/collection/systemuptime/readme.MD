# System Uptime Extension

This extension can be ran on a host(s) to collect the "uptime" stat about the host. I.E., how long this machine(s) been running.

# How To
### Add the Extension to your instance.
##
Download the systemuptime.lua script. Login to your Cloud instance, go to your account icon in the top right, click **Admin** and the on the left, click **Extensions**. Paste the lua code in, name the Extension "System Uptime" and **Save**. Click the dot on the **Active** column to activate the Extension.
##
### Run the Extension on the desired host(s)
##
Now to collect the uptime stats! Extensions can be side-loaded along the survey, so just a run a scan as normal and under **Extension Options** , add the **System Uptime** extension. 
##
### View the results one at a time
##
Once the scan is complete, you may view the uptime stats one at a time under the **Analyze** section of Infocyte (click **Extensions** on the left-hand sidebar. This may tedious if you have many hosts you want to view the uptime for.
##
### Pull results via API.
##
Download this [PowerShell script](https://github.com/freddobson/infocyteapiscripts/blob/master/exportUptime/exportSystemUptime.ps1) and run it using the InfocyteHUNTAPI module. This will allow you to export/download/view the results in bulk! It will return any results from the System Uptime Extension made in the Last 7 days.
