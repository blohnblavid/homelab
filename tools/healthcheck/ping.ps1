# Dead-man's-switch ping, run by a Windows scheduled task.
# Replace CHANGE_ME with the check's ping UUID from Healthchecks.io. Treat the
# full URL as a credential: anyone who has it can keep the check green.
Invoke-WebRequest -Uri "https://hc-ping.com/CHANGE_ME" -UseBasicParsing | Out-Null
