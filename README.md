# Azure-Get-Sensitive-Log-Data
Script to parse azure log files for potentially sensitive data that could be exposed to threat actors if sufficient access is gained to Azure. 
Strictly alpha right now

# Functionality
Scans 500 recent sign-in and audit logs for patterns like:

   -> Email-style usernames

   -> Hostnames and IPs

   -> Any occurrence of words like “password”, “token”, “key” (useful if custom apps log those)

   -> Flags entries and exports them to a CSV for review
