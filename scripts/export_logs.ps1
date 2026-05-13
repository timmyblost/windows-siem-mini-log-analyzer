Get-WinEvent -LogName Security -MaxEvents 500 |
Select-Object TimeCreated, Id, ProviderName, Message |
Export-Csv ".\sample_logs\sample_events.csv" -NoTypeInformation