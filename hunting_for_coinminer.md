# Hunting for Coin Mining network connections

### Problem Statement:
Coin mining activities within the Organization environment often signals additional device hygiene issues and/or device compromise.

### Build or use a list of domains associated with coin mining
I started with the work done by ZeroDot1 - [CoinBlockerLists](https://gitlab.com/ZeroDot1/CoinBlockerLists), 
and consolidated to a smaller set of common domains using a powershell script (available in the
[coinlistTopLevel](https://github.com/jischell-msft/coinlistTopLevel) repo). 

Using the powershell script, I saved the output to a text file in a public repo for the following stage.

### Create External Table lookup

```
let coinList =  (externaldata (Domain:string) 
    [@"https://raw.githubusercontent.com/jischell-msft/coinlistTopLevel/main/listSmall.txt"]  with (format="csv"))
| where Domain !~ "jimdo.com" // too many FP results
;
```

### Check Network Events for matching URLs

Create minimum count of connection events
```
let minimum_count = 5;
```

Network activity matching the coinList set
```
DeviceNetworkEvents
| where Timestamp > now(-5d)
| where isnotempty(RemoteUrl)
    and not (RemoteIP in~ ('127.0.0.1', '::1'))
    and ActionType !contains "Failed"
| where RemoteUrl has_any (coinList)
```

Normalize and standardize RemoteUrl
```
| extend RemoteUrl = trim_start(@'http([s]?)://',RemoteUrl)
| extend RemoteUrl = tostring(split(RemoteUrl,'/')[0])
| extend RemoteUrl = tostring(split(RemoteUrl,':')[0])
```

Create top level destination RemoteUrl representation
```
| extend DestTopLevel = strcat( split(RemoteUrl,'.')[-2], '.', split(RemoteUrl,'.')[-1])
| extend DestTopLevel = iff(
    (strlen(DestTopLevel)  <= 6) 
    and (countof(DestTopLevel,'.') >= 2) 
    and strlen(RemoteUrl) > strlen(DestTopLevel), 
    strcat(split(RemoteUrl,'.')[-3], '.',DestTopLevel), DestTopLevel)
```

Attempt to remove browser connections
```
| where not (InitiatingProcessVersionInfoCompanyName has_any (
    'Microsoft Corporation', 
    'Microsoft Corp',
    'Google LLC', 
    'Mozilla Corporation', 
    'Opera Software',
    'Vivaldi',
    'Brave Software, Inc.'))
```


### Complete Query

```
let coinList =  (externaldata (Domain:string) 
    [@"https://raw.githubusercontent.com/jischell-msft/coinlistTopLevel/main/listSmall.txt"]  with (format="csv"))
| where Domain !~ "jimdo.com" // too many FP results
;
let minimum_count = 5;
DeviceNetworkEvents
| where Timestamp > now(-5d)
| where isnotempty(RemoteUrl)
    and not (RemoteIP in~ ('127.0.0.1', '::1'))
    and ActionType !contains "Failed"
| where RemoteUrl has_any (coinList)
//
// Normalize RemoteUrl names, remove protocol, suffix, port
| extend RemoteUrl = trim_start(@'http([s]?)://',RemoteUrl)
| extend RemoteUrl = tostring(split(RemoteUrl,'/')[0])
| extend RemoteUrl = tostring(split(RemoteUrl,':')[0])
//
// create consolidated representation of domains
| extend DestTopLevel = strcat( split(RemoteUrl,'.')[-2], '.', split(RemoteUrl,'.')[-1])
| extend DestTopLevel = iff(
    (strlen(DestTopLevel)  <= 6) 
    and (countof(DestTopLevel,'.') >= 2) 
    and strlen(RemoteUrl) > strlen(DestTopLevel), 
    strcat(split(RemoteUrl,'.')[-3], '.',DestTopLevel), DestTopLevel)
//
// Remove browser activity
| where not (InitiatingProcessVersionInfoCompanyName has_any (
    'Microsoft Corporation', 
    'Microsoft Corp',
    'Google LLC', 
    'Mozilla Corporation', 
    'Opera Software',
    'Vivaldi',
    'Brave Software, Inc.'))
| summarize Start=min(Timestamp), End=max(Timestamp),
    RemotePort_Set = tostring(array_sort_asc(make_set(RemotePort))),
    DestTopLevel = tostring(array_sort_asc(make_set(DestTopLevel))),
    Count=count() by DeviceId, 
    ProcessName = InitiatingProcessFileName, 
    CompanyName = InitiatingProcessVersionInfoCompanyName,
    CommandLine = InitiatingProcessCommandLine
| where Count >= minimum_count
| extend Duration = format_timespan(End - Start, 'dd.HH:mm:ss')
| project-reorder DeviceId, Duration,Count, ProcessName, DestTopLevel,Start, End
```
