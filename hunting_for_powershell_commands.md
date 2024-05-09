# Hunting for likely malicious powershell commands

### Problem Statement:
Finding adversarial powershell usage is challenging, especially when there is not a 'known bad' indicator. Examining each invocation of powershell is unreasonable, so how can we find unknown malicious commands?

### Filtering and scoring
Most powershell that is _not_ malicious tends to be short, and frequently occurring. If we could examine rarely observed **and** longer than usual commands, we could begin making the candidate pool smaller. After the initial filter, we can also start to create "feature flags" that could increase the likeliness of bad activity.

### Start with scoring the length of commandline, each doubling increases the score by one

Initial starting length is 256, feel free to adjust to more appropriate legth for your environment.

```
// Used to score length of commandline, where each doubling of length increases score by one
let length_lvl_1 = 256;
let length_lvl_2 = length_lvl_1 * 2;
let length_lvl_3 = length_lvl_1 * 2 * 2;
let length_lvl_4 = length_lvl_1 * 2 * 2 * 2;
let length_lvl_5 = length_lvl_1 * 2 * 2 * 2 * 2;
let length_lvl_6 = length_lvl_1 * 2 * 2 * 2 * 2 * 2;
```

### Create a set of strings for powershell invocation

```
let powershell_token_set = pack_array('powershell', 'pwsh');
```

### Collect commonly observed snippets of commands in malicious instances

Base64 encoding signals
```
// find Base64 encoding and/or the -EncodedCommand switch
let base64_cont_str = 'Base64';
let base64_pattern = @'-((?i)encod?e?d?c?o?m?m?a?n?d?|e|en|enc|ec)\s+([^\s]+)';
```

Execution policy, window view and explicit single threaded appartment usage
```
let bypass_token_str = 'bypass'; // needs to be used w/ powershell_token_set
let unrestricted_token_str = 'unrestricted'; // needs to be used w/ powershell_token_set
//
let hidden_token_str = 'hidden'; // needs to be used w/ token_powershell
//
let sta_token_str = '-sta';
```

Indications of downloading
```
let download_token_set = pack_array('DownloadString', 'WebClient');
let download_token_pattern = @'((?i)downloadstring|(?i)webclient)';
```

Redirection artifacts
```
let redirect_token_pattern = @'>([\s\^]?)&|>([\s\^]?)(?i)nul|>([\s\^]?)\\\\([^s]+)';
```

### Create initial set of Process Events
```
DeviceProcessEvents
| where Timestamp > now(-7d)
| project Timestamp, ProcessCommandLine, FileName, InitiatingProcessFileName, 
    DeviceId, AccountName, AccountSid, 
    InitiatingProcessCommandLine, InitiatingProcessFolderPath
| where FileName has_any (powershell_token_set)
    or ProcessCommandLine has_any (powershell_token_set)
//
// Play with minimum length of commandline to include - as long as it is useful 
//  in the enviroment you are monitoring, it is valid. Typically I keep 
//  between .5x and 2x of 'length_lvl_1', out of that boundary, you may want 
//  to adjust the base length of 'length_lvl_1'
// 
| where strlen(ProcessCommandLine) > (length_lvl_1 * 1)
//
// Find likely candidates for Base64 encoded strings
//
| extend commandLine_b64 = extract("[a-zA-Z0-9\\+\\/]{40,}[=]{0,2}",0,ProcessCommandLine)
| extend commandLine_d64 = replace_regex(unicode_codepoints_to_string(base64_decode_toarray(tostring(commandLine_b64))),@'\0','')
//
// Create column for length of commandline
| extend ProcessCommandLine_len = strlen(ProcessCommandLine)
//
// Validate the process before we run intensive queries - if we have a mistake in the logic, limit to 1000 results (remove after testing)
//
| take 1000
```
### Query for features that will become boolean values

Begin creating binary flags for use in scoring
```
| extend has_b64 = iff(
        ProcessCommandLine contains base64_cont_str
        or ProcessCommandLine matches regex base64_pattern,
        true, bool(null)
    ),
    has_b64dbl = iff(
        commandLine_d64 contains base64_cont_str
        or commandLine_d64 matches regex base64_pattern,
        true, bool(null)
    ),
    has_bypass_ps = iff(
        (ProcessCommandLine has_any (powershell_token_set)
        and ProcessCommandLine has bypass_token_str)
        or
        (commandLine_d64 has_any (powershell_token_set)
        and commandLine_d64 has bypass_token_str),
        true, bool(null)
    ),
    has_hidden_ps = iff(
        (ProcessCommandLine has_any (powershell_token_set)
        and ProcessCommandLine has hidden_token_str)
        or
        (commandLine_d64 has_any (powershell_token_set)
        and commandLine_d64 has hidden_token_str),
        true, bool(null)
    ),
    has_unrestricted_ps = iff(
        (ProcessCommandLine has_any (powershell_token_set)
        and ProcessCommandLine has unrestricted_token_str)
        or
        (commandLine_d64 has_any (powershell_token_set)
        and commandLine_d64 has unrestricted_token_str),
        true, bool(null)
    ),
    has_sta = iff(
        ProcessCommandLine has sta_token_str
        or commandLine_d64 has sta_token_str,
        true, bool(null)
    ),
    has_redirect = iff(
        ProcessCommandLine matches regex redirect_token_pattern
        or commandLine_d64 matches regex redirect_token_pattern,
        true, bool(null)
    )
```

### Start adding scores

Once the feature flags have been created, we can begin applying the scoring methodology
```
| extend score = iff(ProcessCommandLine_len > length_lvl_1, 1, 0)
| extend score = iff(ProcessCommandLine_len > length_lvl_2, score + 1, score)
| extend score = iff(ProcessCommandLine_len > length_lvl_3, score + 1, score)
| extend score = iff(ProcessCommandLine_len > length_lvl_4, score + 1, score)
| extend score = iff(ProcessCommandLine_len > length_lvl_5, score + 1, score)
| extend score = iff(ProcessCommandLine_len > length_lvl_6, score + 1, score)
//
| extend score = iff(has_b64, score + 1, score)
| extend score = iff(has_b64dbl, score + 1, score)
| extend score = iff(has_bypass_ps, score + 1, score)
| extend score = iff(has_hidden_ps, score + 1, score)
| extend score = iff(has_unrestricted_ps, score + 1, score)
| extend score = iff(has_sta, score + 1, score)
| extend score = iff(has_redirect, score + 1, score)
```

### Finalizng the query

Depending on the size of the environment, it may make sense to summarize and consolidate candidates further.


Setting a base score can be useful, YMMV.
```
| where score > 2
```

Summarization allows insights such as how many devices did we observe this command line, over what time period, and overall count. If this gets in the way, take it out!
```
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count(), 
    DeviceCount=dcount(DeviceId,4) by score, ProcessCommandLine, ProcessCommandLine_len, 
    commandLine_d64, FileName, InitiatingProcessFileName, has_b64, has_b64dbl,
    has_bypass_ps, has_hidden_ps, has_unrestricted_ps, has_sta, has_redirect
```

If filtering to command lines that are seen on only a subset of machines, we can use the following:
```
| where DeviceCount < 20
```

### Complete Query
```
// Used to score length of commandline, where each doubling of length increases score by one
let length_lvl_1 = 256;
let length_lvl_2 = length_lvl_1 * 2;
let length_lvl_3 = length_lvl_1 * 2 * 2;
let length_lvl_4 = length_lvl_1 * 2 * 2 * 2;
let length_lvl_5 = length_lvl_1 * 2 * 2 * 2 * 2;
let length_lvl_6 = length_lvl_1 * 2 * 2 * 2 * 2 * 2;
//
let powershell_token_set = pack_array('powershell', 'pwsh');
//
let base64_cont_str = 'Base64';
let base64_pattern = @'-((?i)encod?e?d?c?o?m?m?a?n?d?|e|en|enc|ec)\s+([^\s]+)';
//
let bypass_token_str = 'bypass'; // needs to be used w/ powershell_token_set
let unrestricted_token_str = 'unrestricted'; // needs to be used w/ powershell_token_set
//
let hidden_token_str = 'hidden'; // needs to be used w/ token_powershell
//
let sta_token_str = '-sta';
//
let download_token_set = pack_array('DownloadString', 'WebClient');
let download_token_pattern = @'((?i)downloadstring|(?i)webclient)';
//
let redirect_token_pattern = @'>([\s\^]?)&|>([\s\^]?)(?i)nul|>([\s\^]?)\\\\([^s]+)';
//
DeviceProcessEvents
| where Timestamp > now(-7d)
| project Timestamp, ProcessCommandLine, FileName, InitiatingProcessFileName, 
    DeviceId, AccountName, AccountSid, 
    InitiatingProcessCommandLine, InitiatingProcessFolderPath
| where FileName has_any (powershell_token_set)
    or ProcessCommandLine has_any (powershell_token_set)
// 
| where strlen(ProcessCommandLine) > (length_lvl_1 * 1)
// Find likely candidates for Base64 encoded strings
| extend commandLine_b64 = extract("[a-zA-Z0-9\\+\\/]{40,}[=]{0,2}",0,ProcessCommandLine)
| extend commandLine_d64 = replace_regex(unicode_codepoints_to_string(base64_decode_toarray(tostring(commandLine_b64))),@'\0','')
// Create column for length of commandline
| extend ProcessCommandLine_len = strlen(ProcessCommandLine)
//
// Validate the process before we run intensive queries - remove after testing
//
| take 1000
//
| extend has_b64 = iff(
    ProcessCommandLine contains base64_cont_str
    or ProcessCommandLine matches regex base64_pattern,
    true, bool(null)
),
has_b64dbl = iff(
    commandLine_d64 contains base64_cont_str
    or commandLine_d64 matches regex base64_pattern,
    true, bool(null)
),
has_bypass_ps = iff(
    (ProcessCommandLine has_any (powershell_token_set)
    and ProcessCommandLine has bypass_token_str)
    or
    (commandLine_d64 has_any (powershell_token_set)
    and commandLine_d64 has bypass_token_str),
    true, bool(null)
),
has_hidden_ps = iff(
    (ProcessCommandLine has_any (powershell_token_set)
    and ProcessCommandLine has hidden_token_str)
    or
    (commandLine_d64 has_any (powershell_token_set)
    and commandLine_d64 has hidden_token_str),
    true, bool(null)
),
has_unrestricted_ps = iff(
    (ProcessCommandLine has_any (powershell_token_set)
    and ProcessCommandLine has unrestricted_token_str)
    or
    (commandLine_d64 has_any (powershell_token_set)
    and commandLine_d64 has unrestricted_token_str),
    true, bool(null)
),
has_sta = iff(
    ProcessCommandLine has sta_token_str
    or commandLine_d64 has sta_token_str,
    true, bool(null)
),
has_redirect = iff(
    ProcessCommandLine matches regex redirect_token_pattern
    or commandLine_d64 matches regex redirect_token_pattern,
    true, bool(null)
)
//
| extend score = iff(ProcessCommandLine_len > length_lvl_1, 1, 0)
| extend score = iff(ProcessCommandLine_len > length_lvl_2, score + 1, score)
| extend score = iff(ProcessCommandLine_len > length_lvl_3, score + 1, score)
| extend score = iff(ProcessCommandLine_len > length_lvl_4, score + 1, score)
| extend score = iff(ProcessCommandLine_len > length_lvl_5, score + 1, score)
| extend score = iff(ProcessCommandLine_len > length_lvl_6, score + 1, score)
//
| extend score = iff(has_b64, score + 1, score)
| extend score = iff(has_b64dbl, score + 1, score)
| extend score = iff(has_bypass_ps, score + 1, score)
| extend score = iff(has_hidden_ps, score + 1, score)
| extend score = iff(has_unrestricted_ps, score + 1, score)
| extend score = iff(has_sta, score + 1, score)
| extend score = iff(has_redirect, score + 1, score)
//
| where score > 2
//
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count(), 
    DeviceCount=dcount(DeviceId,4) by score, ProcessCommandLine, ProcessCommandLine_len, 
    commandLine_d64, FileName, InitiatingProcessFileName, has_b64, has_b64dbl,
    has_bypass_ps, has_hidden_ps, has_unrestricted_ps, has_sta, has_redirect
//
| where DeviceCount < 20
//
| project-reorder score, DeviceCount, ProcessCommandLine_len, commandLine_d64
| sort by score desc
```


## Additional Feature Flags that may be useful

Find Base64 encoded binaries
```
let b64_pe_str = 'TVqQ';
```

Find Base64 GZip encoding
```
let b64_gz_str = 'H4sI';
```

Find noninteractive, noprofile switches (powershell invoke)
```
let noninteractive_pattern = @'((?i)noni?n?t?e?r?a?c?t?i?v?e?|noni)\s+([^\s]+)';
let noprofile_pattern = @'-((?i)nop?r?o?f?i?l?e?|nop)\s+([^\s]+)';
```

Find binary (math) operation indicators
```
let binary_token_set = pack_array('xor', 'bxor', 'bor', 'band', 'bnot', 'shl', 'shr');
let binary_token_pattern = @'([-\s]?)((?i)xor|(?i)bxor|(?i)bor|(?i)band|(?i)bnot|(?i)shl|(?i)shr)\s+'; 
```

Find usage of *Bytes
```
let bytes_token_set = pack_array('WriteAllBytes', 'GetBytes', 'ReadAllBytes','SendBytes', '[byte[]]');
let bytes_token_pattern = @'((?i)WriteAllBytes|(?i)GetBytes|(?i)ReadAllBytes|(?i)SendBytes|(?i)byte\[\])';
```

Find usage of clearing the event log 
```
let clearLog_token_set = pack_array('wevutil cl', 'wevutil.exe cl', 'Clear-EventLog');
let clearLog_token_pattern = @'((?i)wevutil([\s]+)cl|(?i)wevutil.exe([\s]+)cl|(?i)clear-eventlog)';
```

Find convert
```
let convert_token_str = 'convert';
let convert_token_pattern = @'(?i)convert';
```

Find cryptography
```
let cryptography_token_str = 'cryptography';
```

Find download
```
let download_token_set = pack_array('DownloadString', 'WebClient');
let download_token_pattern = @'((?i)downloadstring|(?i)webclient)';
```

Find Invoke-Expression
```
let iex_token_set = pack_array('iex', 'Invoke-Expression');
let iex_token_pattern = @'((?i)iex|(?i)invoke-expression)';
```

Find Inline Language
```
let inlineLang_token_set = pack_array('using System', '-Language');
let inlineLang_token_pattern = @'((?i)using system|-(?i)language)';
```

Find marshall
```
let marshall_token_str = 'marshall';
let marshall_token_pattern = @'(?i)marshall';
```

Find reflection
```
let reflection_token_str = 'Reflection';
```

Find replace
```
let replace_token_str = 'replace';
let replace_token_pattern = @'(?i)replace';
```

Find schtasks
```
let schtask_token_set = pack_array('schtasks', 'ScheduledTask');
let schtask_token_pattern = @'((?i)schtasks|(?i)scheduledtask)';
```

Find security
```
let security_token_str = 'security';
```

Find (memory)stream
```
let stream_token_set = pack_array('MemoryStream', 'Serialization', 'BinaryFormatter', 'StreamReader','GzipStream');
let stream_token_pattern = @'((?i)MemoryStream|(?i)Serialization|(?i)BinaryFormatter|(?i)StreamReader|(?i)GzipStream)';
```

Find wmi
```
let wmi_token_set = pack_array('wmic', 'wmiobject', 'wmiclass', 'CIMMethod', 'CIMInstance');
let wmi_token_pattern = @'((?i)wmic|(?i)wmiobject|(?i)wmiclass|(?i)cimmethod|(?i)ciminstance)';
```
