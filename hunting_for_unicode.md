# Hunting for Unicode usage in the commandline

### Problem statement:
Adversaries have been observed using obfuscation or obscuring via command obfuscation [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/). The following snippets allow us to find the unicode usage that is more likely to be related to obfuscation.

### Find unicode characters that might be used for obfuscation
[Unicode Blocks](https://en.wikipedia.org/wiki/Unicode_block)

Ranges that have had interesting results (YMMV)
- 0x2020 thru 0x2060
- 0x2150 thru 0x23ff
- 0x2460 thru 0x29ff
- 0x1f000 thru 0x1f77f

### Create an array of unicode characters we want to check

**Block 01** 0x2020-0x2060 || 8224-8303
```
let unicode_block_01 = toscalar(
  print block_01 = range(8224,8303)
  | mv-apply block_01 to typeof(int) on (summarize make_set(unicode_codepoints_to_string(block_01)))
);
```
**Block 02** 0x2150-0x23ff || 8528-9215

**Block 03** 0x2460-0x29ff || 9312-10751

**Block 04** 0x1f000-0x1f77f || 126976-128895

(repeat code sections as shown for block 1)

### Check Create Process events for matching unicode characters

*The use of `has_any` rather than `matches regex` is deliberate. This is usually the less computationally intensive operation, even when `has_any` is scanning all the values of the column, since the search term is less than three characters.*

Create minimum thresholds for matching unicode characters, length of command line. Adjust as needed.
```
let min_unicode_match = toint(4);
let min_commandline_len = toint(256);
```

This query does not have an exclusion set of keywords for the command line, this will be environement specific in many cases.
```
DeviceProcessEvents
| where Timestamp > now(-5d)
| where InitiatingProcessFileName has_any ('powershell', 'pwsh', 'cmd')
    and InitiatingProcessAccountName !~ "System"
| where InitiatingProcessCommandLine has_any (unicode_block01)
    or InitiatingProcessCommandLine has_any (unicode_block02)
    or InitiatingProcessCommandLine has_any (unicode_block03)
    or InitiatingProcessCommandLine has_any (unicode_block04)
```

Exclude child process events that will not assist triage.
```
| where ProcessCommandLine !~ "conhost.exe 0xffffffff -ForceV1"
```

Using regex with `countof` because it's the only method I am aware of at this time (change my mind).
```
| extend countof_block01 = countof(InitiatingProcessCommandLine,@"([\x{2020}-\x{206f}]+)",regex)
| extend countof_block02 = countof(InitiatingProcessCommandLine,@"([\x{2150}-\x{23ff}]+)",regex)
| extend countof_block03 = countof(InitiatingProcessCommandLine,@"([\x{2460}-\x{29ff}]+)",regex)
| extend countof_block04 = countof(InitiatingProcessCommandLine,@"([\x{1f000}-\x{1f77f}]+)",regex)
| extend countChar = countof_block01 + countof_block02 + countof_block03 + countof_block04
| extend countChar_all = strlen(InitiatingProcessCommandLine)
```

Use the [type coercion](/int_to_double.md) technique for the ratio to calculate correctly
```
| extend countChar_ratio = ( todouble(countChar) / todouble(countChar_all) )
```
Only show process commandlines where it meets or exceeds the threshold set
```
| where countChar >= min_unicode_match
  and countChar_all >= min_commandline_len
```
Extract url values in the _child_ commandline (both standard and reversed)
```
| extend childCmdLine_url = extract(@'http([s]?)://([0-9a-zA-Z\.\-_/]+)',0,ProcessCommandLine),
  childCmdline_url_rev = extract(@'([0-9a-zA-Z\._\-/]+)//:([s]?)ptth',0,ProcessCommandLine)
| extend childCmdline_url_rev = reverse(childCmdline_url_rev)
```
Create feature flags, can be used for scoring or simply for faster classification and grouping
```
| extend has_url = iff( isnotempty(childCmdline_url) or isnotempty(childCmdline_url_rev), true,bool(null))
  has_url_pastebin = iff(
    (childCmdline_url has 'pastebin' or childCmdline_url_rev has 'pastebin'), true, bool(null)
  ),
  has_url_pastee = iff(
    (childCmdline_url has 'paste.ee' or childCmdline_url_rev has 'paste.ee'), true, bool(null)
  ),
  has_url_discord = iff(
    (childCmdline_url has 'discordapp' or childCmdline_url_rev has 'discordapp'), true, bool(null)
  ),
  has_url_tinyurl = iff(
    (childCmdline_url has 'tinyurl' or childCmdline_url_rev has 'tinyurl'), true, bool(null)
  ),
  has_url_ip = iff(
    (childCmdline_url matches regex @"http([s]?)://([0-9\.]{4,})"
    or childCmdline_url_rev matches regex @"http([s]?)://([0-9\.]{4,})") , true, bool(null)
  )
| project TimeStamp, DeviceId, DeviceName, countof_block01, countof_block02, countof_block03, countof_block04,
  countChar, countChar_all, countChar_ratio, has_url, has_url_pastebin, has_url_pastee, has_url_discord,
  has_url_tinyurl, has_url_ip, InitiatingProcessCommandLine, ProcessCommandLine
```

### Complete Query
```
let unicode_block_01 = toscalar(
  print block_01 = range(8224,8303)
  | mv-apply block_01 to typeof(int) on (summarize make_set(unicode_codepoints_to_string(block_01)))
);
let unicode_block_02 = toscalar(
  print block_02 = range(8528, 9215)
  | mv-apply block_02 to typeof(int) on (summarize make_set(unicode_codepoints_to_string(block_02)))
);
let unicode_block_03 = toscalar(
  print block_03 = range(9312, 10751)
  | mv-apply block_03 to typeof(int) on (summarize make_set(unicode_codepoints_to_string(block_03)))
);
let unicode_block_04 = toscalar(
  print block_04 = range(126976, 128895)
  | mv-apply block_04 to typeof(int) on (summarize make_set(unicode_codepoints_to_string(block_04)))
);
//
let min_unicode_match = toint(4);
let min_commandline_len = toint(256);
//
DeviceProcessEvents
| where Timestamp > now(-5d)
| where InitiatingProcessFileName has_any ('powershell', 'pwsh', 'cmd')
    and InitiatingProcessAccountName !~ "System"
| where InitiatingProcessCommandLine has_any (unicode_block01)
    or InitiatingProcessCommandLine has_any (unicode_block02)
    or InitiatingProcessCommandLine has_any (unicode_block03)
    or InitiatingProcessCommandLine has_any (unicode_block04)
| where ProcessCommandLine !~ "conhost.exe 0xffffffff -ForceV1"
| extend countof_block01 = countof(InitiatingProcessCommandLine,@"([\x{2020}-\x{206f}]+)",regex)
| extend countof_block02 = countof(InitiatingProcessCommandLine,@"([\x{2150}-\x{23ff}]+)",regex)
| extend countof_block03 = countof(InitiatingProcessCommandLine,@"([\x{2460}-\x{29ff}]+)",regex)
| extend countof_block04 = countof(InitiatingProcessCommandLine,@"([\x{1f000}-\x{1f77f}]+)",regex)
| extend countChar = countof_block01 + countof_block02 + countof_block03 + countof_block04
| extend countChar_all = strlen(InitiatingProcessCommandLine)
| extend countChar_ratio = ( todouble(countChar) / todouble(countChar_all) )
| where countChar >= min_unicode_match
  and countChar_all >= min_commandline_len
| extend childCmdLine_url = extract(@'http([s]?)://([0-9a-zA-Z\.\-_/]+)',0,ProcessCommandLine),
  childCmdline_url_rev = extract(@'([0-9a-zA-Z\._\-/]+)//:([s]?)ptth',0,ProcessCommandLine)
| extend childCmdline_url_rev = reverse(childCmdline_url_rev)
| extend has_url = iff( isnotempty(childCmdline_url) or isnotempty(childCmdline_url_rev), true,bool(null))
  has_url_pastebin = iff(
    (childCmdline_url has 'pastebin' or childCmdline_url_rev has 'pastebin'), true, bool(null)
  ),
  has_url_pastee = iff(
    (childCmdline_url has 'paste.ee' or childCmdline_url_rev has 'paste.ee'), true, bool(null)
  ),
  has_url_discord = iff(
    (childCmdline_url has 'discordapp' or childCmdline_url_rev has 'discordapp'), true, bool(null)
  ),
  has_url_tinyurl = iff(
    (childCmdline_url has 'tinyurl' or childCmdline_url_rev has 'tinyurl'), true, bool(null)
  ),
  has_url_ip = iff(
    (childCmdline_url matches regex @"http([s]?)://([0-9\.]{4,})"
    or childCmdline_url_rev matches regex @"http([s]?)://([0-9\.]{4,})") , true, bool(null)
  )
| project TimeStamp, DeviceId, DeviceName, countof_block01, countof_block02, countof_block03, countof_block04,
  countChar, countChar_all, countChar_ratio, has_url, has_url_pastebin, has_url_pastee, has_url_discord,
  has_url_tinyurl, has_url_ip, InitiatingProcessCommandLine, ProcessCommandLine
```
