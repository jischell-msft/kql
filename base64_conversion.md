# Manipulating Base64

```
[assumes 'base64_content' is valid base64 string]
| extend decoded = replace_regex(unicode_codepoints_to_string(base64_decode_toarray(tostring(base64_content))),@'\0','')
```
