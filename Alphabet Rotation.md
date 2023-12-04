# Alphabet rotation by arbitrary offset (modulo 26)

```
let get_RotationString = (
	input:string,
	rotation:int = 13
	)
{
	let rotation_mod = rotation % 26; // make sure we stay within the bounds of alphabet
	let upperDouble = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
	let lowerDouble = tolower(upperDouble);
	let upperOffset = substring(upperDouble,rotation_mod,26);
	let lowerOffset = substring(lowerDouble,rotation_mod,26);
	let alphaOrg = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	let alphaOff = strcat(upperOffset, lowerOffset);
	print InputString=input
	| extend rotationTranslate = translate(alphaOrg, alphaOff,input)
};
```

Testing with sample inputs
```
get_RotationString('test1@example.com', rotation=(13))
```

| InputString | rotationTranslate |
| --- | --- |
| test1@example.com | grfg1@rknzcyr.pbz |


```
get_RotationString('Test1@example.com', rotation=(-1))
```

| InputString | rotationTranslate  |
| --- | --- |
| Test1@example.com  |	Sdrs1@dwzlokd.bnl |

