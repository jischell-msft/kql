# Coerce from int() to double() to calculate fractions


### Explicit casting of variables to int() type
```
let int_01 = toint(33);
let int_02 = toint(66);
let int_03 = toint(100);
let no_dbl_a = int_01 / int_02;
let no_dbl_b = int_02 / int_01;
let no_dbl_c = int_03 / int_02;
let fraction_a = todouble(int_01) / todouble(int_02);
let fraction_b = todouble(int_02) / todouble(int_01);
let fraction_c = todouble(int_03) / todouble(int_02);
```

### Sample #1
- No change to type - should be 0.5
```
print (no_dbl_a)
```
| print_0 |
|---|
| 0 |

- No change to type - should be 2
```
print (no_dbl_b)
```
| print_0 |
|---|
| 2 |

- No change to type - should be 1.51515151515152
```
print (no_dbl_c)
```
| print_0 |
|---|
| 1 |

### Sample #2
- Change to double - should be 0.5
```
print ( fraction_a )
```
| print_0 |
|---|
| 0.5 |

- Change to double - should be 2
```
print ( fraction_b )
```
| print_0 |
|---|
| 2 |

- Change to double - should be 1.51515151515152
```
print ( fraction_c )
```
| print_0 |
|---|
| 1.51515151515152 |

### Summary
| Scenario | No Type Change | To Double |
| --- | --- | --- |
| A | &#9744; | &#9745; |
| B | &#9745; | &#9745; |
| C | &#9744; | &#9745; |
