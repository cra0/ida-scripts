
# CVDF (Cra0 Vtable Definition File)

Definition file for IDA to resolve object vtables in a IDB based on a in-memory dump.

## Comments

Comments are defined using two forward slashes:

```
// This is a comment
```

---------------

## Definition Count

The definition file must contain a count for the list of definitions defined in the file. This is denoted by a **hyphen** and **c** character followed by a space ending with the **count** as an integer.

> -c {count}

In the example below the count is 10.
```
-c 10
``` 

---------------

## Definition Declaration 

A vtable declaration starts with a ***hexadecimal*** offset from the `ImageBase` followed by the **vtable variable name** then lastly ending with the **full vtable name** as comment.
All strings are represented with quotation marks around them. **"string"**.

> {hex_offset_address},"variable_name","display_name"

---------------

