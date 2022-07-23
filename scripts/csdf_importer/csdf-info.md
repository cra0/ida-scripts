
# CSDF (Cra0 Signature Definition File)

Definition file for IDA to resolve functions in a IDB based on a in-memory dump.

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

A function declaration starts with a ***hexadecimal*** offset from the `ImageBase` followed by the **mangled function name** then lastly ending with the **function display name**.
All strings are represented with quotation marks around them. **"string"**.

> {hex_offset_address},"mangled_name","display_name"

Below is an example of the [UObject::execExecuteUbergraph](https://docs.unrealengine.com/4.27/en-US/API/Runtime/CoreUObject/UObject/UObject/ExecuteUbergraph/) function represented as a declaration. It is offset by `0x1000`
from the ImageBase of the PE Image.
```
0x00001000,"?execExecuteUbergraph@CoreUObject_Object@@SAXPEAVUObject@@AEAUFFrame@@QEAX@Z","Function CoreUObject.Object.ExecuteUbergraph"
``` 

---------------

