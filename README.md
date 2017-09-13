# socksmon
Monitor arbitrary TCP traffic using your HTTP interception proxy of choice

## What is socksmon?
socksmon is a SOCKSv4 server based on Twisted, that tunnels incoming
TCP traffic through an HTTP proxy. socksmon does this by starting an
internal webserver on port 2357, posts the traffic to using the man in
the middle proxy for editing it and then it forward it to the
destination.

socksmon has preliminary support for SSL interception, meaning
arbitrary ssl encrypted tcp traffic can be analyzed using your
interception proxy of choice.

## How do I use it?
First you need to create a certificate you would like to use with
socksmon in PEM format and put it under `/tmp/server.pem`. If you use
BURP, export the private key and the certificate and then concatenate
them together. (e.g. `cat server.crt server.key > /tmp/server.pem`)

Second, start your interception proxy with port 8080 on localhost.

Third, send SOCKSv4 traffic to `yourip:9050`. Be sure to use SOCKSv4,
SOCKSv5 won't work due to the Twisted SOCKS server implementation. For
redirecting traffic I recommend Proxifier[1] under Windows and
Redsocks[2] or Proxychains[3] under Linux.

## Todo

Patches / PRs are welcome.

### Better SSL certificate generation
Currently no certificates are generated for specific endpoints,
e.g. the specified key is used directly for all sites. This is
problematic with clients that check the common name or the revocation
list in the certificate.

### Upstream proxy support
Upstream proxies should be supported for all traffic. HTTP should get
special treatment, so proxies that disallow CONNECT can be used as
well.

### Command line options
Command line options should be used to set the proxy port,
certificates and webserver ports.

### Modular traffic modification framework
Implement a modular framework that allows processing of TCP
traffic. It should be easy to implement decoders and re-encoders for
different protocols and formats (e.g. deserialize Java object to XML).

[1]: https://www.proxifier.com/
[2]: https://github.com/darkk/redsocks
[3]: http://proxychains.sourceforge.net/
