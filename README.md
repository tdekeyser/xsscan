# xsscan

Cross-site protection testing

## Usage

Example from JuiceShop.

```bash
rustbuster --url http://127.0.0.1:3000/FUZZ --wordlist /opt/wordlists/small.txt --filter-content-length 3748 > urls.rb
```

```bash
cat urls.rb | httpx -silent -o urls.httpx -store-response
```

This creates an `/output` folder containing the HTTP response calls. The `xsscan` parser uses from this format.

```bash
tom@MacBook:~/workspace/juice-shop# cat output/127.0.0.1\:3000/b98c1669edd59f28d84e36574be42877c4d67aa8.txt
http://127.0.0.1:3000/api

GET /api HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: Mozilla/5.0 (X11; Linux i686; rv:49.0) Gecko/20100101 Firefox/49.0
Accept-Charset: utf-8
Accept-Encoding: gzip


HTTP/1.1 500 Internal Server Error
Connection: close
Transfer-Encoding: chunked
Access-Control-Allow-Origin: *
Content-Type: text/html; charset=utf-8
Date: Sat, 15 Jun 2024 12:38:20 GMT
Feature-Policy: payment 'self'
Vary: Accept-Encoding
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Recruiting: /#/jobs

bc9
<html>
  <head>
    <meta charset='utf-8'>
    <title>Error: Unexpected path: /api</title>
    <style>* {
  margin: 0;
  padding: 0;
  outline: 0;
}
```

Or from Burp's export. The request and response objects are base64-encoded inside an XML document.
Use `https://github.com/RazrFalcon/roxmltree` crate to read from XML.

```xml
<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
<!ATTLIST items exportTime CDATA "">
<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>
<!ELEMENT time (#PCDATA)>
<!ELEMENT url (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
<!ELEMENT port (#PCDATA)>
<!ELEMENT protocol (#PCDATA)>
<!ELEMENT method (#PCDATA)>
<!ELEMENT path (#PCDATA)>
<!ELEMENT extension (#PCDATA)>
<!ELEMENT request (#PCDATA)>
<!ATTLIST request base64 (true|false) "false">
<!ELEMENT status (#PCDATA)>
<!ELEMENT responselength (#PCDATA)>
<!ELEMENT mimetype (#PCDATA)>
<!ELEMENT response (#PCDATA)>
<!ATTLIST response base64 (true|false) "false">
<!ELEMENT comment (#PCDATA)>
]>
<items burpVersion="2024.4.5" exportTime="Sun Jun 16 21:38:24 CEST 2024">
  <item>
    <time>Sun Jun 09 20:36:12 CEST 2024</time>
    <url><![CDATA[http://localhost:8090/login]]></url>
    <host ip="127.0.0.1">localhost</host>
    <port>8090</port>
    <protocol>http</protocol>
    <method><![CDATA[POST]]></method>
    <path><![CDATA[/login]]></path>
    <extension>null</extension>
    <request base64="true"><![CDATA[UE9TVCAvbG9naW4gSFRUUC8xLjENCkhvc3Q6IGxvY2FsaG9zdDo4MDkwDQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoTWFjaW50b3NoOyBJbnRlbCBNYWMgT1MgWCAxMC4xNTsgcnY6MTI2LjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvMTI2LjANCkFjY2VwdDogdGV4dC9odG1sLGFwcGxpY2F0aW9uL3hodG1sK3htbCxhcHBsaWNhdGlvbi94bWw7cT0wLjksaW1hZ2UvYXZpZixpbWFnZS93ZWJwLCovKjtxPTAuOA0KQWNjZXB0LUxhbmd1YWdlOiBlbi1HQixlbjtxPTAuNQ0KQWNjZXB0LUVuY29kaW5nOiBnemlwLCBkZWZsYXRlLCBicg0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNCkNvbnRlbnQtTGVuZ3RoOiAxMzQNCk9yaWdpbjogaHR0cDovL2xvY2FsaG9zdDo4MDkwDQpETlQ6IDENClNlYy1HUEM6IDENCkNvbm5lY3Rpb246IGtlZXAtYWxpdmUNClJlZmVyZXI6IGh0dHA6Ly9sb2NhbGhvc3Q6ODA5MC9sb2dpbj9lcnJvcg0KQ29va2llOiBKU0VTU0lPTklEPTEzMTIzRTAwMDE5QjU1NkIxRUFDQzgwRDhEMkZGNjREOyBYU1JGLVRPS0VOPWYzYTZjYWQ1LThiODEtNGYwNC1iODkwLTUxMzE2M2IyMDdkNg0KVXBncmFkZS1JbnNlY3VyZS1SZXF1ZXN0czogMQ0KUHJpb3JpdHk6IHU9MQ0KDQp1c2VybmFtZT11c2VyJnBhc3N3b3JkPXBhc3N3b3JkJl9jc3JmPWlGN1VFRFYtMUJpbmtvaHVpZWlHWjBkU0R5T05PVjlVRWptSGFQUklaZU5QRm8xcDdtMjFKbFlmc0MyS3F1cFd1TVd5QVhkbUlrRzFBRzk1SndpMFdjSjdCOUZfSWVsZg==]]></request>
    <status>302</status>
    <responselength>606</responselength>
    <mimetype></mimetype>
    <response base64="true"><![CDATA[SFRUUC8xLjEgMzAyIA0KVmFyeTogT3JpZ2luDQpWYXJ5OiBBY2Nlc3MtQ29udHJvbC1SZXF1ZXN0LU1ldGhvZA0KVmFyeTogQWNjZXNzLUNvbnRyb2wtUmVxdWVzdC1IZWFkZXJzDQpTZXQtQ29va2llOiBYU1JGLVRPS0VOPTsgTWF4LUFnZT0wOyBFeHBpcmVzPVRodSwgMDEgSmFuIDE5NzAgMDA6MDA6MTAgR01UOyBQYXRoPS87IFNhbWVTaXRlPVN0cmljdA0KU2V0LUNvb2tpZTogSlNFU1NJT05JRD03REQ4MTM3N0UzNTdCMTUzRTlGMENDOEYxRUFBRTA5MzsgUGF0aD0vOyBIdHRwT25seTsgU2FtZVNpdGU9U3RyaWN0DQpYLUNvbnRlbnQtVHlwZS1PcHRpb25zOiBub3NuaWZmDQpYLVhTUy1Qcm90ZWN0aW9uOiAwDQpDYWNoZS1Db250cm9sOiBuby1jYWNoZSwgbm8tc3RvcmUsIG1heC1hZ2U9MCwgbXVzdC1yZXZhbGlkYXRlDQpQcmFnbWE6IG5vLWNhY2hlDQpFeHBpcmVzOiAwDQpYLUZyYW1lLU9wdGlvbnM6IERFTlkNCkxvY2F0aW9uOiBodHRwOi8vbG9jYWxob3N0OjgwOTAvDQpDb250ZW50LUxlbmd0aDogMA0KRGF0ZTogU3VuLCAwOSBKdW4gMjAyNCAxODozNjoxMyBHTVQNCktlZXAtQWxpdmU6IHRpbWVvdXQ9NjANCkNvbm5lY3Rpb246IGtlZXAtYWxpdmUNCg0K]]></response>
    <comment></comment>
  </item>
</items>
```
