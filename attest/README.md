Remote attestation support. This family of crates provides support for Intel's EPID remote attestation in MobileCoin enclaves.

# Crates

| Name | Purpose |
| ---- | ------- |
| `ake` | Authenticated key exchange using the noise framework |
| `api` | gRPC Attestation APIs and protobufs |
| `core` | EPID remote attestation types and agnostic primitives |
| `enclave-api` | Serializeable structures for common enclave functions |
| `net` | IAS API Client |
| `trusted` | Traits used to monkey-patch enclave-only functionality onto `core` types |
| `untrusted` | Traits used to monkey-patch untrusted-only functionality onto `core` types |

# Enclave Concepts and Jargon

Intel's enclaves and EPID-based remote attestation is a very complex subject (there are many layers and protocols and ways to stitch things together), so the first thing to get out of the way is understanding the basics and the jargon. We'll use the MobileCoin validator (the "consensus service") for this example.

## Trusted Computing Base

***Trusted Computing Base*** (TCB) is pure jargon. It describes the much more pragmatic "all the things you need to believe haven't been pwned (things you trust) in order to believe the system hasn't been pwned (can be trusted)." It naturally follows that one great way to improve security is to reduce the number of things that you have to believe in to be however secure you need to be.

To show how a TCB comes into being, lets take your typical "take a JSON document from HTTP, process it, return more JSON" web application, for example, isn't going to be passing raw network card buffers in RAM around from function to function. Instead you're going to have the OS deserialize the ethernet frame (and IP packet, and TCP segment), a TLS library decrypt and verify the encrypted data, a web server deserialize the HTTP request, and a framework/parser deserialize the JSON into an object, all before your application ever sees anything.

And ultimately, you're going to create a TCB simply by following good development practices. Stabilizing a procedure and including it in a library that is shared in multiple places makes that library part of your TCB. You've established an ad-hoc trust in that procedure because you have used it and you "know" it works, you have unit tests around it to ensure you exercise edge cases, etc.

All that testing and ad-hoc trust aside, there's an even deeper analogue to be learned. Ultimately, you want to be in the business of squashing *classes* of security bugs. It's all fine and good to fix a SQL injection bug or a string misquote, but what you really want to do is make your code mis-use resistant, so SQL injection or string misquoting bugs are simply impossible to write.

Another way to get to the same place, which seems much weaker but actually has a richer *history* is to make bugs like those *not security impacting*. That is, OK, fine, so there's a SQL injection. If you are talking to a database with read-only credentials with restricted query times, that's not great, but it's also not that bad.

Any networked system already does this. We want to use encrypted communications (i.e. TLS) for everything, because it means a hostile network doesn't have the ability to compromise your system's *security* (note: this is different from your system's *availability*). In a system that contained no private information, you would still want to use authenticated messages to ensure that a bad actor on your network couldn't eavesdrop (if *privacy* is a part of your *security*), or tamper with your packets (which definitely is part of your system's security ;-)).

To put this another way, in the usual case your TCB is your computer, but your *network* isn't. A networked system shouldn't be *designed* to require your WiFi (or router) be secure. The TCB should end at the antenna (or network) port. The TCB may fail, due to software bugs, but that's a failure of implementation, not of design. A web browser (for example) should either be able to contact a secure website properly, where you trust yourself and the website, or it shouldn't. It shouldn't ever connect *insecurely* in that case, and if it does, that's a break, a hack, or a vulnerability.

## Hardware Enclaves

The TCB approach is also used by general purpose hardware enclaves. In the networked scenario, the complete host is considered to be part of the TCB, including the operating system, drivers, libraries, etc. One way to think about a hardware enclave is to think about moving that "trusted"/"untrusted" barrier from the port where the network cable is plugged in, and take it deeper into the computer. Moving the parts of a system that are critical to its security onto hardware designed to keep it private, and then treating everything else (operating system, wireless driver, etc.) as "untrusted".

By making the "trusted" code authenticate any data coming into it, using techniques like those used previously to authenticate data coming in from the network, we can effectively declare anything outside the trusted hardware to be "untrusted"---that is, not something we need to trust to believe the system is secure. This is effectively shrinking the size of the TCB.

## Trusted vs. Untrusted

So how do you do this? Let's start by splitting application code into two pieces: the normal OS application, which you execute like any other process from a shell or launcher; and the enclave, which is a shared library which has one or more functions which can be called from outside the enclave (it is very similar to a `dlopen()`-style plugin library, and when built in "simulation" mode, that's literally what the SGX SDK does).

Intel calls the normal application the ***untrusted*** code, and the enclave library the ***trusted*** code, and in the MobileCoin universe these are literally separate code compiled from independent `cargo build` runs. Additionally, only specifically marked functions in untrusted can be called by trusted code, and visa-versa. This means trusted code cannot perform any IO directly, it can only ask untrusted to act on its behalf.

OK, now we have our code split between outside-the-enclave (untrusted) and inside-the-enclave (trusted). As parenthetically noted above, Intel does have a "simulated" enclave, where they just take the "trusted" code and turn it into a plugin module for your application---how can you tell the difference between a "simulated" enclave and a real one if they're running the same code?

## Attestation

This "telling the difference" is handled by attestation, which is a multi-layered technique using building blocks from lower levels.

1. Local attestation (most of the actual work of attestation is done locally, on the host)
1. Quoting enclaves (by passing data to the quoting enclave)
1. IAS API call (a REST API call to IAS to sign off on the local attestation data)
1. Verification (verifying the result from IAS is what we want)

### Between Enclaves on the same CPU

> Don't skip this section just because you're interested in remote attestation. It's a core building block if you want to understand how the system works.

The first thing to know about attestation is that it begins with Alice The Enclave asking the CPU for it's own `EREPORT`. The CPU will fill in a data structure containing information about Alice.

The contents of Alice's `EREPORT` can be used to construct a `TARGETINFO` data structure, which is given to Bob The Enclave. Bob uses Alice's targetting information when he calls `EREPORT` from within his context, and he CPU fills in the report as before, and adds an authentication code so Alice can verify Bob's report is valid.

Bob sends his `EREPORT` (with authentication code) to Alice, and she verifies the code using information available only to her and the CPU, and she can trust the report that she got from Bob is actually from Bob. That is, she's authenticated the report, and knows there was a Bob enclave out there, and she knows she has a report for it.

#### Eve

The important bit of extra information here is that Bob and Alice can't talk to each other directly. They can each talk to the CPU, independently, but they must pass all messages through Eve (the "untrusted" application code). By using information only the CPU has to authenticate the report messages, Alice and Bob can communicate through an untrusted intermediary, just like hosts can communicate through an untrusted network.

### Quoting Enclaves

For remote attestation purposes, Alice is *Intel's Quoting Enclave* (QE), and Bob is the *MobileCoin Enclave*. Alice provides her target info via `aesmd` and the SGX SDK to the MobileCoin application, which then gives it to it's own enclave. Bob uses `EREPORT` to get his report, which he gives back to the QE.

The QE has (on startup) established a secure connection to Intel and gotten itself "provisioned" with a key it can use for communicating back to IAS. When it gets the report from Bob, the QE first authenticates the report (as Alice did above), then fills in extra details about the host: it's own version and details, the BIOS version, some security-relevant BIOS configuration details (e.g. "is hyperthreading turned on" or "is the GPU turned on", etc.), etc. and creates what's called a `Quote`.

In addition to the contents of Bob's `Quote` is the contents of Bob's `EREPORT`, details about the QE and the host, and additional information which is encrypted between the QE to Intel.

### IAS

Once the MobileCoin application has gotten a `Quote` back from the QE, it encodes it into a JSON document and sends it to the *Intel Attestation Service* (IAS). IAS, for it's part, looks at the quote and tries to verify everything: is the QE up-to-date? Does the CPU have any known vulnerabilities? IAS, then, is verifying that there aren't any known problems with the TCB---that you can actually T the CB.

It puts all that (alongside "update info" if something is not up-to-date) into a report, and signs the bytes using an RSA key, then provides a standard certificate chain.

### Verification

The software the MobileCoin enclave is attesting to (the client) must now verify the report provided by IAS. In particular, it must authenticate the message was signed by a key it trusts. Doing so is fairly straightforward RSA signature checking, where the verifier is given an X509 certificate chain and signature alongside the authenticate that the chain leads back to a trust anchor the application expects.

Once it's authenticated a report as coming from IAS, the verifier can parse the JSON string and use the contents of the report to determine whether or not to trust the enclave. The status returned by Intel will indicate broadly if anything is wrong, and the verifiers can do things like checking the MRENCLAVE values, ensuring the enclave isn't running in debug mode, etc.

## Authentication

At this point, it's probably taking a step back from the details and recalling that what we're trying to do is build a way to have a client be able to trust (and potentially hide) messages into the enclave. That is, in order to ensure the TCB is just the client and the enclave, both the client and enclave need to cryptographically (that is, using math to ensure forgery would be impractical for a given time-frame) authenticate messages to/from each other.

The easeiest way to build an authenticated channel is to use a key exchange protocol. What this means is, Alice and Bob (from above) would take advantage of the fact the `EREPORT` structure contains 64 bytes of user-specified data. That is, when the Alice Enclave calls `EREPORT`, they provide the bytes of their public key as user-specified data. That data is then baked into the `EREPORT` structure which they get back from the CPU (and therefore, cryptographically authenticated by the CPU as coming from Alice).

Similarly, Bob puts his own public key into his `EREPORT` call as user-data, and so the report he gets back contains his public key, cryptographically authenticated by the CPU. Alice and Bob then exchange the reports in the usual "local attestation" way described above.

### Key Exchange

At this point, Alice and Bob both know the other enclave exists, *and* (thanks to the user data) knows a public key associated with the other enclave. At this point, Alice will combine her private key with Bob's public key in order to create a new number. Bob, for his part, will combine his private key with Alic's public key to create a new number, and thanks to the math used, the "new number" they both come up with will be the same.

Because both Alice and Bob are using an asymmetric cryptosystem (where you can't figure out what private key is behind a public key), and neither one ever sends their private keys, the "new number" they come up with is a "shared secret". The "Eve" passing messages back and forth doesn't have either Alice's or Bob's private keys to multiply with the public key.

Bob and Alice now have a secret which each of them knows, but Eve cannot know, which means they can use this shared secret to create their own message authentication codes, between each other, without relying on special CPU instructions like `EREPORT`. When Bob wants to send a message to Alice, he can compute the authentication code for it (the MAC), and send both of them to Alice. Alice, for her part, will independently compute the MAC based on the message, and then compare her MAC with the one Bob sent over. If they match, then she knows that Eve didn't change the message.

In other words, Alice can now authenticate messages from Bob, and visa-versa. If Alice and Bob also want to *hide* their messages from Eve, then Bob would first encrypt his message, then compute the MAC of the encrypted text. It's usually easier to both encrypt and MAC, because there is a special kind of encryption "Authenticated Encryption" that combines encryption and authentication codes into a single package.
