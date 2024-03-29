<a href="https://www.nuget.org/packages/HKDF.Standard/">
  <img src="https://img.shields.io/static/v1?label=%E2%AD%B3%20Get%20Package&message=NuGet&color=blue&style=plastic" height="28px" alt="Get NuGet Package">
</a>

<p>
  <a href="https://ci.appveyor.com/project/AndreiMilto/hkdf-standard">
    <img alt="AppVeyor Build" src="https://img.shields.io/appveyor/build/AndreiMilto/hkdf-standard?style=flat-square">
  </a>
  <a href="https://ci.appveyor.com/project/AndreiMilto/hkdf-standard/build/tests">
    <img alt="AppVeyor Tests" src="https://img.shields.io/appveyor/tests/AndreiMilto/hkdf-standard?style=flat-square">
  </a>
  <a href="https://github.com/andreimilto/HKDF.Standard/blob/main/LICENSE">
    <img alt="GitHub License" src="https://img.shields.io/github/license/andreimilto/HKDF.Standard?style=flat-square">
  </a>
</p>


# HKDF.Standard

[.NET Standard](https://docs.microsoft.com/en-us/dotnet/standard/net-standard) implementation of [HKDF (HMAC-based Key Derivation Function)](https://tools.ietf.org/html/rfc5869).


## Features

* [High performance](#performance).
* [`Span<byte>` support](#spanbyte-methods).
* Can be [used with `ECDiffieHellman`](#using-hkdfstandard-with-ecdiffiehellman).
* [Easy migration](#migration-to-and-from-nets-hkdf) to and from the new [HKDF primitive introduced in .NET&nbsp;5](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hkdf?view=net-5.0).
* [One-shot methods](#functionality) for extraction, expansion and key derivation.
* Supported hash functions: SHA-512, SHA-384, SHA-256, SHA-1 and MD5.
* Available in .NET&nbsp;5 and higher, .NET Core, .NET Framework, Mono, Blazor WebAssembly, Xamarin, UWP and Unity (see [platform support](#platform-support)).
* Compliant with [RFC&nbsp;5869](https://tools.ietf.org/html/rfc5869).


## Getting Started

Install the NuGet package [`HKDF.Standard`](https://www.nuget.org/packages/HKDF.Standard/).

Use the methods of the `Hkdf` class to perform extraction, expansion and key derivation:

```csharp
using HkdfStandard;
using System.Security.Cryptography;

// Input values:
byte[] inputKeyMaterial = ...;
byte[] salt = ...;
byte[] info = ...;
int outputLength = ...;

// Results:
byte[] pseudoRandomKey;
byte[] outputKeyMaterial;

// Perform the Extract stage of HKDF with or without the salt:
pseudoRandomKey = Hkdf.Extract(HashAlgorithmName.SHA256, inputKeyMaterial, salt);
pseudoRandomKey = Hkdf.Extract(HashAlgorithmName.SHA256, inputKeyMaterial);

// Perform the Expand stage of HKDF with or without the context information:
outputKeyMaterial = Hkdf.Expand(HashAlgorithmName.SHA256, pseudoRandomKey, outputLength, info);
outputKeyMaterial = Hkdf.Expand(HashAlgorithmName.SHA256, pseudoRandomKey, outputLength);

// Perform the entire HKDF cycle in one go (Extract + Expand)
// optionally using the salt and/or the context information:
outputKeyMaterial = Hkdf.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, outputLength, salt, info);
outputKeyMaterial = Hkdf.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, outputLength, salt);
outputKeyMaterial = Hkdf.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, outputLength, info: info);
outputKeyMaterial = Hkdf.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, outputLength);
```

For information about:
* whether the `Extract` stage can be skipped, please refer to the [RFC&nbsp;5869 section 3.3](https://tools.ietf.org/html/rfc5869#section-3.3);
* how to use `salt` and when it can be omitted, see the [RFC&nbsp;5869 section 3.1](https://tools.ietf.org/html/rfc5869#section-3.1);
* how to use `info` and when it can be omitted, see the [RFC&nbsp;5869 section 3.2](https://tools.ietf.org/html/rfc5869#section-3.2);
* HKDF in general, please refer to the [original paper](https://eprint.iacr.org/2010/264.pdf).


## Performance

Based on the results of key derivation benchmark, **HKDF.Standard** is:
* **2.7 - 7.4 times faster** than **NSec**
* **1.4 - 5.8 times faster** than **Bouncy Castle**
* **on par** with **.NET&nbsp;5** &ndash; perfomance difference does **not exceed &plusmn;10%**

![Chart: derivation of 128-bit key](/img/Chart_KeyDerivation_128bit.png)
![Chart: derivation of 4096-bit key](/img/Chart_KeyDerivation_4096bit.png)

*256-bit input key material, 256-bit salt, 256-bit context information*

*Windows 10 Pro x64, .NET&nbsp;5.0, AMD Ryzen 7 Pro 1700X, single thread, [Portable.BouncyCastle v1.9.0](https://www.nuget.org/packages/Portable.BouncyCastle/1.9.0),
[NSec v20.2.0](https://www.nuget.org/packages/NSec.Cryptography/20.2.0)*

*The benchmark source code is available at* [`src/HkdfStandard.Benchmark`](https://github.com/andreimilto/HKDF.Standard/tree/main/src/HkdfStandard.Benchmark)


## Migration to and from **.NET**'s HKDF

* [Methods](#functionality) in the **HKDF.Standard** library have the same signatures as in the **.NET**'s [`HKDF` class](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hkdf?view=net-5.0), which makes it is simple to migrate from one HKDF implementation to the other.
* Microsoft's implementation of HKDF will be available only in **.NET&nbsp;5** and onwards. Consider using **HKDF.Standard** if your project targets one of the older frameworks. If later you decide to upgrade the project to **.NET&nbsp;5** or higher, it will be relatively easy to swap the implementation of HKDF with the Microsoft's, if necessary.


## Using **HKDF.Standard** with `ECDiffieHellman`

HKDF is commonly used in conjunction with Diffie-Hellman (finite field or elliptic curve), where the Diffie-Hellman value (shared secret) is passed through HKDF to derive one or more shared keys.

Unfortunately, this scenario cannot be implemented straightforward with the [`ECDiffieHellman`](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdiffiehellman?view=netcore-3.1) class because it
[doesn't allow the export of raw shared secret](https://docs.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography#ecdh). However, there is a method [`ECDiffieHellman.DeriveKeyFromHmac`](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdiffiehellman.derivekeyfromhmac?view=netcore-3.1) that returns the value of shared secret that was passed through HMAC &mdash; this is the same transformation that the input key material undergoes when being passed through the HKDF's Extract stage. Therefore, the workaround is to skip the Extract stage of HKDF and substitute it with [`ECDiffieHellman`](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdiffiehellman?view=netcore-3.1)'s additional HMAC operation:

```csharp
using HkdfStandard;
using System.Security.Cryptography;

byte[] salt = ...;
byte[] info = ...;
int outputLength = ...;

// My instance of ECDH, contains a new randomly generated key pair:
using var myEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

// Other party's instance of ECDH, contains a new randomly generated key pair:
using var otherEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

// Derive the shared ECDH secret and pass it through HMAC along with the salt (as HMAC's message and key respectively).
// This is equivalent to deriving a raw shared secret and running it through the HKDF Extract, which gives a shared pseudorandom key:
byte[] pseudoRandomKey = myEcdh.DeriveKeyFromHmac(otherEcdh.PublicKey, HashAlgorithmName.SHA256, salt);

// Perform the Expand stage of HKDF as usual:
byte[] outputKeyMaterial = Hkdf.Expand(HashAlgorithmName.SHA256, pseudoRandomKey, outputLength, info);
```


## Functionality

### `byte[]` Methods

* ```csharp
  byte[] Extract(HashAlgorithmName hashAlgorithmName, byte[] ikm, byte[]? salt = null);
  ```
  Extracts a pseudorandom key from the input key material.
  
* ```csharp
  byte[] Expand(HashAlgorithmName hashAlgorithmName, byte[] prk, int outputLength, byte[]? info = null);
  ```
  Expands the pseudorandom key into an output keying material.

* ```csharp
  byte[] DeriveKey(HashAlgorithmName hashAlgorithmName, byte[] ikm, int outputLength, byte[]? salt = null, byte[]? info = null);
  ```
  Derives an output keying material from the input key material (performs extraction and expansion) in one go.


### `Span<byte>` Methods

* ```csharp
  int Extract(HashAlgorithmName hashAlgorithmName, ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, Span<byte> prk);
  ```
  Extracts a pseudorandom key from the input key material.

* ```csharp
  void Expand(HashAlgorithmName hashAlgorithmName, ReadOnlySpan<byte> prk, Span<byte> output, ReadOnlySpan<byte> info);
  ```
  Expands the pseudorandom key into an output keying material.

* ```csharp
  void DeriveKey(HashAlgorithmName hashAlgorithmName, ReadOnlySpan<byte> ikm, Span<byte> output, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info);
  ```
  Derives an output keying material from the input key material (performs extraction and expansion) in one go.


## Platform Support

[`byte[]` methods](#byte-methods) are available on the platforms that support [.NET Standard 1.3](https://learn.microsoft.com/en-us/dotnet/standard/net-standard?tabs=net-standard-1-3#net-implementation-support):
* **.NET&nbsp;5** and higher
* **.NET Core 1.0** and higher
* **.NET Framework 4.6** and higher
* **Mono 4.6** and higher
* **Blazor WebAssembly 3.2.0** and higher, except for [**5.x.x** and **6.x.x**](https://docs.microsoft.com/en-us/dotnet/core/compatibility/cryptography/5.0/cryptography-apis-not-supported-on-blazor-webassembly), support was resumed in [**7.0.0** (for SHA-family only, MD5 - unsupported)](https://github.com/dotnet/designs/blob/main/accepted/2021/blazor-wasm-crypto.md#net-7-plan)
* **Xamarin.iOS 10.0** and higher
* **Xamarin.Mac 3.0** and higher
* **Xamarin.Android 7.0** and higher
* **Unity 2018.1** and higher
* **UWP 10.0** and higher

[`Span<byte>` methods](#spanbyte-methods) are available on the platforms that support [.NET Standard 2.1](https://learn.microsoft.com/en-us/dotnet/standard/net-standard?tabs=net-standard-2-1#net-implementation-support):
* **.NET&nbsp;5** and higher
* **.NET Core 3.0** and higher
* **Mono 6.4** and higher
* **Blazor WebAssembly 3.2.0** and higher, except for [**5.x.x** and **6.x.x**](https://docs.microsoft.com/en-us/dotnet/core/compatibility/cryptography/5.0/cryptography-apis-not-supported-on-blazor-webassembly), support was resumed in [**7.0.0** (for SHA-family only, MD5 - unsupported)](https://github.com/dotnet/designs/blob/main/accepted/2021/blazor-wasm-crypto.md#net-7-plan)
* **Xamarin.iOS 12.16** and higher
* **Xamarin.Mac 5.16** and higher
* **Xamarin.Android 10.0** and higher
* **Unity 2021.2** and higher
* **UWP** - currently not supported (expected in the future)
