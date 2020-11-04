# HKDF.Standard

[.NET Standard](https://docs.microsoft.com/en-us/dotnet/standard/net-standard) implementation of [HKDF (HMAC-based Key Derivation Function)](https://tools.ietf.org/html/rfc5869).


## Features

* [High performance](#performance).
* [`Span<byte>` support](#spanbyte-methods).
* Can be [used with `ECDiffieHellman`](#using-hkdfstandard-with-ecdiffiehellman).
* [Easy migration](#migration-to-and-from-net-5s-hkdf) to and from the new [HKDF primitive introduced in .NET 5](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hkdf?view=net-5.0).
* [One-shot methods](#functionality) for extraction, expansion and key derivation.
* Supported hash functions: SHA-512, SHA-384, SHA-256, SHA-1 and MD5.
* Available in .NET 5, .NET Core, .NET Framework, Mono, Xamarin, UWP and Unity (see [platform support](#platform-support)).
* Compliant with [RFC 5869](https://tools.ietf.org/html/rfc5869).


## Getting Started

Install the NuGet package [`HKDF.Standard`](https://www.nuget.org/packages/HKDF.Standard/) from [nuget.org](https://www.nuget.org).

Use the methods of the `Hkdf` class (namespace `HkdfStandard`) to perform extraction, expansion and key derivation:

```csharp
using HkdfStandard;
...

// Input values:
byte[] inputKeyMaterial = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
int outputLength = 16;
byte[] info = Encoding.UTF8.GetBytes("My context-specific information.");
byte[] salt = new byte[32];
using (var rng = RandomNumberGenerator.Create())
    rng.GetBytes(salt);

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
* when the `Extract` stage can be skipped, please refer to the [RFC 5869 section 3.3](https://tools.ietf.org/html/rfc5869#section-3.3).
* how to use `salt` and when it can be omitted, see the [RFC 5869 section 3.1](https://tools.ietf.org/html/rfc5869#section-3.1).
* how to use `info` and when it can be omitted, see the [RFC 5869 section 3.2](https://tools.ietf.org/html/rfc5869#section-3.2).
* HKDF in general, please refer to the [original paper](https://eprint.iacr.org/2010/264.pdf).


## Functionality

### `byte[]` Methods

* ```csharp
  byte[] Extract(HashAlgorithmName hashAlgorithmName, byte[] ikm, byte[]? salt);
  ```
  Extracts a pseudorandom key from the input key material.
  
* ```csharp
  byte[] Expand(HashAlgorithmName hashAlgorithmName, byte[] prk, int outputLength, byte[]? info);
  ```
  Expands the pseudorandom key into an output keying material.

* ```csharp
  byte[] DeriveKey(HashAlgorithmName hashAlgorithmName, byte[] ikm, int outputLength, byte[]? salt, byte[]? info);
  ```
  Derives an output keying material from the input key material (performs extraction and extension) in one go.


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
  Derives an output keying material from the input key material (performs extraction and extension) in one go.


## Platform Support

[`byte[]` methods](#byte-methods) are available on the platforms that support [.NET Standard 1.6](https://docs.microsoft.com/en-us/dotnet/standard/net-standard#net-implementation-support):
* **.NET 5** and higher
* **.NET Core 1.0** and higher
* **.NET Framework 4.6.1** and higher
* **Mono 4.6** and higher
* **Xamarin.iOS 10.0** and higher
* **Xamarin.Mac 3.0** and higher
* **Xamarin.Android 7.0** and higher
* **UWP 10.0.16299** and higher
* **Unity 2018.1** and higher

[`Span<byte>` methods](#spanbyte-methods) are available on the platforms that support [.NET Standard 2.1](https://docs.microsoft.com/en-us/dotnet/standard/net-standard#net-implementation-support):
* **.NET 5** and higher
* **.NET Core 3.0** and higher
* **Mono 6.4** and higher
* **Xamarin.iOS 12.16** and higher
* **Xamarin.Mac 5.16** and higher
* **Xamarin.Android 10.0** and higher
* **UWP** - currently not supported (expected in the future)
* **Unity** - currently not supported (expected in the future)


## Performance

Based on the results of key derivation benchmark, **HKDF.Standard** is:
* **2.5 - 6.8 times faster** than **NSec**
* **1.3 - 5.4 times faster** than **BouncyCastle**
* **practically on par** with **.NET 5**, being about **4% - 18% slower**

![Chart: derivation of 128-bit key](/img/Chart_KeyDerivation_128bit.png)
![Chart: derivation of 4096-bit key](/img/Chart_KeyDerivation_4096bit.png)

*256-bit input key material, 256-bit salt, 256-bit context info*

*Windows 10 Pro x64, .NET 5.0-rc2, AMD Ryzen 7 Pro 1700X, single thread, [Portable.BouncyCastle v1.8.8](https://www.nuget.org/packages/Portable.BouncyCastle/1.8.8),
[NSec v20.2.0](https://www.nuget.org/packages/NSec.Cryptography/20.2.0)*


## Migration to and from **.NET 5**'s HKDF

TBD


## Using **HKDF.Standard** with `ECDiffieHellman`

HKDF is commonly used in conjunction with Diffie-Hellman (finite field or elliptic curve), where the Diffie-Hellman value (shared secret) is passed through HKDF to derive one or more shared keys.

Unfortunately, this scenario cannot be implemented straightforward with the [`ECDiffieHellman`](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdiffiehellman?view=netcore-3.1) class because it
[doesn't allow the export of raw shared secret](https://docs.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography#ecdh). However, there is a method [`ECDiffieHellman.DeriveKeyFromHmac`](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdiffiehellman.derivekeyfromhmac?view=netcore-3.1) that returns the value of shared secret that was passed through HMAC &mdash; this is the same transformation that the input key material undergoes when being passed through the HKDF's Extract stage. Therefore, the workaround is to skip the Extract stage of HKDF and substitute it with [`ECDiffieHellman`](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdiffiehellman?view=netcore-3.1)'s additional HMAC operation:

```csharp
byte[] salt = ...
byte[] info = ...
int outputLength = ...

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
