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

TBD


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

TBD


## Migration to and from **.NET 5**'s HKDF

TBD


## Using **HKDF.Standard** with `ECDiffieHellman`

TBD
