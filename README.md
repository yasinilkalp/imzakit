# ImzaKit

ImzaKit is an Apache-2.0 licensed .NET toolkit for provider-independent electronic signature workflows. The current prerelease focuses on CMS and PAdES preparation/completion, PKCS#11 provider abstractions, signature validation, local-agent security primitives, API operation semantics, and dependency-injection integration.

> **Prerelease:** The API may change before the stable `1.0.0` release. Validate legal, regulatory, hardware, certificate-policy, and interoperability requirements before production use.

## Modules in the package

NuGet distributes every production module below through the single `ImzaKit` package.

| Package | Purpose |
| --- | --- |
| `ImzaKit.Core` | Provider-independent signing and cryptography contracts |
| `ImzaKit.Cryptography` | Digest calculation and algorithm models |
| `ImzaKit.Cms` | CMS signed-attributes preparation and completion |
| `ImzaKit.PAdES` | PDF/PAdES preflight, preparation, completion, and policy checks |
| `ImzaKit.Pkcs11` | PKCS#11 provider contracts and signing orchestration |
| `ImzaKit.Verify` | CMS/PAdES validation reports |
| `ImzaKit.Agent` | Loopback-agent configuration and ticket security primitives |
| `ImzaKit.Api` | Idempotent signature-operation domain services and API problem mapping |
| `ImzaKit.DependencyInjection` | DI registration and in-process orchestration |

Install the toolkit with one package reference:

```shell
dotnet add package ImzaKit --version 1.0.0-alpha.2
```

The package targets `.NET 10`. Source, requirements, technical evidence, and implementation status are maintained in this repository.

## Security

Do not log PINs, private keys, raw authorization tickets, or unmasked token serial numbers. Keep private-key operations inside the intended cryptographic provider or hardware token, use deployment-specific trust policy, and test with representative PDF readers and PKCS#11 devices.

## License

Copyright 2026 ImzaKit contributors. Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution information.
