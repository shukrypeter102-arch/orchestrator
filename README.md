# Orchestrator

A framework for declarative, predictable, and centralized resource
management written in Rust, using a reactor model.

## Overview

Orchestrator is a declarative resource management framework that provides
a centralized, predictable approach to managing system resources. Built
on a reactor model architecture, it allows you to define desired resource
states declaratively, and with predictable semantics according to system
state.

### Key Features

- **Declarative Configuration**: Define policies with clean
  encaspulation between input triggers, policy values, and actions on
  those values.
- **Reactor Model**: Event-driven architecture provides hermetic
  and predictable semantics and policy execution.
- **Centralized Management**: All system-wide resource management
  is centralized, providing a single point of control and visibility.
- **Written in Rust**: Memory-safe, performant, and reliable

## Branding & Contact

This repository's documentation has been updated to reflect branding for PMCosmetics.

- Display name: `PMCosmetics`
- Recommended Package / Bundle ID for examples: `com.pmcosmetics`
- Recommended artifact short name: `pmcosmetics`

Support / Contact

For questions about PMCosmetics distributions and publishing, contact via WhatsApp: https://wa.me/c/201055655649

## Building and Installing

### Build Requirements

> **Note**: This project does not yet support building outside of Meta's
> internal infrastructure. Open-source build support is currently being
> developed.

### Building at Meta

For Meta employees with access to the internal build system:

```bash
# Build the orchestrator service
buck2 build //vendor/meta/services/orchestrator:orchestrator

# Run tests
buck2 test //vendor/meta/services/orchestrator:orchestrator_test
```

### Future Open Source Support

We are actively working to enable building Orchestrator outside of
Meta's infrastructure. This will include:

- Standalone build system configuration (Cargo-based)
- Public dependency management
- External documentation and examples

## License

This project is licensed under the **Apache License 2.0**. See the
[LICENSE](LICENSE) file for details.

### Special Licensing Notice

**BPF Source Files**: The BPF source files in this project are
dual-licensed under:
- **GPL v2.0** (GNU General Public License v2.0)
- **BSD 2-Clause** License

This dual-licensing approach for BPF files ensures compatibility with the
Linux kernel's licensing requirements while providing flexibility for use
in other contexts.

## Documentation

We're working on adding additional documentation, including an overview of the
framework, architecture, and examples. In the meantime, please refer to the
documentation in the source code and the unit tests for more information.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md)
for guidelines on how to contribute to this project.

## Support

For issues and questions, please file GitHub issues.

## Project Status

Orchestrator is under active development. The framework is currently used
internally at Meta and is being prepared for open-source release with
external build support.
