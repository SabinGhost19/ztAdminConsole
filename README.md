<div align="center">

# Zero-Trust Kubernetes Platform

**An end-to-end zero-trust control plane for Kubernetes** — provenance-verified workload
admission, supply-chain attestation, runtime drift sanctioning, blast-radius analysis,
and just-in-time access.

<br />

<p>
  <img src="https://img.shields.io/badge/Kubernetes-1.35%2B-326CE5?style=flat-square&logo=kubernetes&logoColor=white" alt="Kubernetes" />
  <img src="https://img.shields.io/badge/SLSA-Level%203-2563EB?style=flat-square&logo=slsa&logoColor=white" alt="SLSA" />
  <img src="https://img.shields.io/badge/cosign-keyless%20%2B%20Fulcio-FF6B6B?style=flat-square&logo=sigstore&logoColor=white" alt="Sigstore" />
  <img src="https://img.shields.io/badge/OPA-Gatekeeper-7B2BF9?style=flat-square&logo=openpolicyagent&logoColor=white" alt="OPA" />
  <img src="https://img.shields.io/badge/GUAC-v1.1.0-22C55E?style=flat-square" alt="GUAC" />
  <img src="https://img.shields.io/badge/Cilium-eBPF-F8C517?style=flat-square&logo=cilium&logoColor=black" alt="Cilium" />
  <img src="https://img.shields.io/badge/Falco-runtime-00B5AD?style=flat-square&logo=falco&logoColor=white" alt="Falco" />
  <img src="https://img.shields.io/badge/SPDX-SBOM-A8C3FF?style=flat-square&logo=spdx&logoColor=white" alt="SPDX" />
  <img src="https://img.shields.io/badge/OpenVEX-v0.2.0-9B9B9B?style=flat-square" alt="OpenVEX" />
</p>

<p>
  <img src="https://img.shields.io/badge/status-research%20%2F%20thesis-orange?style=flat-square" alt="status" />
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="license" />
  <img src="https://img.shields.io/badge/version-0.1.0-informational?style=flat-square" alt="version" />
</p>

</div>

<br />

---

## Overview

This repository contains an integrated set of Kubernetes-native components that establish a
**continuous, cryptographically attested identity for every workload**, from source code to
runtime. Each admitted workload is described by a `ZeroTrustApplication` Custom Resource and
must clear a sequence of provenance, supply-chain, and policy gates before its pods are
scheduled; once running, it is continuously evaluated against its own signed attestations and
any drift produces an automated sanction.

The platform is intentionally decomposed into single-purpose operators so each gate
(provenance verification, vulnerability scan, runtime policy, just-in-time access) can be
audited, replaced, or deployed independently.

<br />

## Status

This codebase is the implementation accompanying a Master's thesis on Kubernetes-native
zero-trust architectures. It is **research-grade**, not production-grade — identity is
bootstrapped against a local Keycloak instance, GUAC runs on the in-memory `keyvalue`
backend, and the platform targets a single cluster.

<br />

## License

Released under the **Apache License 2.0**. Third-party components are governed by their
respective licenses.

<br />

## Acknowledgements

Built on the open-source work of the **OpenSSF** (GUAC, in-toto, SLSA), **CNCF** (Falco,
OPA Gatekeeper, Cilium, FluxCD), **Sigstore** (cosign, Fulcio, Rekor), and the **Vue /
Vuetify / FastAPI** communities. Standards used verbatim: SPDX 2.x, OpenVEX v0.2.0, in-toto
attestation framework v1.0, DSSE v1.0.

<br />


