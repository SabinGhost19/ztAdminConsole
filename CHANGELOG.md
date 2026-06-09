## [1.18.2](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.18.1...v1.18.2) (2026-06-09)


### Bug Fixes

* **dashboard:** improve jit access frotnned ([3c3c2fa](https://github.com/SabinGhost19/ztAdminConsole/commit/3c3c2faf42ac52ea8785c89096b00ba5e5a749d8))

## [1.18.1](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.18.0...v1.18.1) (2026-06-04)


### Bug Fixes

* **dashboard:** factual audit-alert cause + fix drift header overlap ([728671f](https://github.com/SabinGhost19/ztAdminConsole/commit/728671fbd1392114b267ad82b127ac49f5f94f85))

# [1.18.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.17.1...v1.18.0) (2026-06-03)


### Features

* **dashboard,operator:** surface Trivy CVE detail + fix Talon namespace ([3a25fd8](https://github.com/SabinGhost19/ztAdminConsole/commit/3a25fd81e7d110338dbdf18f70820d4e1f609b0e))

## [1.17.1](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.17.0...v1.17.1) (2026-06-03)


### Bug Fixes

* **manifests:** enforce securityScanPolicy on payments + analytics SCAs ([901d170](https://github.com/SabinGhost19/ztAdminConsole/commit/901d1707dc1af86cb0cf4ef704b99e8f9c17bf21))

# [1.17.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.16.0...v1.17.0) (2026-06-03)


### Features

* **supply-chain:** add OSS Snyk-style security-scan attestation flow ([3f69b55](https://github.com/SabinGhost19/ztAdminConsole/commit/3f69b556fccbc41df1b9b8bd5fa08b3023e9e8d5))

# [1.16.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.15.0...v1.16.0) (2026-05-26)


### Features

* **ui:** show per-stage durations in Reconcile Pipeline ([5dea48f](https://github.com/SabinGhost19/ztAdminConsole/commit/5dea48f908a6077cc5cd7e17d8e4f6484de36440))

# [1.15.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.14.2...v1.15.0) (2026-05-26)


### Features

* graceful Falco/Talon missing detection across operator → backend → UI ([4ed1d5f](https://github.com/SabinGhost19/ztAdminConsole/commit/4ed1d5fd47e530f842a83439eea336dc4868dad7))

## [1.14.2](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.14.1...v1.14.2) (2026-05-25)


### Bug Fixes

* **sca-crd,ui:** admit new policy fields + handle ZTA deletion live ([9296bde](https://github.com/SabinGhost19/ztAdminConsole/commit/9296bde57b5d2f8df0edcf77930bbf468267568b))

## [1.14.1](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.14.0...v1.14.1) (2026-05-25)


### Bug Fixes

* **ui:** coerce v-for index to number in ReconcileFlow.vue ([3f2e947](https://github.com/SabinGhost19/ztAdminConsole/commit/3f2e94740aa7f668f17217a9a0ea675a2789100c))

# [1.14.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.13.1...v1.14.0) (2026-05-25)


### Features

* structured error taxonomy across operator, backend, SSE and UI ([0635747](https://github.com/SabinGhost19/ztAdminConsole/commit/063574760b69825930a47c96ca97649db0933e66))

## [1.13.1](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.13.0...v1.13.1) (2026-05-23)


### Bug Fixes

* **secrets,networking,identity:** unblock ESO chain + add FreeIPA pod ([3247d41](https://github.com/SabinGhost19/ztAdminConsole/commit/3247d41bbadc21738b5a271eb5c10f96acf3e341))

# [1.13.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.12.0...v1.13.0) (2026-05-21)


### Features

* **jit:** instant approve UI, multi-select blocked users, live sessions ([0cbcfd4](https://github.com/SabinGhost19/ztAdminConsole/commit/0cbcfd42ce12681e2d4489e378a1b2cdf251809e))

# [1.12.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.11.0...v1.12.0) (2026-05-21)


### Features

* **jit:** manual approval workflow + real-time SSE stream ([591573e](https://github.com/SabinGhost19/ztAdminConsole/commit/591573ea858f9c8f852d06b2f90762870adec6eb))

# [1.11.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.10.5...v1.11.0) (2026-05-21)


### Features

* **rbac:** allow developer role limited read on JIT sessions/analytics/policies ([b26f6bc](https://github.com/SabinGhost19/ztAdminConsole/commit/b26f6bcc3b5a737d611148ec7ba8c42af5f07aec))

## [1.10.5](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.10.4...v1.10.5) (2026-05-21)


### Bug Fixes

* **dashboard:** accept GHSA and debian-cve identifiers in blast-radius route ([bc6df6e](https://github.com/SabinGhost19/ztAdminConsole/commit/bc6df6ee29bea6afd651f2737c08384f18ea89ad))

## [1.10.4](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.10.3...v1.10.4) (2026-05-21)


### Bug Fixes

* **dashboard:** correct GUAC blast-radius query and accept GHSA / debian-cve IDs ([93144ca](https://github.com/SabinGhost19/ztAdminConsole/commit/93144ca27de4d109b2ba3bf00963de00ca5424b4))

## [1.10.3](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.10.2...v1.10.3) (2026-05-20)


### Bug Fixes

* **guac:** align default service URLs with the official guacsec/guac chart ([daf2cd0](https://github.com/SabinGhost19/ztAdminConsole/commit/daf2cd0a07f59d49636bfd7dfad97e327147a852))

## [1.10.2](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.10.1...v1.10.2) (2026-05-20)


### Bug Fixes

* **frontend:** return 404 for missing Vite assets instead of index.html ([87b8077](https://github.com/SabinGhost19/ztAdminConsole/commit/87b8077bb763621aecba0933fc17f53d360cc195))

## [1.10.1](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.10.0...v1.10.1) (2026-05-20)


### Bug Fixes

* frontend build ([88d4a23](https://github.com/SabinGhost19/ztAdminConsole/commit/88d4a23ff479c92bbacc4929f4cbbab9434ce5ad))

# [1.10.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.9.4...v1.10.0) (2026-05-20)


### Features

* **supply-chain:** RFC 6962 Merkle + Audit-mode + webhook + CEL + VEX + KubeArmor + GUAC ([2f1b7f6](https://github.com/SabinGhost19/ztAdminConsole/commit/2f1b7f6ea4283ad4913678922be34d7cbcc03e5f))

## [1.9.4](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.9.3...v1.9.4) (2026-05-18)


### Bug Fixes

* **breakglass:** requester fallback, RBAC NPP, visible errors ([138b24e](https://github.com/SabinGhost19/ztAdminConsole/commit/138b24edd6a47419f991c84208d61254b2c4792d))

## [1.9.3](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.9.2...v1.9.3) (2026-05-12)


### Bug Fixes

* **jit:** enforce 10-min token minimum, namespace dropdown, instant UI refresh ([32061fa](https://github.com/SabinGhost19/ztAdminConsole/commit/32061fa43ba7d68a4f93c304e719b8dd5bb9ed0c))

## [1.9.2](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.9.1...v1.9.2) (2026-05-12)


### Bug Fixes

* **integrity:** robust Trivy severity hint in Alert sub-task ([6670103](https://github.com/SabinGhost19/ztAdminConsole/commit/6670103f51ac012821da0452995d24605ded84f9))

## [1.9.1](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.9.0...v1.9.1) (2026-05-12)


### Bug Fixes

* **backend:** wire breakglass /policies to the async k8s client ([cbc9b50](https://github.com/SabinGhost19/ztAdminConsole/commit/cbc9b50a831649b33d61e7a2c12dc596147dd313))

# [1.9.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.8.1...v1.9.0) (2026-05-12)


### Features

* **ui:** horizontal CI/CD pipeline + granular sub-task forensics ([d2da58f](https://github.com/SabinGhost19/ztAdminConsole/commit/d2da58fcd2e7e12f5a8c311b3acefdfa65b55cbc))

## [1.8.1](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.8.0...v1.8.1) (2026-05-11)


### Bug Fixes

* RBAC guards, JIT token flow, ZTA polling stability and operator namespace alignment ([78b3059](https://github.com/SabinGhost19/ztAdminConsole/commit/78b3059fa4aa3c435473e0c5e338f93595f1d785))

# [1.8.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.7.0...v1.8.0) (2026-05-05)


### Features

* **zta-rbac-login:** login rbac using keycloak:v3 ([1b37a5c](https://github.com/SabinGhost19/ztAdminConsole/commit/1b37a5cd05c552eb5f99df060ff232f849da4066))

# [1.7.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.6.0...v1.7.0) (2026-05-05)


### Features

* **zta-rbac-login:** login rbac using keycloak:v2 ([430a2f5](https://github.com/SabinGhost19/ztAdminConsole/commit/430a2f54309a9d32f89973a78bcd490a02020f6a))

# [1.6.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.5.0...v1.6.0) (2026-05-05)


### Features

* **zta-rbac-login:** login rbac using keycloak ([bf0b012](https://github.com/SabinGhost19/ztAdminConsole/commit/bf0b0124591adf09023fb2c980e61c93e0218c54))

# [1.5.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.4.0...v1.5.0) (2026-05-04)


### Features

* **zta-helm:** expose ingress/JIT auth defaults in values and deployment env ([b2b4914](https://github.com/SabinGhost19/ztAdminConsole/commit/b2b49149870380b12f8d8ebbf3f4f0ce5f832e37))

# [1.4.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.3.0...v1.4.0) (2026-04-21)


### Features

* **iam:** integrate dynamic IAM web app JIT portal and identity ([cbfca8c](https://github.com/SabinGhost19/ztAdminConsole/commit/cbfca8c63bf66533338c8a8e526db56194a09d64))

# [1.3.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.2.3...v1.3.0) (2026-04-21)


### Features

* **iam:** integrate dynamic IAM web app JIT portal and identity matrix ([6eb3c4f](https://github.com/SabinGhost19/ztAdminConsole/commit/6eb3c4f98642de7abaa87ae7b763c376fdf8b887))

## [1.2.3](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.2.2...v1.2.3) (2026-04-18)


### Bug Fixes

* ui updated for merkel tree arangement ([aba6d56](https://github.com/SabinGhost19/ztAdminConsole/commit/aba6d5697f378d70cad6110fc89c44bc5ab408eb))

## [1.2.2](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.2.1...v1.2.2) (2026-04-18)


### Bug Fixes

* reconcile zta resource ([a2a35cf](https://github.com/SabinGhost19/ztAdminConsole/commit/a2a35cf4cf7d8180e5aec4ab82447145a69cad52))

## [1.2.1](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.2.0...v1.2.1) (2026-04-18)


### Bug Fixes

* reconcile ui ([d01c0a5](https://github.com/SabinGhost19/ztAdminConsole/commit/d01c0a58c54f03f21cd75a00804ab2da348f2f87))

# [1.2.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.1.5...v1.2.0) (2026-04-18)


### Features

* actions vizualizer for reconcile ([536cf06](https://github.com/SabinGhost19/ztAdminConsole/commit/536cf0666c69f8f63420a824ec8f77795bffe29f))

## [1.1.5](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.1.4...v1.1.5) (2026-04-17)


### Bug Fixes

* **zta:** duplicated tracing logs ([efd66a8](https://github.com/SabinGhost19/ztAdminConsole/commit/efd66a810b7c7097864522030059ffe28d74e83d))

## [1.1.4](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.1.3...v1.1.4) (2026-04-17)


### Bug Fixes

* **zta:** anifest spec hash mismatch ([525f4d2](https://github.com/SabinGhost19/ztAdminConsole/commit/525f4d2dec2028bf8216a954252d6f72d3f6b236))

## [1.1.3](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.1.2...v1.1.3) (2026-04-16)


### Bug Fixes

* disable streaming ([06fec32](https://github.com/SabinGhost19/ztAdminConsole/commit/06fec32eedc41f00fe12f8edcd3b5e17a068b244))

## [1.1.2](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.1.1...v1.1.2) (2026-04-16)


### Bug Fixes

* fsnotify watcher: too many open files ([6fd1c0c](https://github.com/SabinGhost19/ztAdminConsole/commit/6fd1c0c12a9b974c9226da7ad7eee24cee187114))

## [1.1.1](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.1.0...v1.1.1) (2026-04-16)


### Bug Fixes

* fsnotify watcher: too many open files ([152127b](https://github.com/SabinGhost19/ztAdminConsole/commit/152127bb41ebd3b8d16333a1ebd3c7b341518abe))

# [1.1.0](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.0.1...v1.1.0) (2026-04-16)


### Features

* provenance enforcer added ([13be9ae](https://github.com/SabinGhost19/ztAdminConsole/commit/13be9aedd4f694291ad9bb19d0f42ee77def5610))

## [1.0.1](https://github.com/SabinGhost19/ztAdminConsole/compare/v1.0.0...v1.0.1) (2026-04-06)


### Bug Fixes

* update opnapi version for jit access request ([724fd5a](https://github.com/SabinGhost19/ztAdminConsole/commit/724fd5a6a0a6da772fe2670916e36bfa3dbd833c))

# 1.0.0 (2026-04-06)


### Features

* added robust error handling ([f15b85f](https://github.com/SabinGhost19/ztAdminConsole/commit/f15b85f043a7cfe394060833edf8a19747d53fa3))
