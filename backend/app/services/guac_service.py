"""GUAC GraphQL proxy — Blast Radius queries for the UI.

The frontend never talks to GUAC directly: this would expose the internal
GraphQL endpoint to the browser and make CORS/auth a nightmare. Instead,
the backend acts as a thin proxy: receives a CVE or package query, asks
GUAC, and returns a normalized JSON tree shape that the Vue Tree View can
render directly.

This module assumes GUAC runs inside the cluster and is reachable from the
backend pod at the address configured via the `GUAC_GRAPHQL_URL` env var
(default: http://guac-graphql-server.guac.svc.cluster.local:8080/query).
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("zero_trust_guac_service")


def _endpoint() -> str:
    # Default tracks the official `guacsec/guac` Helm chart Service names:
    #   Service/graphql-server  :8080  /query
    # Override per-cluster with GUAC_GRAPHQL_URL on the backend deployment.
    return os.environ.get(
        "GUAC_GRAPHQL_URL",
        "http://graphql-server.guac.svc.cluster.local:8080/query",
    ).strip()


async def is_healthy() -> dict[str, Any]:
    """Returns a structured health probe for the UI to disable / enable
    the Blast Radius feature when GUAC is unreachable.
    """
    url = _endpoint()
    if not url:
        return {"reachable": False, "endpoint": "", "reason": "GUAC_GRAPHQL_URL unset"}

    probe = {"query": "{ __typename }"}
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(url, json=probe)
            return {
                "reachable": resp.status_code < 400,
                "endpoint": url,
                "statusCode": resp.status_code,
            }
    except Exception as exc:
        return {"reachable": False, "endpoint": url, "reason": str(exc)[:200]}


async def list_known_vulnerabilities() -> dict[str, Any]:
    """Enumerate every vulnerability ID that has at least one CertifyVuln
    link in the graph, with the count of distinct packages affected.

    Powers the "pick a vulnerability" dropdown in the UI — the auditor sees
    only IDs that will actually return data, not the entire OSV catalog.

    Filters out OSV's `type=novuln` "clean scan" markers (those record that
    a package was scanned and had NO vulnerability — we don't want them
    polluting the picker).
    """
    url = _endpoint()
    if not url:
        return {"vulnerabilities": [], "guacUnavailable": True}

    query = """
    {
      CertifyVuln(certifyVulnSpec: {}) {
        vulnerability { type vulnerabilityIDs { vulnerabilityID } }
        package {
          type
          namespaces { namespace names { name versions { version } } }
        }
      }
    }
    """
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, json={"query": query})
        if resp.status_code >= 400:
            return {"vulnerabilities": [], "error": f"GUAC HTTP {resp.status_code}"}
        body = resp.json()
        if body.get("errors"):
            return {
                "vulnerabilities": [],
                "error": str(body["errors"][0].get("message", "GUAC GraphQL error"))[:200],
            }
    except Exception as exc:
        logger.exception(
            "GUAC vulnerability list query failed",
            extra={"details": {"error": str(exc)}},
        )
        return {"vulnerabilities": [], "error": str(exc)[:200]}

    # Bucket affected packages per vuln ID. Use (type, name) so two packages
    # with the same name but different ecosystem aren't double-counted.
    affected: dict[str, set[tuple[str, str]]] = {}
    for entry in ((body.get("data") or {}).get("CertifyVuln") or []):
        vuln = entry.get("vulnerability") or {}
        if str(vuln.get("type") or "").lower() == "novuln":
            continue
        pkg = entry.get("package") or {}
        pkg_type = str(pkg.get("type") or "")
        pkg_names: set[tuple[str, str]] = set()
        for ns in (pkg.get("namespaces") or []):
            for n in (ns.get("names") or []):
                name = str(n.get("name") or "")
                if name:
                    pkg_names.add((pkg_type, name))
        for vid_node in (vuln.get("vulnerabilityIDs") or []):
            vid = str(vid_node.get("vulnerabilityID") or "").strip()
            if not vid:
                continue
            affected.setdefault(vid, set()).update(pkg_names)

    vulns = [
        {
            "id": vid,
            "affectedPackageCount": len(pkgs),
            # Light hint about ecosystem family — UI groups by this so
            # GHSA/CVE/debian-cve render in separate sections.
            "family": _family_of(vid),
        }
        for vid, pkgs in affected.items()
    ]
    vulns.sort(key=lambda v: (-v["affectedPackageCount"], v["id"]))
    return {"vulnerabilities": vulns}


def _family_of(vid: str) -> str:
    v = vid.lower()
    if v.startswith("ghsa-"):
        return "GHSA"
    if v.startswith("debian-cve-"):
        return "Debian"
    if v.startswith("rhsa-"):
        return "RHSA"
    if v.startswith("alas-"):
        return "Amazon Linux"
    if v.startswith("osv-"):
        return "OSV"
    if v.startswith("cve-"):
        return "CVE"
    return "Other"


async def blast_radius_by_cve(cve_id: str) -> dict[str, Any]:
    """Aggregate the impact of a CVE across all images and deployments
    known to GUAC. Returns a tree-shaped payload optimised for the UI.

    Shape:
      {
        "cve": "CVE-2024-XXXX",
        "vulnerablePackages": [
          {
            "name": "...",
            "version": "...",
            "affectedImages": [
              {
                "image": "...",
                "deployments": [
                  { "namespace": "...", "name": "...", "vexExempted": bool }
                ]
              }
            ]
          }
        ]
      }
    """
    url = _endpoint()
    if not url:
        return {"cve": cve_id, "vulnerablePackages": [], "guacUnavailable": True}

    # GUAC v1.x exposes the join through `CertifyVuln(certifyVulnSpec: ...)`
    # filtered by vulnerabilityID. Earlier drafts of this proxy used a
    # non-existent `findVulnerability` field which returned HTTP 422.
    # IDs in the graph come in three flavors (osv-certifier output):
    #   - "ghsa-xxxx-xxxx-xxxx"
    #   - "cve-2024-xxxx"
    #   - "debian-cve-2024-xxxx"
    # GUAC stores them lowercased, so normalise before querying.
    query = """
    query BlastRadius($cve: String!) {
      CertifyVuln(certifyVulnSpec: { vulnerability: { vulnerabilityID: $cve } }) {
        vulnerability { vulnerabilityIDs { vulnerabilityID } }
        package {
          type
          namespaces {
            namespace
            names {
              name
              versions { version qualifiers { key value } }
            }
          }
        }
      }
    }
    """

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                url,
                json={"query": query, "variables": {"cve": cve_id.lower()}},
            )
        if resp.status_code >= 400:
            logger.warning(
                "GUAC returned non-2xx for blast-radius query",
                extra={"details": {"cve": cve_id, "status": resp.status_code, "body": resp.text[:300]}},
            )
            return {"cve": cve_id, "vulnerablePackages": [], "error": f"GUAC HTTP {resp.status_code}"}
        body = resp.json()
        if body.get("errors"):
            logger.warning(
                "GUAC returned GraphQL errors for blast-radius query",
                extra={"details": {"cve": cve_id, "errors": str(body["errors"])[:300]}},
            )
            return {"cve": cve_id, "vulnerablePackages": [], "error": str(body["errors"][0].get("message", "GUAC GraphQL error"))[:200]}
    except Exception as exc:
        logger.exception(
            "GUAC blast-radius query failed",
            extra={"details": {"cve": cve_id, "error": str(exc)}},
        )
        return {"cve": cve_id, "vulnerablePackages": [], "error": str(exc)[:200]}

    # Normalise — GUAC payload shape is intentionally tolerant to schema drift.
    findings = ((body.get("data") or {}).get("CertifyVuln") or []) or []
    by_package: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in findings:
        pkg = entry.get("package") or {}
        pkg_type = str(pkg.get("type") or "")
        for namespace in (pkg.get("namespaces") or []):
            for pkg_name in (namespace.get("names") or []):
                for version in (pkg_name.get("versions") or []):
                    key = (pkg_type, pkg_name.get("name", ""), version.get("version", ""))
                    by_package.setdefault(
                        key,
                        {
                            # `type` is required when we ask GUAC which OCI
                            # images depend on this package (merge_cluster_context).
                            "type": pkg_type,
                            "name": pkg_name.get("name", ""),
                            "version": version.get("version", ""),
                            "affectedImages": [],
                        },
                    )
    return {
        "cve": cve_id,
        "vulnerablePackages": list(by_package.values()),
        "guacRaw": body if os.environ.get("GUAC_DEBUG") == "1" else None,
    }


def _canonical_image_ref(image: str) -> str:
    """Return the `registry/repo` part of an OCI ref (digest/tag stripped).

    Used as the join key between GUAC OCI package nodes and ZTA's
    `summary.image`. Keeps the digest/tag aside so we can prefer exact-digest
    matches when both sides carry one.
    """
    s = image.strip()
    if "@" in s:
        s = s.split("@", 1)[0]
    elif ":" in s.rsplit("/", 1)[-1]:
        s = s.rsplit(":", 1)[0]
    return s


def _zta_image_digest(image: str) -> str:
    if "@" in image:
        return image.split("@", 1)[1].strip()
    return ""


def _oci_pkg_to_canonical(pkg_node: dict[str, Any]) -> list[tuple[str, str]]:
    """Flatten a GUAC OCI package node into a list of `(repo, digest)` pairs.

    GUAC stores OCI packages with `type="oci"`, the registry+repo collapsed
    into either `namespace` + `name` or just `name`, and the digest in
    `version`. We normalise both shapes into a single canonical repo string.
    """
    out: list[tuple[str, str]] = []
    if pkg_node.get("type") != "oci":
        return out
    for ns in (pkg_node.get("namespaces") or []):
        ns_value = str(ns.get("namespace") or "").strip().strip("/")
        for n in (ns.get("names") or []):
            name = str(n.get("name") or "").strip().strip("/")
            repo = f"{ns_value}/{name}" if ns_value else name
            repo = repo.strip("/")
            if not repo:
                continue
            versions = n.get("versions") or [{}]
            for v in versions:
                out.append((repo, str(v.get("version") or "").strip()))
    return out


async def _images_for_package(pkg: dict[str, Any]) -> list[tuple[str, str]]:
    """Ask GUAC which OCI packages depend on `pkg`. Returns `(repo, digest)`.

    Replaces the previous substring hack. Uses `IsDependency` with
    `dependencyPackage` filter and keeps only OCI dependents.
    """
    url = _endpoint()
    if not url:
        return []
    pkg_type = str(pkg.get("type") or "").strip()
    pkg_name = str(pkg.get("name") or "").strip()
    if not pkg_type or not pkg_name:
        return []

    query = """
    query ImagesDependingOn($type: String!, $name: String!) {
      IsDependency(isDependencySpec: {
        dependencyPackage: { type: $type, name: $name }
      }) {
        package {
          type
          namespaces {
            namespace
            names { name versions { version } }
          }
        }
      }
    }
    """
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                url,
                json={"query": query, "variables": {"type": pkg_type, "name": pkg_name}},
            )
        if resp.status_code >= 400:
            logger.warning(
                "GUAC IsDependency lookup HTTP error",
                extra={"details": {"pkg": pkg_name, "status": resp.status_code}},
            )
            return []
        body = resp.json()
        if body.get("errors"):
            logger.warning(
                "GUAC IsDependency lookup GraphQL errors",
                extra={"details": {"pkg": pkg_name, "errors": str(body["errors"])[:200]}},
            )
            return []
    except Exception as exc:
        logger.warning(
            "GUAC IsDependency lookup failed",
            extra={"details": {"pkg": pkg_name, "error": str(exc)[:200]}},
        )
        return []

    pairs: list[tuple[str, str]] = []
    for entry in ((body.get("data") or {}).get("IsDependency") or []):
        pairs.extend(_oci_pkg_to_canonical(entry.get("package") or {}))
    return pairs


async def merge_cluster_context(
    blast: dict[str, Any],
    zta_index: list[dict[str, Any]],
) -> dict[str, Any]:
    """Attach K8s deployment context from the live ZTA list to each affected
    image. This is what makes the Blast Radius visualisation actionable:
    GUAC knows which images contain a package, the operator/scanner knows
    which images run in which namespaces.

    Joins by OCI repo (registry/repo), preferring an exact digest match when
    both GUAC and ZTA know one. Real graph traversal via IsDependency
    replaces the earlier substring hack — see `_images_for_package`.
    """
    # Index ZTA entries by canonical OCI repo so we can answer "which K8s
    # deployments run this image" in O(1). One repo can resolve to multiple
    # ZTAs if the image is reused across namespaces.
    repo_to_ztas: dict[str, list[dict[str, Any]]] = {}
    for entry in zta_index:
        summary = entry.get("summary", {}) or {}
        image = str(summary.get("image") or "").strip()
        if not image:
            continue
        meta = entry.get("metadata", {}) or {}
        vex_exempt = bool((summary.get("vex", {}) or {}).get("exemptedCount", 0))
        repo = _canonical_image_ref(image)
        repo_to_ztas.setdefault(repo, []).append(
            {
                "image": image,                            # full ref incl. digest
                "digest": _zta_image_digest(image),
                "namespace": meta.get("namespace"),
                "name": meta.get("name"),
                "trustLevel": summary.get("trustLevel"),
                "securityState": summary.get("securityState"),
                "vexExempted": vex_exempt,
            }
        )

    enriched_packages = []
    for pkg in blast.get("vulnerablePackages", []):
        # GUAC graph: which OCI images include this vulnerable package?
        dependent_images = await _images_for_package(pkg)
        # Bucket by canonical repo so multiple digests for the same image
        # collapse into one card with deployments listed under it.
        affected_by_repo: dict[str, dict[str, Any]] = {}
        for repo, guac_digest in dependent_images:
            ztas = repo_to_ztas.get(repo)
            if not ztas:
                # Image exists in GUAC graph but no ZTA runs it — skipped.
                # The filtering UI relies on `affectedImages` being empty
                # for "in graph only" packages.
                continue
            # When both sides know a digest, prefer the exact-digest match;
            # otherwise fall back to repo-level match (still useful — the
            # SBOM was ingested for the same image even if ZTA records a
            # newer pushed digest).
            if guac_digest:
                matched = [d for d in ztas if d["digest"] == guac_digest] or ztas
            else:
                matched = ztas
            label_image = matched[0]["image"] if matched else repo
            bucket = affected_by_repo.setdefault(
                repo,
                {"image": label_image, "deployments": []},
            )
            seen = {(d.get("namespace"), d.get("name")) for d in bucket["deployments"]}
            for d in matched:
                key = (d.get("namespace"), d.get("name"))
                if key in seen:
                    continue
                seen.add(key)
                bucket["deployments"].append(
                    {
                        "namespace": d["namespace"],
                        "name": d["name"],
                        "trustLevel": d["trustLevel"],
                        "securityState": d["securityState"],
                        "vexExempted": d["vexExempted"],
                    }
                )
        enriched = dict(pkg)
        enriched["affectedImages"] = list(affected_by_repo.values())
        enriched_packages.append(enriched)
    blast["vulnerablePackages"] = enriched_packages
    return blast
