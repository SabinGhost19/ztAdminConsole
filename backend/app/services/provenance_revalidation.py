from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import shutil
import subprocess
from typing import Any


class RevalidationError(Exception):
    pass


logger = logging.getLogger("zero_trust_provenance_revalidation")


VBBI_ATTESTATION_TYPE = os.getenv("VBBI_ATTESTATION_TYPE", "https://devsecops.licenta.ro/VBBI/v1")
VBBI_STATEMENT_TYPE = os.getenv("VBBI_STATEMENT_TYPE", "https://in-toto.io/Statement/v1")
VBBI_HMAC_MODE = os.getenv("VBBI_HMAC_MODE", "shared-secret").strip().lower()
VBBI_HMAC_KEY = os.getenv("VBBI_HMAC_KEY", "dev-only-vbbi-key")
OIDC_ISSUER = os.getenv("VBBI_OIDC_ISSUER", "https://token.actions.githubusercontent.com")
COSIGN_BIN = os.getenv("COSIGN_BIN", "cosign")
VERIFY_TIMEOUT_SECONDS = int(os.getenv("VBBI_VERIFY_TIMEOUT_SECONDS", "30"))


def normalize_hex(value: str) -> str:
    return str(value or "").strip().lower().replace("0x", "")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def extract_json_objects(output: str) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            objects.append(parsed)
    return objects


def decode_attestation_payload(attestation_obj: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    payload_b64 = attestation_obj.get("payload")
    if not payload_b64:
        return None, None
    decoded = base64.b64decode(payload_b64).decode("utf-8")
    statement = json.loads(decoded)
    predicate_type = statement.get("predicateType")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return predicate_type, None
    return predicate_type, {
        "predicate": predicate,
        "subject": statement.get("subject", []) or [],
        "statementType": statement.get("_type", ""),
    }


def validate_vbbi_structure(voucher: dict[str, Any]) -> dict[str, Any]:
    predicate = voucher.get("predicate", {}) or {}
    subject = voucher.get("subject", []) or []
    statement_type = str(voucher.get("statementType", "")).strip()
    build_context = predicate.get("build_context", {}) or {}
    hmac_chain = predicate.get("hmac_chain", {}) or {}
    merkle_tree = predicate.get("merkle_tree", {}) or {}

    if statement_type != VBBI_STATEMENT_TYPE:
        raise RevalidationError(f"Voucher statement type '{statement_type}' does not match required '{VBBI_STATEMENT_TYPE}'")
    if not isinstance(subject, list) or not subject:
        raise RevalidationError("Voucher must contain at least one subject entry")

    required_context = ["repository", "workflow", "run_id", "event", "issuer_oidc", "slsa_level", "image", "commit_sha"]
    missing = [key for key in required_context if str(build_context.get(key, "")).strip() == ""]
    if missing:
        raise RevalidationError(f"Voucher build_context is missing required fields: {', '.join(missing)}")

    steps = hmac_chain.get("steps", []) or []
    leaves = merkle_tree.get("leaves", []) or []
    if not isinstance(steps, list) or not steps:
        raise RevalidationError("Voucher must include a non-empty hmac_chain.steps array")
    if not isinstance(leaves, list) or not leaves:
        raise RevalidationError("Voucher must include a non-empty merkle_tree.leaves array")
    if len(steps) != len(leaves):
        raise RevalidationError("Voucher hmac_chain.steps and merkle_tree.leaves must have the same length")

    return {
        "statementType": statement_type,
        "stepCount": len(steps),
    }


def validate_voucher_policy(voucher: dict[str, Any], image: str, min_slsa_level: int, trusted_repositories: list[str]) -> dict[str, Any]:
    predicate = voucher.get("predicate", {}) or {}
    subject = voucher.get("subject", []) or []
    structure_info = validate_vbbi_structure(voucher)
    build_context = predicate.get("build_context", {}) or {}
    repository = str(build_context.get("repository", "")).strip()

    if trusted_repositories and repository not in trusted_repositories:
        raise RevalidationError(f"Voucher repository '{repository}' is not allowed by policy")

    build_context_image = str(build_context.get("image", "")).strip()
    if build_context_image and build_context_image != image:
        raise RevalidationError("Voucher build_context.image does not match the ZeroTrustApplication image")

    expected_digest = ""
    if "@sha256:" in image:
        expected_digest = image.split("@sha256:", 1)[1].strip().lower()
    subject_matches = False
    for item in subject:
        if not isinstance(item, dict):
            continue
        digest = ((item.get("digest", {}) or {}).get("sha256", "") or "").strip().lower()
        if expected_digest and digest == expected_digest:
            subject_matches = True
            break
    if expected_digest and subject and not subject_matches:
        raise RevalidationError("Voucher subject digest does not match the ZeroTrustApplication image digest")

    slsa_level = int(build_context.get("slsa_level", predicate.get("slsa_level", 0)) or 0)
    if slsa_level < min_slsa_level:
        raise RevalidationError(f"Voucher SLSA level {slsa_level} is below required minimum {min_slsa_level}")

    return {
        "statementType": structure_info.get("statementType"),
        "stepCount": structure_info.get("stepCount"),
        "repository": repository,
        "slsaLevel": slsa_level,
        "subjectVerified": subject_matches if expected_digest else False,
    }


def fetch_vbbi_attestation(image: str, trusted_issuers: list[str]) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if shutil.which(COSIGN_BIN) is None:
        logger.warning("Cosign binary missing for VBBI revalidation", extra={"details": {"image": image, "cosignBin": COSIGN_BIN}})
        return None, {"status": "unavailable", "reason": "cosign-binary-missing"}

    last_error = ""
    for identity in trusted_issuers:
        logger.info("Attempting to fetch VBBI attestation", extra={"details": {"image": image, "identity": identity, "oidcIssuer": OIDC_ISSUER}})
        cmd = [
            COSIGN_BIN,
            "verify-attestation",
            image,
            "--type",
            VBBI_ATTESTATION_TYPE,
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            OIDC_ISSUER,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=VERIFY_TIMEOUT_SECONDS)
        if result.returncode != 0:
            last_error = result.stderr or result.stdout
            logger.warning("Cosign verify-attestation failed", extra={"details": {"image": image, "identity": identity, "returnCode": result.returncode, "stderr": last_error}})
            continue
        for obj in extract_json_objects(result.stdout):
            predicate_type, payload = decode_attestation_payload(obj)
            if payload is not None and predicate_type == VBBI_ATTESTATION_TYPE:
                logger.info("Fetched VBBI attestation successfully", extra={"details": {"image": image, "identity": identity}})
                return payload, {"status": "fetched", "identity": identity}
        last_error = "VBBI attestation output could not be parsed"
        logger.warning("Cosign output did not contain a parseable VBBI attestation", extra={"details": {"image": image, "identity": identity}})

    return None, {"status": "failed", "reason": last_error or "unable-to-fetch-vbbi-attestation"}


def compute_step_hmac(metadata_hash: str, previous: str, secret_key: str) -> str:
    payload = f"{metadata_hash}{previous}".encode("utf-8")
    return hmac.new(secret_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_hmac_chain(predicate: dict[str, Any], secret_key: str, enforce: bool = True) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    chain = predicate.get("hmac_chain", {}) or {}
    if not enforce:
        return {"verified": False, "steps": 0, "reason": "hmac-chain-enforcement-disabled"}, []

    provider = str(chain.get("provider", "shared-secret") or "shared-secret").strip().lower()
    algorithm = str(chain.get("algorithm", "") or "").strip().lower()
    seed = str(chain.get("h0_seed", "")).strip()
    final_voucher = str(chain.get("final_voucher", "")).strip()
    steps = chain.get("steps", []) or []

    if provider not in {"shared-secret", "vault-transit"}:
        raise RevalidationError(f"Unsupported VBBI hmac_chain.provider '{provider}'")
    if algorithm not in {"sha256", "sha2-256"}:
        raise RevalidationError(f"Unsupported VBBI hmac_chain.algorithm '{algorithm}'")
    if not seed or not final_voucher or not isinstance(steps, list) or not steps:
        raise RevalidationError("Voucher is missing required hmac_chain fields")

    if provider == "vault-transit":
        return {
            "verified": False,
            "steps": len(steps),
            "provider": provider,
            "reason": "vault-transit-revalidation-not-supported-in-dashboard",
        }, [
            {
                "id": f"step-{index}",
                "label": str(step.get("step_name", f"step-{index}")),
                "position": index,
                "verified": False,
                "metadataHash": step.get("metadata_hash"),
                "hmacResult": step.get("hmac_result"),
            }
            for index, step in enumerate(steps, start=1)
        ]

    previous = normalize_hex(seed)
    nodes: list[dict[str, Any]] = []
    for index, step in enumerate(steps, start=1):
        metadata_hash = normalize_hex(str(step.get("metadata_hash", "")).strip())
        expected_result = normalize_hex(str(step.get("hmac_result", "")).strip())
        computed = compute_step_hmac(metadata_hash, previous, secret_key)
        verified = computed == expected_result
        nodes.append(
            {
                "id": f"step-{index}",
                "label": str(step.get("step_name", f"step-{index}")),
                "position": index,
                "verified": verified,
                "metadataHash": metadata_hash,
                "hmacResult": expected_result,
                "computed": computed,
            }
        )
        if not verified:
            raise RevalidationError(f"HMAC chain mismatch at {step.get('step_name', f'step-{index}')}")
        previous = computed

    if previous != normalize_hex(final_voucher):
        raise RevalidationError("Final voucher does not match the last HMAC chain value")

    return {
        "verified": True,
        "steps": len(steps),
        "provider": provider,
        "finalVoucher": previous,
    }, nodes


def compute_merkle_root(leaves: list[str]) -> str:
    if not leaves:
        raise RevalidationError("Merkle tree requires at least one leaf")
    nodes = [sha256_text(normalize_hex(leaf)) for leaf in leaves]
    while len(nodes) > 1:
        next_level: list[str] = []
        for index in range(0, len(nodes), 2):
            left = nodes[index]
            right = nodes[index + 1] if index + 1 < len(nodes) else left
            next_level.append(sha256_text(left + right))
        nodes = next_level
    return nodes[0]


def build_merkle_tree(predicate: dict[str, Any]) -> tuple[dict[str, Any], list[list[dict[str, Any]]]]:
    merkle = predicate.get("merkle_tree", {}) or {}
    leaves_raw = merkle.get("leaves", []) or []
    if not leaves_raw:
        raise RevalidationError("Voucher is missing predicate.merkle_tree.leaves")

    leaves: list[str] = []
    labels: list[str] = []
    for index, item in enumerate(leaves_raw, start=1):
        if isinstance(item, dict):
            leaf_hash = str(item.get("hash", "")).strip()
            leaves.append(leaf_hash)
            labels.append(str(item.get("step", f"leaf-{index}")))
        else:
            leaves.append(str(item).strip())
            labels.append(f"leaf-{index}")

    expected_root = normalize_hex(str(merkle.get("root_hash", "")).strip())
    computed_root = compute_merkle_root(leaves)
    if computed_root != expected_root:
        raise RevalidationError("Merkle root mismatch")

    levels: list[list[dict[str, Any]]] = []
    current = [{"hash": normalize_hex(item), "label": labels[index]} for index, item in enumerate(leaves)]
    levels.append(current)
    while len(current) > 1:
        next_level: list[dict[str, Any]] = []
        for index in range(0, len(current), 2):
            left = current[index]["hash"]
            right = current[index + 1]["hash"] if index + 1 < len(current) else left
            next_level.append({"hash": sha256_text(left + right), "label": f"node-{len(levels)}-{index // 2}"})
        current = next_level
        levels.append(current)

    return {
        "verified": True,
        "computedRoot": computed_root,
        "expectedRoot": expected_root,
        "leafCount": len(leaves),
    }, list(reversed(levels))


def revalidate_vbbi(image: str, trusted_issuers: list[str], min_slsa_level: int, trusted_repositories: list[str], enforce_hmac_chain: bool) -> dict[str, Any]:
    logger.info(
        "Starting VBBI revalidation",
        extra={"details": {"image": image, "trustedIssuers": trusted_issuers, "minSlsaLevel": min_slsa_level, "trustedRepositories": trusted_repositories, "enforceHmacChain": enforce_hmac_chain}},
    )
    voucher, fetch_status = fetch_vbbi_attestation(image=image, trusted_issuers=trusted_issuers)
    if voucher is None:
        logger.warning("VBBI revalidation could not fetch attestation", extra={"details": {"image": image, "fetch": fetch_status}})
        return {
            "status": fetch_status.get("status", "failed"),
            "reason": fetch_status.get("reason", "attestation-not-available"),
            "fetch": fetch_status,
            "ledgerNodes": [],
            "merkleLevels": [],
        }

    voucher_policy = validate_voucher_policy(
        voucher=voucher,
        image=image,
        min_slsa_level=min_slsa_level,
        trusted_repositories=trusted_repositories,
    )
    hmac_result, ledger_nodes = verify_hmac_chain(
        predicate=voucher.get("predicate", {}) or {},
        secret_key=VBBI_HMAC_KEY,
        enforce=enforce_hmac_chain,
    )
    merkle_result, merkle_levels = build_merkle_tree(voucher.get("predicate", {}) or {})
    payload = {
        "status": "verified" if hmac_result.get("verified") and merkle_result.get("verified") else "warning",
        "fetch": fetch_status,
        "voucherPolicy": voucher_policy,
        "hmacChain": hmac_result,
        "merkle": merkle_result,
        "buildContext": ((voucher.get("predicate", {}) or {}).get("build_context", {}) or {}),
        "ledgerNodes": ledger_nodes,
        "merkleLevels": merkle_levels,
        "statementType": voucher.get("statementType"),
    }
    logger.info("Completed VBBI revalidation", extra={"details": {"image": image, "status": payload["status"], "fetch": fetch_status}})
    return payload