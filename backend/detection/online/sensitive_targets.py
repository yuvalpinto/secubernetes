SENSITIVE_EXACT_PATHS = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh/authorized_keys",
}

SENSITIVE_PREFIXES = [
    "/root/",
    "/var/run/secrets/kubernetes.io/serviceaccount",
    "/etc/kubernetes/",
    "/etc/ssl/private/",
]

SUSPICIOUS_FILENAME_TOKENS = {
    "id_rsa",
    "id_ed25519",
    ".kube/config",
    "token",
}


def match_sensitive_openat_target(filename: str) -> tuple[bool, str | None]:
    """
    Returns:
        (True, matched_rule) if filename is sensitive/suspicious.
        (False, None) otherwise.
    """
    if not filename:
        return False, None

    if filename in SENSITIVE_EXACT_PATHS:
        return True, f"exact:{filename}"

    for prefix in SENSITIVE_PREFIXES:
        if filename.startswith(prefix):
            return True, f"prefix:{prefix}"

    for token in SUSPICIOUS_FILENAME_TOKENS:
        if token in filename:
            return True, f"token:{token}"

    return False, None