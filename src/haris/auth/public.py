PUBLIC_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("/health", "GET"),
        ("/login", "GET"),
        ("/login", "POST"),
        ("/auth/logout", "POST"),
        ("/auth/setup", "GET"),
        ("/auth/setup", "POST"),
        ("/auth/register", "GET"),
        ("/auth/register", "POST"),
        ("/auth/verify-email", "GET"),
        ("/auth/resend-verification", "POST"),
        ("/auth/oidc/login", "GET"),
        ("/auth/oidc/callback", "GET"),
    }
)
