package io.aegis.commons.security;

import java.time.Duration;
import java.util.List;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Builds an explicit {@link CorsConfigurationSource} from an allow-list of origins. Refuses the
 * wildcard-{@code *}-with-credentials combination (browsers reject it anyway, and it is the wrong
 * default). Credentials are enabled because the platform's browser flows rely on cookies/headers.
 */
public final class CorsConfigFactory {

    private CorsConfigFactory() {
    }

    /**
     * Builds a CORS source that requires explicit {@code https://} origins. Equivalent to
     * {@link #fromAllowedOrigins(List, boolean)} with insecure-localhost disabled.
     */
    public static CorsConfigurationSource fromAllowedOrigins(List<String> allowedOrigins) {
        return fromAllowedOrigins(allowedOrigins, false);
    }

    /**
     * Builds a CORS source from an allow-list of origins.
     *
     * <p>Rejects: an empty list, the wildcard {@code *} (never valid with credentials), the literal
     * {@code "null"} origin (sent by sandboxed iframes / {@code file://} / redirected requests and a
     * classic allow-list bypass), and any non-{@code https://} origin. When {@code allowInsecureLocalhost}
     * is {@code true}, {@code http://localhost} / {@code http://127.0.0.1} origins are permitted for
     * local development only.
     *
     * @param allowedOrigins          explicit origins to allow
     * @param allowInsecureLocalhost  dev-only escape hatch for plaintext localhost origins
     */
    public static CorsConfigurationSource fromAllowedOrigins(List<String> allowedOrigins,
            boolean allowInsecureLocalhost) {
        if (allowedOrigins == null || allowedOrigins.isEmpty()) {
            throw new IllegalArgumentException("at least one allowed origin is required");
        }
        if (allowedOrigins.contains("*")) {
            throw new IllegalArgumentException(
                    "wildcard origin '*' is not allowed with credentials; list explicit origins");
        }
        for (String origin : allowedOrigins) {
            if ("null".equalsIgnoreCase(origin)) {
                throw new IllegalArgumentException(
                        "the literal 'null' origin is not allowed; list explicit origins");
            }
            if (!isHttps(origin) && !(allowInsecureLocalhost && isLocalhostHttp(origin))) {
                throw new IllegalArgumentException(
                        "origin must use https:// (got '" + origin + "'); "
                                + "http://localhost is only allowed when insecure localhost is enabled");
            }
        }
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.copyOf(allowedOrigins));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Correlation-Id",
                "X-XSRF-TOKEN"));
        config.setExposedHeaders(List.of("X-Correlation-Id"));
        config.setAllowCredentials(true);
        config.setMaxAge(Duration.ofHours(1));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    private static boolean isHttps(String origin) {
        return origin != null && origin.regionMatches(true, 0, "https://", 0, "https://".length());
    }

    private static boolean isLocalhostHttp(String origin) {
        if (origin == null) {
            return false;
        }
        String lower = origin.toLowerCase(java.util.Locale.ROOT);
        return lower.startsWith("http://localhost")
                || lower.startsWith("http://127.0.0.1")
                || lower.startsWith("http://[::1]");
    }
}
