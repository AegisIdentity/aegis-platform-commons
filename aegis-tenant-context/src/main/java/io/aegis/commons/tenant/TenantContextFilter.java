package io.aegis.commons.tenant;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.MDC;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Binds the tenant from the {@link TenantHeaders#TENANT_ID} header to {@link TenantContext} for the
 * duration of the request, and always clears it afterwards.
 *
 * <p>This filter <em>trusts</em> the header — it must therefore run only where the header is
 * trustworthy (behind the gateway on the internal mesh). Do not place it on a public-facing edge
 * without first stripping/deriving the header. Also mirrors the tenant into SLF4J {@link MDC} so
 * every log line is attributable to a tenant.
 */
public class TenantContextFilter extends OncePerRequestFilter {

    /** MDC key for structured logging. */
    public static final String MDC_TENANT = "tenant";

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader(TenantHeaders.TENANT_ID);
        boolean bound = false;
        try {
            if (header != null && !header.isBlank()) {
                TenantId tenantId = TenantId.of(header.trim());
                TenantContext.set(tenantId);
                MDC.put(MDC_TENANT, tenantId.value());
                bound = true;
            }
            filterChain.doFilter(request, response);
        } catch (IllegalArgumentException ex) {
            // Malformed tenant header — reject rather than proceed tenant-less.
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid tenant header");
        } finally {
            if (bound) {
                TenantContext.clear();
                MDC.remove(MDC_TENANT);
            }
        }
    }
}
