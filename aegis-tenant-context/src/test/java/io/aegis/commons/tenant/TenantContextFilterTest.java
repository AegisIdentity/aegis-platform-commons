package io.aegis.commons.tenant;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.Filter;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class TenantContextFilterTest {

    private final TenantContextFilter filter = new TenantContextFilter();

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void binds_tenant_from_header_during_request_and_clears_after() throws Exception {
        var request = new MockHttpServletRequest();
        request.addHeader(TenantHeaders.TENANT_ID, "acme");
        var response = new MockHttpServletResponse();

        AtomicReference<TenantId> seenInsideChain = new AtomicReference<>();
        Filter inner = (req, res, c) -> seenInsideChain.set(TenantContext.currentOrThrow());
        var chain = new MockFilterChain(new jakarta.servlet.http.HttpServlet() {}, inner);

        filter.doFilter(request, response, chain);

        assertThat(seenInsideChain.get()).isEqualTo(TenantId.of("acme"));
        // Critical: context must not leak past the request (pooled-thread reuse ⇒ cross-tenant bug).
        assertThat(TenantContext.isSet()).isFalse();
    }

    @Test
    void proceeds_without_binding_when_header_absent() throws Exception {
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();

        AtomicReference<Boolean> boundInside = new AtomicReference<>();
        Filter inner = (req, res, c) -> boundInside.set(TenantContext.isSet());
        var chain = new MockFilterChain(new jakarta.servlet.http.HttpServlet() {}, inner);

        filter.doFilter(request, response, chain);

        assertThat(boundInside.get()).isFalse();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void rejects_malformed_tenant_header_with_400() throws Exception {
        var request = new MockHttpServletRequest();
        request.addHeader(TenantHeaders.TENANT_ID, "bad/tenant");
        var response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(TenantContext.isSet()).isFalse();
    }
}
