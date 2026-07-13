package io.aegis.commons.web;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;

class ApiExceptionHandlerTest {

    private final ApiExceptionHandler handler = new ApiExceptionHandler();

    @AfterEach
    void tearDown() {
        MDC.clear();
    }

    @Test
    void illegal_argument_maps_to_400_with_its_message() {
        ProblemDetail pd = handler.handleIllegalArgument(new IllegalArgumentException("bad tenant"));
        assertThat(pd.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(pd.getDetail()).isEqualTo("bad tenant");
    }

    @Test
    void unexpected_exception_maps_to_500_without_leaking_internals() {
        ProblemDetail pd = handler.handleUnexpected(
                new IllegalStateException("NPE at com.internal.Secret.line42 -- do not leak"));
        assertThat(pd.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        // The client must not see the internal detail.
        assertThat(pd.getDetail()).isEqualTo("An unexpected error occurred.");
        assertThat(pd.getDetail()).doesNotContain("Secret").doesNotContain("line42");
    }

    @Test
    void correlation_id_is_attached_when_present() {
        MDC.put(CorrelationIdFilter.MDC_KEY, "corr-123");
        ProblemDetail pd = handler.handleIllegalArgument(new IllegalArgumentException("x"));
        assertThat(pd.getProperties()).containsEntry("correlationId", "corr-123");
    }

    @Test
    void blank_message_falls_back_to_safe_default() {
        ProblemDetail pd = handler.handleIllegalArgument(new IllegalArgumentException(" "));
        assertThat(pd.getDetail()).isEqualTo("Invalid request.");
    }
}
