package io.aegis.commons.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.aegis.commons.tenant.TenantContext;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

/**
 * ADR-0010: the delegation chain is added <b>additively</b>. {@code AuditEvent}'s own javadoc says
 * records are "streamed to customer SIEMs", which makes this schema a customer-facing contract —
 * so the existing nine fields must keep their exact names and meanings, and {@code actor} must keep
 * meaning "the effective (last-hop) actor".
 */
class AuditEventDelegationTest {

    private final ObjectMapper mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    @AfterEach
    void tearDown() {
        TenantContext.clear();
        MDC.clear();
    }

    private static DelegationChain aliceToResearcher() {
        return DelegationChain.of(
                new DelegationHop("user:alice@acme", PrincipalType.HUMAN, null, Instant.now(), Set.of("files:read")),
                new DelegationHop("agent:planner", PrincipalType.AGENT, "mcp", Instant.now(), Set.of("files:read")),
                new DelegationHop("agent:researcher", PrincipalType.AGENT, "mcp", Instant.now(), Set.of("files:read")));
    }

    // --- backward compatibility: the contract nobody may break ---------------------------------

    @Test
    void the_original_nine_json_keys_are_unchanged() throws Exception {
        AuditEvent event = AuditEvent.of("auth", "login", AuditOutcome.SUCCESS)
                .tenant("acme").actor("user-1").target("session-9").build();

        JsonNode json = mapper.readTree(mapper.writeValueAsString(event));

        assertThat(json.has("type")).isTrue();
        assertThat(json.has("action")).isTrue();
        assertThat(json.has("outcome")).isTrue();
        assertThat(json.has("tenantId")).isTrue();
        assertThat(json.has("actor")).isTrue();
        assertThat(json.has("target")).isTrue();
        assertThat(json.has("correlationId")).isTrue();
        assertThat(json.has("at")).isTrue();
        assertThat(json.has("attributes")).isTrue();

        assertThat(json.get("type").asText()).isEqualTo("auth");
        assertThat(json.get("actor").asText()).isEqualTo("user-1");
        assertThat(json.get("tenantId").asText()).isEqualTo("acme");
    }

    @Test
    void the_nine_argument_constructor_still_compiles_and_works() {
        // Downstream repos construct AuditEvent directly; adding record components must not force
        // them to change. This test exists to fail loudly if that convenience overload is removed.
        AuditEvent event = new AuditEvent("admin", "user.created", AuditOutcome.SUCCESS,
                "acme", "root", "bob", "corr-1", Instant.now(), null);

        assertThat(event.actor()).isEqualTo("root");
        assertThat(event.delegationChain().isEmpty()).isTrue();
        assertThat(event.onBehalfOf()).isNull();
    }

    @Test
    void an_event_without_delegation_has_an_empty_chain_not_null() {
        AuditEvent event = AuditEvent.of("auth", "login", AuditOutcome.SUCCESS).build();
        assertThat(event.delegationChain()).isNotNull();
        assertThat(event.delegationChain().isEmpty()).isTrue();
    }

    // --- the added behaviour --------------------------------------------------------------------

    @Test
    void delegation_derives_actor_from_the_effective_hop_and_onBehalfOf_from_the_root() {
        AuditEvent event = AuditEvent.of("agent", "tool.invoke", AuditOutcome.SUCCESS)
                .delegation(aliceToResearcher())
                .build();

        // ADR-0010 invariant, made executable: actor keeps meaning "last hop", and the root human
        // is always one field away no matter how deep the chain went.
        assertThat(event.actor()).isEqualTo("agent:researcher");
        assertThat(event.onBehalfOf()).isEqualTo("user:alice@acme");
        assertThat(event.delegationChain().depth()).isEqualTo(3);
    }

    @Test
    void an_explicit_actor_set_after_delegation_wins() {
        AuditEvent event = AuditEvent.of("agent", "tool.invoke", AuditOutcome.SUCCESS)
                .delegation(aliceToResearcher())
                .actor("agent:override")
                .build();
        assertThat(event.actor()).isEqualTo("agent:override");
        assertThat(event.onBehalfOf()).isEqualTo("user:alice@acme");
    }

    @Test
    void agent_instance_and_tool_invocation_ids_are_carried() {
        AuditEvent event = AuditEvent.of("agent", "tool.invoke", AuditOutcome.SUCCESS)
                .agentInstanceId("run-7f3a")
                .toolInvocationId("call-0001")
                .build();

        assertThat(event.agentInstanceId()).isEqualTo("run-7f3a");
        assertThat(event.toolInvocationId()).isEqualTo("call-0001");
    }

    @Test
    void delegation_fields_serialize_as_additional_keys() throws Exception {
        AuditEvent event = AuditEvent.of("agent", "tool.invoke", AuditOutcome.SUCCESS)
                .delegation(aliceToResearcher())
                .agentInstanceId("run-7f3a")
                .build();

        JsonNode json = mapper.readTree(mapper.writeValueAsString(event));
        assertThat(json.get("onBehalfOf").asText()).isEqualTo("user:alice@acme");
        assertThat(json.get("agentInstanceId").asText()).isEqualTo("run-7f3a");
        assertThat(json.get("delegationChain").get("hops")).hasSize(3);
    }

    @Test
    void round_trips_through_jackson_with_the_delegation_chain_intact() throws Exception {
        // admin-api-service DESERIALIZES audit events off Kafka. Adding a second (9-arg)
        // constructor must not confuse Jackson's record handling into picking the wrong one.
        AuditEvent original = AuditEvent.of("agent", "tool.invoke", AuditOutcome.SUCCESS)
                .tenant("acme")
                .delegation(aliceToResearcher())
                .agentInstanceId("run-7f3a")
                .toolInvocationId("call-0001")
                .build();

        AuditEvent restored = mapper.readValue(mapper.writeValueAsString(original), AuditEvent.class);

        assertThat(restored.actor()).isEqualTo("agent:researcher");
        assertThat(restored.onBehalfOf()).isEqualTo("user:alice@acme");
        assertThat(restored.agentInstanceId()).isEqualTo("run-7f3a");
        assertThat(restored.toolInvocationId()).isEqualTo("call-0001");
        assertThat(restored.delegationChain().depth()).isEqualTo(3);
        assertThat(restored.delegationChain().root()).get()
                .extracting(DelegationHop::principal).isEqualTo("user:alice@acme");
    }

    @Test
    void a_legacy_json_payload_without_delegation_fields_still_deserializes() throws Exception {
        // A SIEM replaying events written before this change must not break.
        String legacy = """
                {"type":"auth","action":"login","outcome":"SUCCESS","tenantId":"acme",
                 "actor":"user-1","target":null,"correlationId":"corr-1",
                 "at":"2026-08-26T10:00:00Z","attributes":{}}
                """;

        AuditEvent restored = mapper.readValue(legacy, AuditEvent.class);

        assertThat(restored.actor()).isEqualTo("user-1");
        assertThat(restored.delegationChain()).isNotNull();
        assertThat(restored.delegationChain().isEmpty()).isTrue();
        assertThat(restored.onBehalfOf()).isNull();
    }

    @Test
    void a_laundering_chain_is_detectable_from_the_event_itself() {
        DelegationChain laundering = DelegationChain.of(
                new DelegationHop("agent:low", PrincipalType.AGENT, null, Instant.now(), Set.of("files:read")),
                new DelegationHop("agent:high", PrincipalType.AGENT, null, Instant.now(), Set.of("admin:all")));

        AuditEvent event = AuditEvent.of("agent", "tool.invoke", AuditOutcome.DENIED)
                .delegation(laundering)
                .build();

        assertThat(event.delegationChain().isMonotonicallyNarrowing()).isFalse();
    }
}
