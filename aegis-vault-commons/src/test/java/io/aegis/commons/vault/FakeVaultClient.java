package io.aegis.commons.vault;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Records what would have been sent to Vault, so tests can assert on paths and request bodies. */
class FakeVaultClient implements VaultClient {

    record Call(String verb, String path, Map<String, Object> body, String namespace) {
    }

    final List<Call> calls = new ArrayList<>();
    final Map<String, Map<String, Object>> responses = new LinkedHashMap<>();

    void respondTo(String path, Map<String, Object> response) {
        responses.put(path, response);
    }

    @Override
    public Map<String, Object> read(String path, String namespace) {
        calls.add(new Call("READ", path, Map.of(), namespace));
        return responses.getOrDefault(path, Map.of());
    }

    @Override
    public Map<String, Object> write(String path, Map<String, Object> data, String namespace) {
        calls.add(new Call("WRITE", path, data, namespace));
        return responses.getOrDefault(path, Map.of());
    }

    @Override
    public void delete(String path, String namespace) {
        calls.add(new Call("DELETE", path, Map.of(), namespace));
    }

    Call lastCall() {
        return calls.get(calls.size() - 1);
    }
}
