package org.owasp.untrust.vv.visibility.secret.vault;

import java.util.Map;

import org.owasp.untrust.vv.visibility.secret.SecretReference;
import org.owasp.untrust.vv.visibility.secret.SecretStore;
import org.springframework.vault.core.VaultKeyValueOperations;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.VaultKeyValueOperationsSupport
        .KeyValueBackend;
import org.springframework.vault.support.VaultResponse;

public final class SpringVaultStringSecretStore
        implements SecretStore<String> {

    private static final String VALUE_KEY = "value";

    private final VaultKeyValueOperations operations;

    public SpringVaultStringSecretStore(
            VaultOperations vaultOperations,
            String mount) {

        this.operations = vaultOperations.opsForKeyValue(
                mount,
                KeyValueBackend.KV_2);
    }

    @Override
    public void write(
            SecretReference reference,
            String value) {

        operations.put(
                reference.path(),
                Map.of(VALUE_KEY, value));
    }

    @Override
    public String read(SecretReference reference) {
        VaultResponse response =
                operations.get(reference.path());

        // ALLOW NULL LITERAL: Spring Vault represents an absent or malformed secret response with a null response or null data map. This adapter is the library boundary that translates those external nullable outcomes into SecretUnavailableException without returning null to callers.
        if (response == null || response.getData() == null) {
            throw new SecretUnavailableException(reference);
        }

        Object value = response.getData().get(VALUE_KEY);

        if (!(value instanceof String secret)) {
            throw new SecretUnavailableException(reference);
        }

        return secret;
    }
}
