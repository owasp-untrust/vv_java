package org.owasp.untrust.vv.pii.vault;

import java.util.Map;
import java.util.Objects;

import org.owasp.untrust.vv.pii.SecretReference;
import org.owasp.untrust.vv.pii.SecretStore;
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

        Objects.requireNonNull(vaultOperations);
        Objects.requireNonNull(mount);

        this.operations = vaultOperations.opsForKeyValue(
                mount,
                KeyValueBackend.KV_2);
    }

    @Override
    public void write(
            SecretReference reference,
            String value) {

        Objects.requireNonNull(reference);
        Objects.requireNonNull(value);

        operations.put(
                reference.path(),
                Map.of(VALUE_KEY, value));
    }

    @Override
    public String read(SecretReference reference) {
        Objects.requireNonNull(reference);

        VaultResponse response =
                operations.get(reference.path());

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
