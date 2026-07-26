package org.owasp.untrust.vv.prebuilt;

import org.owasp.untrust.vv.visibility.secret.SecretReference;
import org.owasp.untrust.vv.visibility.secret.SecretStore;
import org.owasp.untrust.vv.visibility.secret.SecretValue;
import org.owasp.untrust.vv.visibility.secret.SecretValueInitializer;

public class ApiKey extends SecretValue<String> {
    public ApiKey(SecretValueInitializer<String, ApiKey> initializer) {
        super(initializer);
    }

    public ApiKey(
            SecretStore<String> store,
            SecretReference reference,
            String displayValue) {
        super(store, reference, displayValue);
    }

    @Override
    protected String revalidate(String value) {
        return validate(value, new PendingApiKey.Traits());
    }
}
