package org.owasp.untrust.vv.visibility.secret.vault;

import org.owasp.untrust.vv.visibility.secret.SecretReference;

public final class SecretUnavailableException
        extends RuntimeException {

    public SecretUnavailableException(
            SecretReference reference) {

        /*
         * Consider omitting the path if Vault paths themselves
         * contain sensitive information.
         */
        super("Secret could not be retrieved");
    }
}
