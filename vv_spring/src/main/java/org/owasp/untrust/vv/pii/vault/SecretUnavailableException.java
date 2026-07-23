package org.owasp.untrust.vv.pii.vault;

import org.owasp.untrust.vv.pii.SecretReference;

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
