package org.owasp.untrust.vv.pii;

import org.owasp.untrust.valuedescriptors.foundation.ToStringPublicReplacement;

public interface Pii<T> extends ToStringPublicReplacement{
    T exposeUnchecked();
}
