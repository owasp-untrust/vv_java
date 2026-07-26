package org.owasp.untrust.vv.visibility;

import org.owasp.untrust.valuedescriptors.foundation.PubliclyRepresentable;

// marker interface for values that are sensitive and should not be exposed publicly
public interface Sensitive<T> extends PubliclyRepresentable {
}
