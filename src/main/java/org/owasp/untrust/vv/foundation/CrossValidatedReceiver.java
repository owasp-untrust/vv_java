package org.owasp.untrust.vv.foundation;

import org.owasp.untrust.vv.foundation.CrossValidationCandidate.FullyValidated;
import org.owasp.untrust.vv.foundation.HalfBakedExposable.ExposeHalfBakedValueIntendedForInternalLibraryUseOnlyMarker;
import org.owasp.untrust.valuedescriptors.foundation.ExposableWrappedValue;

public abstract class CrossValidatedReceiver<T, ReceiverOfValidated extends CrossValidatedReceiver<T, ReceiverOfValidated>> 
        extends ExposableWrappedValue<T> {
    protected CrossValidatedReceiver(FullyValidated<T, ReceiverOfValidated> validated) {
        super(validated.m_validated);
    }
}
