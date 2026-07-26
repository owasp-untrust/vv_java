package org.owasp.untrust.vv.foundation;

public interface HalfBakedExposable<T> {
    record ExposeHalfBakedValueIntendedForInternalLibraryUseOnlyMarker() {}
    static final ExposeHalfBakedValueIntendedForInternalLibraryUseOnlyMarker EXPOSE_HALF_BAKED_VALUE_INTENDED_FOR_INTERNAL_LIBRARY_USE_ONLY_MARKER = new ExposeHalfBakedValueIntendedForInternalLibraryUseOnlyMarker();
    T exposeUnchecked(ExposeHalfBakedValueIntendedForInternalLibraryUseOnlyMarker marker);
}
