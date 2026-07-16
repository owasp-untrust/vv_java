package org.owasp.untrust.vv;

import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.springframework.security.core.Authentication;

import org.owasp.untrust.vv.DataAccess.AuthorizedAccess;
import org.owasp.untrust.vv.DataAccess.DisclosurePolicy;
import org.owasp.untrust.vv.exceptions.ValidationException;

public class Entity<Snapshot> {
    private final ViewableUuidValue m_entityId;
    private final DataAccess<Snapshot> m_dataAccess = new DataAccess<>();

    public Entity(String raw) throws ValidationException {
        m_entityId = new ViewableUuidValue(raw);
    }

    public AuthorizedAccess<Snapshot> authorize(
            Authentication authentication,
            Function<ViewableUuidValue, Optional<Snapshot>> findSnapshotById,
            BiFunction<Authentication, Snapshot, Optional<String>> justifyAuthorization) {
        return m_dataAccess.authorize(authentication, m_entityId, findSnapshotById, justifyAuthorization, DisclosurePolicy.HIDE_EXISTENCE);
    }
}
