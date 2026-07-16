package org.owasp.untrust.vv;

import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.owasp.untrust.valuedescriptors.Hardcoded;

import org.owasp.untrust.vv.exceptions.EntityNotFoundException;
import org.owasp.untrust.vv.exceptions.EntityAccessForbiddenException;

import jakarta.servlet.http.HttpServletRequest;

public class DataAccess<Snapshot> {
    private static final Logger LOGGER = LoggerFactory.getLogger(DataAccess.class);

    public enum DisclosurePolicy {
        EXPLICIT_404_403,
        HIDE_EXISTENCE
    }

    public static record AuthorizedAccess<Snapshot> (
        ViewableUuidValue entityId,
        String authorizationJustification,
        Class<? extends Snapshot> snapshotClass,
        Snapshot snapshot,
        String authorizedForPrincipal,
        DisclosurePolicy disclosurePolicy
    ) {
        @SuppressWarnings("unchecked")
        public static <Snapshot> AuthorizedAccess<Snapshot> from(ViewableUuidValue entityId, String authorizationJustification, Snapshot snapshot, String authorizedForPrincipal, DisclosurePolicy disclosurePolicy) {
            Class<? extends Snapshot> snapshotClass = (Class<? extends Snapshot>) snapshot.getClass();
            return new AuthorizedAccess<Snapshot>(
                entityId, 
                authorizationJustification,
                snapshotClass, 
                snapshot, 
                authorizedForPrincipal, 
                disclosurePolicy);
        }
    }

    @SuppressWarnings("unchecked")
    public AuthorizedAccess<Snapshot> authorize(
            Authentication authentication,
            ViewableUuidValue entityId,
            HttpServletRequest request,
            Hardcoded attrKeyForCached,
            Class<Snapshot> snapshotClass,
            Function<ViewableUuidValue, Optional<Snapshot>> findSnapshotById,
            BiFunction<Authentication, Snapshot, Optional<String>> justifyAuthorization,
            DisclosurePolicy disclosurePolicy) {
        if (!authentication.isAuthenticated()) {
            throw new EntityAccessForbiddenException(entityId);
        }

        Object cached = request.getAttribute(attrKeyForCached.exposeUnchecked());
        if (cached instanceof AuthorizedAccess existing
                && existing.entityId().equals(entityId)
                && existing.snapshotClass().equals(snapshotClass)
                && existing.authorizedForPrincipal().equals(authentication.getName())
                && existing.disclosurePolicy() == disclosurePolicy) {
            return existing;
        }

        return authorize(authentication, entityId, findSnapshotById, justifyAuthorization, disclosurePolicy);
    }

    public AuthorizedAccess<Snapshot> authorize(
            Authentication authentication,
            ViewableUuidValue entityId,
            Function<ViewableUuidValue, Optional<Snapshot>> findSnapshotById,
            BiFunction<Authentication, Snapshot, Optional<String>> justifyAuthorization) {
        return authorize(authentication, entityId, findSnapshotById, justifyAuthorization, DisclosurePolicy.HIDE_EXISTENCE);
    }

    public AuthorizedAccess<Snapshot> authorize(
            Authentication authentication,
            ViewableUuidValue entityId,
            Function<ViewableUuidValue, Optional<Snapshot>> findSnapshotById,
            BiFunction<Authentication, Snapshot, Optional<String>> justifyAuthorization,
            DisclosurePolicy disclosurePolicy) {
        if (!authentication.isAuthenticated()) {
            throw new EntityAccessForbiddenException(entityId);
        }

        Snapshot snapshot = findSnapshotById.apply(entityId)
            .orElseThrow(() -> new EntityNotFoundException(entityId));

        Optional<String> authorizationJustification = justifyAuthorization.apply(authentication, snapshot);
        if (authorizationJustification.isEmpty()) {
            // TODO: change logging to structured logging
            LOGGER.warn("Authorization failed for principal {} on entity {} with snapshot {}. Disclosure policy: {}",
                authentication.getName(), entityId, snapshot, disclosurePolicy);
            if (disclosurePolicy == DisclosurePolicy.HIDE_EXISTENCE) {
                throw new EntityNotFoundException(entityId);
            }
            throw new EntityAccessForbiddenException(entityId);
        }

        AuthorizedAccess<Snapshot> access = AuthorizedAccess.from(
            entityId, authorizationJustification.get(),
            snapshot, authentication.getName(), disclosurePolicy);

        //request.setAttribute(ATTR, access);
        return access;
    }
}
