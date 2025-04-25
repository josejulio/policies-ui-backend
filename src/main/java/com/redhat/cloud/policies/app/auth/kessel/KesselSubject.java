package com.redhat.cloud.policies.app.auth.kessel;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Objects;

public class KesselSubject {

    KesselObjectRef objectRef;
    String subjectRelation;

    public KesselSubject(KesselObjectRef objectRef, String subjectRelation) {
        this.objectRef = objectRef;
        this.subjectRelation = subjectRelation;
    }

    public static KesselSubject fromPrincipal(String principal) {
        return new KesselSubject(
                new KesselObjectRef(
                        principal,
                        new KesselObjectType("rbac", "principal")
                ),
                null
        );
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof KesselSubject that)) return false;
        return Objects.equals(objectRef, that.objectRef) && Objects.equals(subjectRelation, that.subjectRelation);
    }

    @Override
    public int hashCode() {
        return Objects.hash(objectRef, subjectRelation);
    }
}
