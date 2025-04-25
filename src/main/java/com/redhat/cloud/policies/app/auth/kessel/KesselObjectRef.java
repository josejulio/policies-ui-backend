package com.redhat.cloud.policies.app.auth.kessel;

import java.util.Objects;

public class KesselObjectRef {
    String id;
    KesselObjectType objectType;

    public KesselObjectRef(String id, KesselObjectType objectType) {
        this.id = id;
        this.objectType = objectType;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof KesselObjectRef that)) return false;
        return Objects.equals(id, that.id) && Objects.equals(objectType, that.objectType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, objectType);
    }
}
