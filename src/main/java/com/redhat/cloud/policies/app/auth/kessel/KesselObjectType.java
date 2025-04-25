package com.redhat.cloud.policies.app.auth.kessel;

import java.util.Objects;

public class KesselObjectType {
    public String namespace;
    public String name;

    public KesselObjectType(String namespace, String name) {
        this.namespace = namespace;
        this.name = name;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof KesselObjectType that)) return false;
        return Objects.equals(namespace, that.namespace) && Objects.equals(name, that.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(namespace, name);
    }
}
