package com.redhat.cloud.policies.app.auth.kessel;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

public class KesselResult {
    private boolean canRead = false;
    private boolean canWrite = false;
    private List<UUID> hostGroupIds = List.of();

    public KesselResult(boolean canRead, boolean canWrite, List<UUID> hostGroupIds) {
        this.canRead = canRead;
        this.canWrite = canWrite;
        this.hostGroupIds = hostGroupIds;
    }


    public boolean canRead() {
        return canRead;
    }

    public boolean canWrite() {
        return canWrite;
    }

    public List<UUID> getHostGroupIds() {
        return hostGroupIds;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof KesselResult that)) return false;
        return canRead == that.canRead && canWrite == that.canWrite && Objects.equals(hostGroupIds, that.hostGroupIds);
    }

    @Override
    public int hashCode() {
        return Objects.hash(canRead, canWrite, hostGroupIds);
    }
}
