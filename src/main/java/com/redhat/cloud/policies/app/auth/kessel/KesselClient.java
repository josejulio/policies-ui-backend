package com.redhat.cloud.policies.app.auth.kessel;

import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;
import java.util.Map;

@ApplicationScoped
public class KesselClient {

    static class Permission {
        String orgId = "";
        boolean canReadPolicies = false;
        boolean canWritePolicies = false;
        List<String> hostGroupIds = null;

        Permission(String orgId, boolean canReadPolicies, boolean canWritePolicies, List<String> hostGroupIds) {
            this.orgId = orgId;
            this.canReadPolicies = canReadPolicies;
            this.canWritePolicies = canWritePolicies;
            this.hostGroupIds = hostGroupIds;
        }
    }

    Map<String, Permission> permissions = Map.of(
            "123456", new Permission(
                    "123456",
                    true,
                    true,
                    List.of(
                    "f3f5bfbe-80c3-4e09-be3e-17ec5ab360c6",
                    "b757589c-b927-42cc-80d1-a13747f253f9",
                    "d45f6c91-8371-4c7b-8cfe-367b111ceaa6"
            ))
    );

    private boolean isOrg (KesselObjectType maybeOrg) {
        return maybeOrg.namespace.equals("rbac") && maybeOrg.name.equals("tenant");
    }

    private boolean isWorkspace(KesselObjectType maybeWorkspace) {
        return maybeWorkspace.namespace.equals("rbac") && maybeWorkspace.name.equals("workspace");
    }

    private boolean isPrincipal(KesselObjectType maybeWorkspace) {
        return maybeWorkspace.namespace.equals("rbac") && maybeWorkspace.name.equals("principal");
    }

    public boolean checkAccess(KesselObjectRef object, String relation, KesselSubject subject) {
        if (isOrg(object.objectType) && isPrincipal(subject.objectRef.objectType)) {
            Permission permission = permissions.get(subject.objectRef.id);
            if (permission != null) {
                if (relation.equals("policies_can_read")) {
                    return permission.canReadPolicies;
                } else if (relation.equals("policies_can_write")) {
                    return permission.canWritePolicies;
                }
            }
        }

        return false;
    }

    public List<String> getResources(KesselObjectType objectType, String relation, KesselSubject subject) {
        if (isWorkspace(objectType) && isPrincipal(subject.objectRef.objectType)) {
            Permission permission = permissions.get(subject.objectRef.id);
            if (permission != null) {
                return permission.hostGroupIds;
            }
        }
        return null;
    }
}
