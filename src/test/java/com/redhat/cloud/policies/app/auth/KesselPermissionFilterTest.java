package com.redhat.cloud.policies.app.auth;

import com.redhat.cloud.policies.app.auth.kessel.KesselClient;
import com.redhat.cloud.policies.app.auth.kessel.KesselObjectType;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import io.quarkus.test.InjectMock;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.jboss.resteasy.core.interception.jaxrs.PreMatchContainerRequestContext;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.spi.HttpRequest;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
@TestProfile(KesselPermissionFilterTest.class)
public class KesselPermissionFilterTest implements QuarkusTestProfile {
    @InjectMock
    KesselClient kesselClient;

    @InjectMock
    RhIdPrincipal user;

    @InjectMock
    RhIdPrincipal userPrincipal;

    @Inject
    PermissionFilter permissionFilter;

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "rbac.enabled", "false",
                "kessel.enabled", "true"
        );
    }

    @Test
    void testAbortsOnKesselError() throws Exception {
        Mockito.when(kesselClient.checkAccess(any(), any(), any())).thenThrow(RuntimeException.class);
        Mockito.when(kesselClient.getResources(any(), any(), any())).thenThrow(RuntimeException.class);

        HttpRequest request = MockHttpRequest.get("/");
        PreMatchContainerRequestContext context = spy(new PreMatchContainerRequestContext(request, null, null));

        permissionFilter.filter(context);
        verifyAbortedAsForbidden(context);

        verify(user, times(0)).setRbac(Mockito.anyBoolean(), Mockito.anyBoolean(), any());
        verify(userPrincipal, times(0)).setRbac(Mockito.anyBoolean(), Mockito.anyBoolean(), any());
    }

    @Test
    void testSetsPermssionsOnPrincipals() throws Exception {
        Mockito.when(kesselClient.checkAccess(any(), eq("policies_can_read"), any())).thenReturn(true);
        Mockito.when(kesselClient.checkAccess(any(), eq("policies_can_write"), any())).thenReturn(false);
        Mockito.when(kesselClient.getResources(eq(new KesselObjectType("rbac", "workspace")), any(), any())).thenReturn(null);

        HttpRequest request = MockHttpRequest.get("/");
        PreMatchContainerRequestContext context = spy(new PreMatchContainerRequestContext(request, null, null));

        context.setSecurityContext(securityContext());

        permissionFilter.filter(context);
        verify(context, Mockito.times(0)).abortWith(any());

        // two calls are made, as user and userPrincipal are the same instances
        verify(user, times(2)).setRbac(true, false, null);
        verify(userPrincipal, times(2)).setRbac(true, false, null);
    }


    @Test
    void testSetsHostGroupsOnPrincipals() throws Exception {
        UUID ungrouped = null;
        UUID groudOne = UUID.randomUUID();
        UUID groupTwo = UUID.randomUUID();

        List<String> groupsIn = new ArrayList<String>();
        groupsIn.add(groudOne.toString());
        groupsIn.add((String) null);
        groupsIn.add(groupTwo.toString());

        List<UUID> expected = new ArrayList<UUID>();
        expected.add(groudOne);
        expected.add(ungrouped);
        expected.add(groupTwo);

        Mockito.when(kesselClient.checkAccess(any(), eq("policies_can_read"), any())).thenReturn(true);
        Mockito.when(kesselClient.checkAccess(any(), eq("policies_can_write"), any())).thenReturn(false);
        Mockito.when(kesselClient.getResources(eq(new KesselObjectType("rbac", "workspace")), any(), any())).thenReturn(groupsIn);

        HttpRequest request = MockHttpRequest.get("/");
        PreMatchContainerRequestContext context = spy(new PreMatchContainerRequestContext(request, null, null));
        context.setSecurityContext(securityContext());

        permissionFilter.filter(context);
        verify(context, Mockito.times(0)).abortWith(Mockito.any());

        // two calls are made, as user and userPrincipal are the same instances
        ArgumentCaptor<List<UUID>> userSetGroupIds = ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<List<UUID>> userPrincipalSetGroupIds = ArgumentCaptor.forClass(List.class);
        verify(user, times(2))
            .setRbac(Mockito.eq(true), Mockito.eq(false), userSetGroupIds.capture());
        verify(userPrincipal, times(2))
            .setRbac(Mockito.eq(true), Mockito.eq(false), userPrincipalSetGroupIds.capture());
        assertEquals(expected, userSetGroupIds.getValue());
        assertEquals(expected, userPrincipalSetGroupIds.getValue());
    }


    void testAbortsOnBadHostGroups() throws Exception {
        Mockito.when(kesselClient.checkAccess(any(), eq("policies_can_read"), any())).thenReturn(true);
        Mockito.when(kesselClient.checkAccess(any(), eq("policies_can_write"), any())).thenReturn(false);
        Mockito.when(kesselClient.getResources(eq(new KesselObjectType("rbac", "workspace")), any(), any())).thenReturn(List.of("baduuid"));

        HttpRequest request = MockHttpRequest.get("/");
        PreMatchContainerRequestContext context = spy(new PreMatchContainerRequestContext(request, null, null));
        context.setSecurityContext(securityContext());

        permissionFilter.filter(context);
        verifyAbortedAsForbidden(context);

        verify(user, times(0)).setRbac(Mockito.anyBoolean(), Mockito.anyBoolean(), any());
        verify(userPrincipal, times(0)).setRbac(Mockito.anyBoolean(), Mockito.anyBoolean(), any());
    }

    @Test
    void testSomePathsAlwaysAllowed() throws Exception {
        Mockito.when(kesselClient.checkAccess(any(), any(), any())).thenThrow(RuntimeException.class);
        Mockito.when(kesselClient.getResources(any(), any(), any())).thenThrow(RuntimeException.class);


        HttpRequest request = MockHttpRequest.get("/admin");
        PreMatchContainerRequestContext context = spy(new PreMatchContainerRequestContext(request, null, null));
        permissionFilter.filter(context);
        verify(context, times(0)).abortWith(any());

        request = MockHttpRequest.get("/api/policies/v1.0/status");
        context = spy(new PreMatchContainerRequestContext(request, null, null));
        permissionFilter.filter(context);
        verify(context, times(0)).abortWith(any());

        verify(user, times(0)).setRbac(Mockito.anyBoolean(), Mockito.anyBoolean(), any());
        verify(userPrincipal, times(0)).setRbac(Mockito.anyBoolean(), Mockito.anyBoolean(), any());
    }


    void verifyAbortedAsForbidden(ContainerRequestContext context) {
        ArgumentCaptor<Response> response = ArgumentCaptor.forClass(Response.class);
        verify(context).abortWith(response.capture());
        assertEquals(Response.Status.FORBIDDEN, response.getValue().getStatusInfo());
    }

    SecurityContext securityContext() {
        return new SecurityContext() {
            @Override
            public Principal getUserPrincipal() {
                return userPrincipal;
            }
            @Override
            public boolean isUserInRole(String string) { return true; }
            @Override
            public boolean isSecure() { return true; }
            @Override
            public String getAuthenticationScheme() { return "X-RH-IDENTITY"; }
        };
    }

    @Test
    void testHostGroupsToUUIDs() {
        assertNull(PermissionFilter.hostGroupsToUUIDs(null));

        UUID ungrouped = null;
        UUID groudOne = UUID.randomUUID();
        UUID groupTwo = UUID.randomUUID();

        List<String> groupsIn = new ArrayList<String>();
        groupsIn.add(groudOne.toString());
        groupsIn.add((String) null);
        groupsIn.add(groupTwo.toString());

        List<UUID> expected = new ArrayList<UUID>();
        expected.add(groudOne);
        expected.add(ungrouped);
        expected.add(groupTwo);

        assertEquals(expected, PermissionFilter.hostGroupsToUUIDs(groupsIn));
    }

    @Test
    void testHostGroupsToUUIDsUniqeValues() {
        UUID ungrouped = null;
        UUID groudOne = UUID.randomUUID();
        UUID groupTwo = UUID.randomUUID();

        List<String> groupsIn = new ArrayList<String>();
        groupsIn.add(groudOne.toString());
        groupsIn.add(groudOne.toString());
        groupsIn.add((String) null);
        groupsIn.add((String) null);
        groupsIn.add(groupTwo.toString());
        groupsIn.add(groupTwo.toString());

        List<UUID> expected = new ArrayList<UUID>();
        expected.add(groudOne);
        expected.add(ungrouped);
        expected.add(groupTwo);

        assertEquals(expected, PermissionFilter.hostGroupsToUUIDs(groupsIn));
    }

    @Test
    void testHostGroupsToUUIDsMalformed() {
        assertThrows(IllegalArgumentException.class, () -> {
            PermissionFilter.hostGroupsToUUIDs(List.of("baduuid"));
        });
    }
}
