package com.communityguardian.service;

public class AuthorizationService {
    public static boolean canManageMembers(SafeCircleService.MemberEntry actorMembership) {
        return actorMembership != null
            && "active".equals(actorMembership.status)
            && actorMembership.canManage;
    }

    public static boolean canChangeManageAccess(SafeCircleService.MemberEntry actorMembership) {
        return actorMembership != null
            && "active".equals(actorMembership.status)
            && actorMembership.isOwner;
    }
}
