## Phase 3: Authorization & Access Control

**Objective:** Find paths to escalate privileges, access admin functionality, or perform unauthorized actions.

### Checklist

1. Verify all admin endpoints check role server-side (not just UI hiding)
2. Check for role escalation â€” can a user promote themselves to admin?
3. Verify sensitive admin actions require extra confirmation
4. Check that role hierarchy is enforced (admin can't modify superadmin)
5. Verify API routes don't trust client-provided role/permission claims
6. Check for horizontal privilege escalation between same-role users
7. Verify team/project-level permissions are checked server-side
8. Check invite/sharing flows for privilege escalation
9. Verify that role changes trigger session invalidation

### Where to Look

```bash
# Authorization checks
grep -r "isAdmin\|is_admin\|role\|permission\|authorize\|requireAdmin\|requireAuth\|requireOwnership" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# Admin routes
grep -r "admin\|superadmin\|moderator" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# Role assignment
grep -r "setRole\|updateRole\|role.*=\|assignRole" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules

# Team/project access
grep -r "teamMember\|projectAccess\|memberRole\|invite" --include="*.{js,ts,tsx,py,go,rb,php}" | grep -v node_modules
```

### Anti-Patterns

```typescript
// CRITICAL: Client-side only admin check
function AdminPanel() {
  const { user } = useAuth();
  if (user.role !== 'admin') return null; // Only UI check!
  return <AdminControls />; // API endpoints still accessible!
}

// CRITICAL: Trust client-provided role
app.post('/api/admin/action', (req, res) => {
  if (req.body.isAdmin === true) { // Attacker sets this!
    performAdminAction();
  }
});

// HIGH: No role escalation protection
async function setUserRole(targetUserId, newRole) {
  // Any admin can set any role, including superadmin!
  await db.patch(targetUser._id, { role: newRole });
}

// HIGH: Missing confirmation for destructive admin actions
async function banUser(targetUserId) {
  // One accidental click bans a user
  await db.patch(targetUser._id, { banned: true });
}

// MEDIUM: No session invalidation on role change
await db.patch(targetUser._id, { role: newRole });
// Old sessions still carry the previous role!
```

### Proper Patterns

```typescript
// GOOD: Server-side admin verification on every admin endpoint
async function requireAdmin(ctx, sessionToken) {
  const { userId, user } = await requireAuth(ctx, sessionToken);
  if (user.role !== "admin" && user.role !== "superadmin") {
    throw new Error("Forbidden");
  }
  return { userId, user };
}

// GOOD: Role escalation prevention
async function setUserRole(ctx, args) {
  // Require explicit confirmation token
  if (args.confirmAction !== "CONFIRM_ROLE_CHANGE") {
    throw new Error("Sensitive action requires confirmation");
  }

  const { user: adminUser } = await requireAdmin(ctx, args.sessionToken);

  // Only superadmins can grant admin privileges
  if ((args.role === "admin" || args.role === "superadmin")
      && adminUser.role !== "superadmin") {
    throw new Error("Only superadmins can grant admin privileges");
  }

  // Cannot change your own role
  if (targetUser.id === adminUser.id) {
    throw new Error("Cannot change your own role");
  }

  // Cannot modify superadmin roles (unless you're superadmin)
  if (targetUser.role === "superadmin" && adminUser.role !== "superadmin") {
    throw new Error("Cannot change superadmin role");
  }

  // Apply change
  await db.patch(targetUser._id, { role: args.role });

  // Invalidate all sessions â€” forces re-authentication with new role
  const sessions = await db.query("sessions")
    .withIndex("by_user", (q) => q.eq("userId", args.targetUserId))
    .collect();
  for (const session of sessions) {
    await db.delete(session._id);
  }
}

// GOOD: Multi-level project access with role-based permissions
async function requireProjectAccess(ctx, projectId, userId) {
  const project = await ctx.db.get(projectId);
  if (!project) throw new Error("Not found");

  // Owner always has full access
  if (project.userId === userId) return { role: "owner" };

  // Check team membership â€” only active members
  const member = await ctx.db.query("teamMembers")
    .withIndex("by_project_member", (q) =>
      q.eq("projectId", projectId).eq("memberAuthId", userId))
    .first();

  if (member && member.status === "active") {
    return { role: member.role }; // "member" or "viewer"
  }

  throw new Error("Forbidden");
}

// GOOD: Confirmation tokens for sensitive admin actions
// banUser requires confirmAction: "CONFIRM_BAN"
// unbanUser requires confirmAction: "CONFIRM_UNBAN"
// setUserRole requires confirmAction: "CONFIRM_ROLE_CHANGE"
```

### Quick Fixes

- Add server-side role checks to every admin endpoint (never rely on UI-only checks)
- Implement role hierarchy protection (admin can't modify superadmin)
- Require confirmation tokens for destructive admin actions
- Prevent self-role-modification
- Invalidate all user sessions when their role changes
- Log all admin actions to a separate audit trail
