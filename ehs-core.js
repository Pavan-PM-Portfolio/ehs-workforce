/* =====================================================================
   ehs-core.js — shared client for EHS Workspace
   Loaded by index.html (the shell) and, from Phase 5, by every tool.
   Provides ONE Supabase connection, the auth/session guard, and the
   access + permission API. All the permission logic lives server-side
   (schema.sql); this file just calls it.

   Requires, before this script:
     <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
     <script>window.EHS_CONFIG = { url:'...', anon:'...' };</script>
   ===================================================================== */
(function (global) {
  const cfg = global.EHS_CONFIG || {};
  let sb = null;
  let _me = null;

  function configured() { return !!(global.supabase && cfg.url && cfg.anon); }

  function client() {
    if (sb) return sb;
    if (!configured()) {
      throw new Error('EHS not configured — set window.EHS_CONFIG {url, anon} and include supabase-js before ehs-core.js.');
    }
    sb = global.supabase.createClient(cfg.url, cfg.anon);
    return sb;
  }

  /* ---------------- auth / session ---------------- */
  async function getSession() {
    const { data, error } = await client().auth.getSession();
    if (error) throw error;
    return data.session;
  }
  async function signIn(email, password) {
    return client().auth.signInWithPassword({ email, password });
  }
  async function signOut() {
    try { await client().auth.signOut(); } catch (e) {}
    _me = null;
  }
  // For tools (Phase 5): bounce to the shell login if there's no session.
  async function requireSession(loginUrl) {
    const s = await getSession();
    if (!s) { global.location.href = loginUrl || 'index.html'; return null; }
    return s;
  }

  /* ---------------- who am I ---------------- */
  async function loadMe(force) {
    if (_me && !force) return _me;
    const s = await getSession();
    if (!s) { _me = null; return null; }
    const uid = s.user.id;
    const [{ data: profile }, { data: access }] = await Promise.all([
      client().from('profiles').select('*').eq('id', uid).single(),
      client().from('tool_access').select('tool_id, role').eq('user_id', uid),
    ]);
    _me = {
      id: uid,
      email: s.user.email,
      full_name: (profile && profile.full_name) || '',
      is_master_admin: !!(profile && profile.is_master_admin),
      status: (profile && profile.status) || 'active',
      access: access || [],
    };
    return _me;
  }
  function me() { return _me; }
  function isMaster() { return !!(_me && _me.is_master_admin); }
  function roleInTool(toolId) {
    if (isMaster()) return 'admin';
    const a = _me && _me.access.find(x => x.tool_id === toolId);
    return a ? a.role : null;
  }
  function canAccessTool(toolId) { return isMaster() || !!roleInTool(toolId); }
  // ids of tools this user may see (master sees all supplied ids)
  function myToolIds(allIds) {
    if (isMaster()) return (allIds || []).slice();
    return _me ? _me.access.map(a => a.tool_id) : [];
  }

  /* ---------------- Master Admin: people & access ---------------- */
  async function listUsers() {
    const { data, error } = await client()
      .from('profiles')
      .select('id, full_name, email, is_master_admin, status, tool_access(tool_id, role)')
      .order('created_at', { ascending: true });
    if (error) throw error;
    return data || [];
  }
  async function grantAccess(userId, toolId, role) {
    const { error } = await client()
      .from('tool_access')
      .upsert({ user_id: userId, tool_id: toolId, role }, { onConflict: 'user_id,tool_id' });
    if (error) throw error;
  }
  async function revokeAccess(userId, toolId) {
    const { error } = await client()
      .from('tool_access').delete().eq('user_id', userId).eq('tool_id', toolId);
    if (error) throw error;
  }
  async function setMaster(userId, val) {
    const { error } = await client()
      .from('profiles').update({ is_master_admin: val }).eq('id', userId);
    if (error) throw error;
  }
  // ---- admin-user Edge Function (service role stays server-side) ----
  // Actions: create | reset | set_master | delete  (caller must be Master Admin)
  async function adminUser(action, payload) {
    const s = await getSession();
    const res = await fetch(cfg.url + '/functions/v1/admin-user', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': cfg.anon,
        'Authorization': 'Bearer ' + (s ? s.access_token : ''),
      },
      body: JSON.stringify(Object.assign({ action }, payload || {})),
    });
    const out = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(out.error || (action + ' failed (' + res.status + ')'));
    return out;
  }
  // create a brand-new user (returns { user_id, email, password, generated })
  async function addUser(email, fullName, grants, password, isMaster) {
    return adminUser('create', {
      email, full_name: fullName, grants: grants || [],
      password: password || undefined,
      is_master: !!isMaster,
      require_change: !password,           // force a change only when we auto-generate the pw
    });
  }
  // back-compat: invite == create with a forced password change
  async function inviteUser(email, fullName, grants) {
    return adminUser('create', { email, full_name: fullName, grants: grants || [], require_change: true });
  }
  async function deleteUser(userId) { return adminUser('delete', { user_id: userId }); }
  async function resetPassword(userId, password) {
    return adminUser('reset', { user_id: userId, password: password || undefined, require_change: !password });
  }

  // ---- self-service (signed-in user, no service role needed) ----
  async function updateMyName(name) {
    const m = await loadMe();
    if (!m) throw new Error('Not signed in');
    const { error } = await client().from('profiles').update({ full_name: name }).eq('id', m.id);
    if (error) throw error;
    try { await client().auth.updateUser({ data: { full_name: name } }); } catch (e) {}
    _me = null;                            // force a fresh loadMe next call
  }
  async function changePassword(newPassword) {
    const { error } = await client().auth.updateUser({ password: newPassword });
    if (error) throw error;
  }

  /* ---------------- field permissions (server-resolved) ---------------- */
  // returns { field_key: {read:bool, write:bool}, ... } for the current user in a tool
  async function fieldPerms(toolId) {
    const { data, error } = await client().rpc('my_field_perms', { p_tool: toolId });
    if (error) throw error;
    const map = {};
    (data || []).forEach(r => { map[r.field_key] = { read: r.can_read, write: r.can_write }; });
    return map;
  }

  global.EHS = {
    configured, client, getSession, signIn, signOut, requireSession,
    loadMe, me, isMaster, roleInTool, canAccessTool, myToolIds,
    listUsers, grantAccess, revokeAccess, setMaster, fieldPerms,
    adminUser, addUser, inviteUser, deleteUser, resetPassword,
    updateMyName, changePassword,
  };
})(window);
