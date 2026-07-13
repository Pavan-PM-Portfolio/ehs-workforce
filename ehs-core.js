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
  let _signedOutCb = null;
  function onSignedOut(cb){ _signedOutCb = cb; }

  function configured() { return !!(global.supabase && cfg.url && cfg.anon); }

  function client() {
    if (sb) return sb;
    if (!configured()) {
      throw new Error('EHS not configured — set window.EHS_CONFIG {url, anon} and include supabase-js before ehs-core.js.');
    }
    sb = global.supabase.createClient(cfg.url, cfg.anon);
    // Immediately react to sign-out from any tab/device (fires cross-tab).
    try {
      sb.auth.onAuthStateChange(function (event) {
        if (event === 'SIGNED_OUT') {
          _me = null;
          if (typeof _signedOutCb === 'function') { try { _signedOutCb(); } catch (e) {} }
        }
      });
    } catch (e) {}
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
    // 'global' revokes every session for this user (all tabs & devices).
    try { await client().auth.signOut({ scope: 'global' }); }
    catch (e) { try { await client().auth.signOut(); } catch (_) {} }
    _me = null;
    try { global.localStorage.setItem('ehs:signout', String(Date.now())); } catch (e) {}
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
      must_change: !!(s.user.user_metadata && s.user.user_metadata.must_change_pw),
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
  // privileged Master-Admin actions go through the admin-user Edge Function
  async function adminUser(action, payload) {
    const s = await getSession();
    const res = await fetch(cfg.url + '/functions/v1/admin-user', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + (s ? s.access_token : ''),
      },
      body: JSON.stringify({ action, ...(payload || {}) }),
    });
    const out = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(out.error || (action + ' failed (' + res.status + ')'));
    return out;
  }
  async function setMaster(userId, val) {
    return adminUser('set_master', { user_id: userId, value: !!val });
  }
  async function deleteUser(userId) {
    return adminUser('delete', { user_id: userId });
  }
  // create a brand-new user DIRECTLY (no email invite): master sets/omits a
  // password; the account is created already-confirmed so they can sign in now.
  // returns { ok, user_id, email, password, generated }
  async function addUser(email, fullName, grants, password, isMaster, requireChange) {
    return adminUser('create', {
      email, full_name: fullName, grants: grants || [], password: password || '', is_master: !!isMaster, require_change: !!requireChange,
    });
  }
  // Master Admin: reset another user's password (and optionally force reset on next sign-in)
  async function resetPassword(userId, password, requireChange) {
    return adminUser('reset', { user_id: userId, password: password || '', require_change: !!requireChange });
  }

  /* ---------------- account self-service ---------------- */
  async function updateMyName(fullName) {
    const s = await getSession(); if (!s) throw new Error('Not signed in');
    const { error } = await client().from('profiles').update({ full_name: fullName }).eq('id', s.user.id);
    if (error) throw error;
    try { await client().auth.updateUser({ data: { full_name: fullName } }); } catch (e) {}
    if (_me) _me.full_name = fullName;
  }
  async function changePassword(newPassword) {
    const { error } = await client().auth.updateUser({ password: newPassword, data: { must_change_pw: false } });
    if (error) throw error;
    if (_me) _me.must_change = false;
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
    configured, client, getSession, signIn, signOut, requireSession, onSignedOut,
    loadMe, me, isMaster, roleInTool, canAccessTool, myToolIds,
    listUsers, grantAccess, revokeAccess, setMaster, deleteUser, addUser, resetPassword, updateMyName, changePassword, fieldPerms,
  };
})(window);
