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
      client().from('profiles').select('*').eq('id', uid).maybeSingle(),
      client().from('tool_access').select('tool_id, role').eq('user_id', uid),
    ]);
    const meta = (s.user && s.user.user_metadata) || {};
    _me = {
      id: uid,
      email: s.user.email,
      full_name: (profile && profile.full_name) || meta.full_name || '',
      is_master_admin: !!(profile && profile.is_master_admin),
      status: (profile && profile.status) || 'active',
      avatar_url: (profile && profile.avatar_url) || null,
      // admin-user stores this on the auth user when it generates a temp password.
      // Without it, index.html's `if (EHS.me().must_change)` was always false and
      // the forced password change never happened.
      must_change: !!meta.must_change_pw,
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
  // Master-only. Goes through the Edge Function so profiles/tool_access can stay
  // locked down by RLS (a direct select here would need them world-readable).
  async function listUsers() {
    const out = await adminUser('list_users', {});
    return (out && out.users) || [];
  }
  // SECURITY: must stay server-side. When this wrote to tool_access directly,
  // any signed-in user could run EHS.grantAccess(myId,'pm','admin') from the
  // console and become a PM admin. The Edge Function verifies Master Admin.
  async function grantAccess(userId, toolId, role) {
    await adminUser('grant_access', { user_id: userId, tool_id: toolId, role });
  }
  async function revokeAccess(userId, toolId) {
    await adminUser('revoke_access', { user_id: userId, tool_id: toolId });
  }
  // SECURITY: must stay server-side. This used to update profiles directly, so
  // ANY signed-in user could call EHS.setMaster(theirOwnId, true) and become a
  // Master Admin. The Edge Function verifies the caller is already a master.
  async function setMaster(userId, val) {
    await adminUser('set_master', { user_id: userId, value: !!val });
  }
  // ---- admin-user Edge Function (service role stays server-side) ----
  // Actions: list_users | create | reset | delete | set_master (Master only)
  //          grant_access | revoke_access (Master or an admin of that tool)
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
  async function addUser(email, fullName, grants, password, isMaster, requireChange) {
    return adminUser('create', {
      email, full_name: fullName, grants: grants || [],
      password: password || undefined,
      is_master: !!isMaster,
      // honour an explicit choice; default to forcing a change only when we auto-generate the pw
      require_change: (requireChange === undefined) ? !password : !!requireChange,
    });
  }
  // back-compat: invite == create with a forced password change
  async function inviteUser(email, fullName, grants) {
    return adminUser('create', { email, full_name: fullName, grants: grants || [], require_change: true });
  }
  async function deleteUser(userId) { return adminUser('delete', { user_id: userId }); }
  // index.html calls resetPassword(id, pw, requireChange) — the 3rd argument was
  // being dropped, so "require a password change" was ignored whenever an admin
  // typed an explicit password. Harmless while must_change was broken; not now.
  async function resetPassword(userId, password, requireChange) {
    return adminUser('reset', {
      user_id: userId,
      password: password || undefined,
      require_change: (requireChange === undefined) ? !password : !!requireChange,
    });
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
  // ---- profile photo (Supabase Storage, not localStorage) ----
  // Accepts a Blob/File, or a data: URL (what the croppers produce).
  // Uploads to  avatars/<uid>.jpg  and stores the public URL on the profile,
  // so every tool that loads profiles gets the photo for free.
  function _toBlob(input) {
    if (input instanceof Blob) return input;
    const s = String(input || '');
    const m = /^data:([^;]+);base64,(.*)$/.exec(s);
    if (!m) throw new Error('Unsupported image input');
    const bin = atob(m[2]);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return new Blob([buf], { type: m[1] });
  }
  async function updateMyPhoto(input) {
    const m = await loadMe();
    if (!m) throw new Error('Not signed in');

    // null / empty clears the photo
    if (!input) {
      try { await client().storage.from('avatars').remove([m.id + '.jpg']); } catch (e) {}
      const { error } = await client().from('profiles').update({ avatar_url: null }).eq('id', m.id);
      if (error) throw error;
      _me = null;
      return null;
    }

    const blob = _toBlob(input);
    if (blob.size > 2 * 1024 * 1024) throw new Error('Image is too large (max 2 MB)');

    const path = m.id + '.jpg';
    const up = await client().storage.from('avatars')
      .upload(path, blob, { upsert: true, contentType: blob.type || 'image/jpeg', cacheControl: '3600' });
    if (up.error) throw up.error;

    const { data: pub } = client().storage.from('avatars').getPublicUrl(path);
    // cache-bust so a replaced photo shows immediately rather than the old one
    const url = pub.publicUrl + '?v=' + Date.now();

    const { error } = await client().from('profiles').update({ avatar_url: url }).eq('id', m.id);
    if (error) throw error;
    _me = null;                          // force a fresh loadMe
    return url;
  }
  // everyone's photo, for rosters and pickers: { <uid>: url }
  async function photoMap() {
    const { data, error } = await client().from('profiles').select('id, email, avatar_url');
    if (error) throw error;
    const byId = {}, byEmail = {};
    (data || []).forEach(p => {
      if (!p.avatar_url) return;
      byId[p.id] = p.avatar_url;
      if (p.email) byEmail[String(p.email).toLowerCase()] = p.avatar_url;
    });
    return { byId, byEmail };
  }

  async function changePassword(newPassword) {
    const { error } = await client().auth.updateUser({
      password: newPassword,
      data: { must_change_pw: false },   // clear the forced-reset flag
    });
    if (error) throw error;
    _me = null;                          // force a fresh loadMe
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
    updateMyName, changePassword, updateMyPhoto, photoMap,
  };
})(window);
