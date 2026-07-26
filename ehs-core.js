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
      first_name: (profile && profile.first_name) || meta.first_name || '',
      last_name: (profile && profile.last_name) || meta.last_name || '',
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
  async function addUser(email, fullName, grants, password, isMaster, requireChange, firstName, lastName) {
    return adminUser('create', {
      email, full_name: fullName, first_name: firstName, last_name: lastName, grants: grants || [],
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
  // master edits another user's name / email (auth identity + profile)
  async function updateUser(userId, patch) { return adminUser('update_user', Object.assign({ user_id: userId }, patch || {})); }
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
  async function updateMyName(firstName, lastName) {
    const m = await loadMe();
    if (!m) throw new Error('Not signed in');
    const fn = (firstName || '').trim(), ln = (lastName || '').trim();
    const full = (fn + ' ' + ln).trim();
    const { error } = await client().from('profiles')
      .update({ first_name: fn || null, last_name: ln || null, full_name: full }).eq('id', m.id);
    if (error) throw error;
    try { await client().auth.updateUser({ data: { full_name: full, first_name: fn, last_name: ln } }); } catch (e) {}
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

  /* ---------------- shared top nav (Phase 1) ----------------
     One nav for every tool. Markup lives here so it can't drift; each page
     wires its own actions via configureNav(), with URL-based defaults so a
     brand-new tool works with zero wiring. */
  let _navCfg = {};
  function configureNav(cfg) { Object.assign(_navCfg, cfg || {}); }
  function navBrand() { _navCfg.onBrand ? _navCfg.onBrand() : (global.location.href = 'index.html#/'); }
  function navUsers() { _navCfg.onUsers ? _navCfg.onUsers() : (global.location.href = 'index.html#/people'); }
  function navTools(e) { if (_navCfg.onTools) return _navCfg.onTools(e); }
  function navAccount(e) { if (_navCfg.onAccount) return _navCfg.onAccount(e); }
  function navBell(e) { if (_navCfg.onBell) return _navCfg.onBell(e); }
  function injectNavCSS() {
    if (typeof document === 'undefined' || document.getElementById('ehs-nav-css')) return;
    const s = document.createElement('style'); s.id = 'ehs-nav-css';
    s.textContent = '.ehsnav{height:60px;background:var(--surface);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:16px;padding:0 24px;flex:none}.ehsnav.sticky{position:sticky;top:0;z-index:40}.ehsnav .tb-brand{display:flex;align-items:center;gap:11px;cursor:pointer;text-decoration:none;flex:none}.ehsnav .ehs-logo{display:block;height:24px;width:auto;flex:none}.ehsnav .tb-glyph{width:30px;height:30px;flex:none;display:grid;place-items:center;border-radius:999px !important;background:var(--surface-3);color:var(--ink-2);overflow:hidden}.ehsnav .tb-glyph svg{width:18px;height:18px;display:block;margin-top:1px}.ehsnav .tb-glyph img{width:100%;height:100%;object-fit:cover;display:block;border-radius:999px !important}.ehsnav .tb-spacer{flex:1}.ehsnav .tb-link{display:inline-flex;align-items:center;gap:7px;font-family:inherit;font-size:12.5px;font-weight:600;color:var(--ink-2);padding:7px 11px;border:0;background:none;border-radius:8px !important;cursor:pointer;transition:background .12s}.ehsnav .tb-link:hover{color:var(--ink)}.ehsnav .tb-link.on{color:var(--accent)}.ehsnav .tb-tools-wrap,.ehsnav .notif-wrap,.ehsnav .acct-wrap{position:relative;flex:none}.ehsnav .tb-acct{display:flex;align-items:center;gap:9px;padding:6px 8px;border:0;background:none;border-radius:8px !important;cursor:pointer;font-family:inherit;transition:background .12s}.ehsnav .tb-acct:hover{background:transparent}.ehsnav .tb-acct .who{font-weight:600;font-size:12.5px;line-height:1.2;text-align:left;color:var(--ink)}.ehsnav .tb-acct .role{font-size:11px;color:var(--muted);text-align:left}.ehsnav .tn-acct-txt{display:flex;flex-direction:column;align-items:flex-start;line-height:1.15}.ehsnav .tb-bell{position:relative;flex:none;width:36px;height:36px;display:grid;place-items:center;border:0;background:none;border-radius:999px !important;color:var(--ink-2,#3A3F47);cursor:pointer;margin-right:2px}.ehsnav .tb-bell:hover{background:var(--surface-2,#F6F7F9)}.ehsnav .tb-bell-badge{position:absolute;top:3px;right:3px;min-width:15px;height:15px;padding:0 3px;border-radius:999px !important;background:#E24B4A;color:#fff;font-size:9px;font-weight:700;display:grid;place-items:center;line-height:1;border:1.5px solid var(--surface,#fff);box-sizing:content-box}';
    document.head.appendChild(s);
  }
  const _NAV_GLYPH = '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="8.2" r="3.9"/><path d="M12 13.4c-4.1 0-7.4 2.6-7.4 5.9 0 .4.3.7.7.7h13.4c.4 0 .7-.3.7-.7 0-3.3-3.3-5.9-7.4-5.9Z"/></svg>';
  function _navEsc(s) { return (s == null ? '' : String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
  function navHTML(opts) {
    opts = opts || {};
    injectNavCSS();
    const u = me() || {};
    const master = isMaster();
    const dn = opts.name || (u.full_name && u.full_name.trim()) || (u.email || '').split('@')[0] || 'Account';
    const photo = opts.photo || u.avatar_url || null;
    const logo = opts.logo || cfg.logo || '';
    const grid = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>';
    const usersIc = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/></svg>';
    const chev = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6"/></svg>';
    const usersActive = (global.location.hash || '').includes('people');
    const bell = opts.showBell ? `<button class="tb-bell" onclick="EHS.navBell(event)" title="Notifications"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg>${(opts.bellCount > 0) ? `<span class="tb-bell-badge" id="ehsBellBadge">${opts.bellCount > 99 ? '99+' : opts.bellCount}</span>` : ''}</button>` : '';
    return `<div class="ehsnav${opts.sticky === false ? '' : ' sticky'}">
      <div class="tb-brand" onclick="EHS.navBrand()"><img class="ehs-logo" src="${_navEsc(logo)}" alt="EduHubSpot"></div>
      <div class="tb-spacer"></div>
      <div class="tb-tools-wrap">
        <div class="tb-link" id="tbTools" onclick="EHS.navTools(event)">${grid} All tools ${chev}</div>
        <div class="tb-tools-menu" id="tbToolsMenu"></div>
      </div>
      ${master ? `<div class="tb-link ${usersActive ? 'on' : ''}" onclick="EHS.navUsers()">${usersIc} Users</div>` : ''}
      ${opts.extra || ''}
      ${bell}
      <div class="tb-acct" onclick="EHS.navAccount(event)"><span class="tb-glyph">${photo ? `<img src="${_navEsc(photo)}" alt="${_navEsc(dn)}">` : _NAV_GLYPH}</span>
        <div><div class="who">${_navEsc(dn)}</div><div class="role">${master ? 'Master Admin' : 'Member'}</div></div>${chev}</div>
    </div>`;
  }

  global.EHS = {
    configured, client, getSession, signIn, signOut, requireSession,
    loadMe, me, isMaster, roleInTool, canAccessTool, myToolIds,
    listUsers, grantAccess, revokeAccess, setMaster, fieldPerms,
    adminUser, addUser, inviteUser, deleteUser, updateUser, resetPassword,
    updateMyName, changePassword, updateMyPhoto, photoMap,
    configureNav, navHTML, navBrand, navUsers, navTools, navAccount, navBell, injectNavCSS,
  };
})(window);
