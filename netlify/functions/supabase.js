// netlify/functions/supabase.js
// Proxies all Supabase auth and data operations
// Credentials never touch the frontend

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

exports.handler = async function(event) {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  let body;
  try {
    body = JSON.parse(event.body);
  } catch(e) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const { action, email, password, token, payload } = body;

  try {
    let result;

    // ── AUTH: SIGN UP ─────────────────────────────────────────
    if (action === 'signup') {
      const res = await fetch(`${SUPABASE_URL}/auth/v1/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_ANON_KEY
        },
        body: JSON.stringify({ email, password })
      });
      result = await res.json();
      return { statusCode: res.status, headers, body: JSON.stringify(result) };
    }

    // ── AUTH: SIGN IN ─────────────────────────────────────────
    if (action === 'signin') {
      const res = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_ANON_KEY
        },
        body: JSON.stringify({ email, password })
      });
      result = await res.json();
      return { statusCode: res.status, headers, body: JSON.stringify(result) };
    }

    // ── AUTH: SIGN OUT ────────────────────────────────────────
    if (action === 'signout') {
      const res = await fetch(`${SUPABASE_URL}/auth/v1/logout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_ANON_KEY,
          'Authorization': `Bearer ${token}`
        }
      });
      return { statusCode: res.status, headers, body: JSON.stringify({ success: true }) };
    }

    // ── DATA: LOAD ────────────────────────────────────────────
    if (action === 'load') {
      const res = await fetch(`${SUPABASE_URL}/rest/v1/user_data?select=payload`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_ANON_KEY,
          'Authorization': `Bearer ${token}`
        }
      });
      const rows = await res.json();
      if (!res.ok) return { statusCode: res.status, headers, body: JSON.stringify(rows) };
      // Return payload or null if no row yet
      const data = rows.length > 0 ? rows[0].payload : null;
      return { statusCode: 200, headers, body: JSON.stringify({ data }) };
    }

    // ── DATA: SAVE (upsert) ───────────────────────────────────
    if (action === 'save') {
      // Decode user_id from JWT token payload (middle segment)
      let user_id;
      try {
        const jwtPayload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
        user_id = jwtPayload.sub;
      } catch(e) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid token' }) };
      }

      const res = await fetch(`${SUPABASE_URL}/rest/v1/user_data`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_ANON_KEY,
          'Authorization': `Bearer ${token}`,
          'Prefer': 'resolution=merge-duplicates'
        },
        body: JSON.stringify({
          user_id,
          payload,
          updated_at: new Date().toISOString()
        })
      });
      if (!res.ok) {
        const err = await res.json();
        return { statusCode: res.status, headers, body: JSON.stringify(err) };
      }
      return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
    }

    // ── AUTH: PASSWORD RESET ─────────────────────────────────
    if (action === 'resetpassword') {
      const res = await fetch(`${SUPABASE_URL}/auth/v1/recover`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_ANON_KEY
        },
        body: JSON.stringify({ email })
      });
      // Always return 200 — Supabase doesn't reveal if email exists
      return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
    }

    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Unknown action' }) };

  } catch(err) {
    console.error('Supabase proxy error:', err);
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
