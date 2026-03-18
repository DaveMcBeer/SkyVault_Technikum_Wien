/*
 * static/js/webauthn.js
 * FIDO2 / WebAuthn helpers for SkyVault
 * Uses @simplewebauthn/browser v13 via unpkg (loaded in base.html)
 */

// ── Feature detection ────────────────────────────────────────

/**
 * Returns true if the browser supports WebAuthn at all.
 * Use this to decide whether to show the passkey UI.
 */
function passkeySupported() {
  return (
    typeof window !== 'undefined' &&
    window.PublicKeyCredential !== undefined &&
    typeof window.PublicKeyCredential === 'function'
  );
}

/**
 * Returns a promise that resolves to true if the platform authenticator
 * (Touch ID, Face ID, Windows Hello) is available on this device.
 */
async function platformAuthenticatorAvailable() {
  if (!passkeySupported()) return false;
  try {
    return await window.PublicKeyCredential
      .isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

// ── Registration ─────────────────────────────────────────────

/**
 * Run the full passkey registration ceremony.
 * @param {string} keyName  - User-friendly label e.g. "MacBook Touch ID"
 * @returns {Promise<{status: string, name: string}>}
 */
async function registerPasskey(keyName = 'My passkey') {
  // 1. Fetch options from the server
  const beginResp = await fetch('/webauthn/register/begin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
  });
  if (!beginResp.ok) {
    const err = await beginResp.json().catch(() => ({}));
    throw new Error(err.error || `Server error ${beginResp.status}`);
  }
  const optionsJSON = await beginResp.json();

  // 2. Call the authenticator — SimpleWebAuthn handles ArrayBuffer conversion
  let credential;
  try {
    credential = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON });
  } catch (err) {
    if (err.name === 'NotAllowedError') {
      throw new Error('Passkey creation was cancelled or timed out.');
    }
    throw err;
  }

  // 3. Send the credential back for server verification
  const completeResp = await fetch('/webauthn/register/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ credential, name: keyName }),
  });
  const result = await completeResp.json();
  if (!completeResp.ok || result.error) {
    throw new Error(result.error || `Server error ${completeResp.status}`);
  }
  return result;
}

// ── Authentication ────────────────────────────────────────────

/**
 * Run the full passkey authentication ceremony.
 * @param {string} username - The username typed in the login form
 * @returns {Promise<{status: string, redirect: string}>}
 */
async function loginWithPasskey(username) {
  if (!username) throw new Error('Enter your username first.');

  // 1. Fetch a challenge bound to this user's credentials
  const beginResp = await fetch('/webauthn/login/begin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ username }),
  });
  if (!beginResp.ok) {
    const err = await beginResp.json().catch(() => ({}));
    throw new Error(err.error || `Server error ${beginResp.status}`);
  }
  const optionsJSON = await beginResp.json();

  // 2. Ask the authenticator to sign the challenge
  let credential;
  try {
    credential = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON });
  } catch (err) {
    if (err.name === 'NotAllowedError') {
      throw new Error('Passkey sign-in was cancelled or timed out.');
    }
    throw err;
  }

  // 3. Verify the signature on the server
  const completeResp = await fetch('/webauthn/login/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ credential }),
  });
  const result = await completeResp.json();
  if (!completeResp.ok || result.error) {
    throw new Error(result.error || `Server error ${completeResp.status}`);
  }
  if (result.redirect) {
    window.location.href = result.redirect;
  }
  return result;
}
