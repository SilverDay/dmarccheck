/*
 * WebAuthn (passkey) browser glue. Vanilla JS, no build step, matching the
 * project's no-framework convention. Talks to server endpoints that emit
 * webauthn-lib's PublicKeyCredentialCreationOptions/RequestOptions JSON
 * (base64url-encoded binary fields) and expects the credential response
 * back in the shape webauthn-lib's PublicKeyCredentialDenormalizer reads:
 * { id, rawId, type, response: { ... } }, all binary fields base64url.
 */
(function () {
    function b64urlToBytes(b64url) {
        const pad = '='.repeat((4 - (b64url.length % 4)) % 4);
        const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
        const raw = atob(b64);
        const bytes = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) {
            bytes[i] = raw.charCodeAt(i);
        }
        return bytes;
    }

    function bytesToB64url(buf) {
        const bytes = new Uint8Array(buf);
        let bin = '';
        for (let i = 0; i < bytes.length; i++) {
            bin += String.fromCharCode(bytes[i]);
        }
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function decodeCreationOptions(o) {
        o.challenge = b64urlToBytes(o.challenge);
        o.user.id = b64urlToBytes(o.user.id);
        (o.excludeCredentials || []).forEach(function (c) { c.id = b64urlToBytes(c.id); });
        return o;
    }

    function decodeRequestOptions(o) {
        o.challenge = b64urlToBytes(o.challenge);
        (o.allowCredentials || []).forEach(function (c) { c.id = b64urlToBytes(c.id); });
        return o;
    }

    function encodeAttestationCredential(cred) {
        const idB64 = bytesToB64url(cred.rawId);
        return {
            id: idB64,
            rawId: idB64,
            type: cred.type,
            response: {
                clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
                attestationObject: bytesToB64url(cred.response.attestationObject),
                transports: (cred.response.getTransports && cred.response.getTransports()) || [],
            },
        };
    }

    function encodeAssertionCredential(cred) {
        const idB64 = bytesToB64url(cred.rawId);
        return {
            id: idB64,
            rawId: idB64,
            type: cred.type,
            response: {
                clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
                authenticatorData: bytesToB64url(cred.response.authenticatorData),
                signature: bytesToB64url(cred.response.signature),
                userHandle: cred.response.userHandle ? bytesToB64url(cred.response.userHandle) : null,
            },
        };
    }

    async function register(optionsJson) {
        const options = decodeCreationOptions(JSON.parse(optionsJson));
        const cred = await navigator.credentials.create({ publicKey: options });
        return JSON.stringify(encodeAttestationCredential(cred));
    }

    async function authenticate(optionsJson) {
        const options = decodeRequestOptions(JSON.parse(optionsJson));
        const cred = await navigator.credentials.get({ publicKey: options });
        return JSON.stringify(encodeAssertionCredential(cred));
    }

    window.DmarcWebauthn = { register: register, authenticate: authenticate };

    /*
     * Generic button wiring — a button with data-webauthn="register" or
     * "authenticate", data-options-url, data-verify-url, and optionally
     * data-extra-fields="field1,field2" (form field names to forward to
     * both endpoints, e.g. email or an invite token) and
     * data-error-target (CSS selector, default #webauthn-error).
     *
     * options-url is POSTed to and must return the options JSON directly.
     * verify-url is POSTed to (extra fields + "credential" + "label", if a
     * [name=passkey_label] field exists) and must return
     * {"ok":true,"redirect":"..."} or {"ok":false,"error":"..."}.
     */
    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('[data-webauthn]').forEach(function (button) {
            button.addEventListener('click', function (event) {
                event.preventDefault();
                runCeremony(button).catch(function (err) {
                    const errorEl = resolveErrorTarget(button);
                    if (errorEl) {
                        errorEl.textContent = err.message || String(err);
                    }
                });
            });
        });
    });

    function resolveErrorTarget(button) {
        return document.querySelector(button.dataset.errorTarget || '#webauthn-error');
    }

    /*
     * Step-up re-verification (spec §15.4/§15.5), used two ways:
     *
     * 1. A <form data-step-up-passkey ...> whose action needs step-up: the
     *    submit is intercepted, the ceremony runs against
     *    /account/stepup/passkey/*, and only on success is the *same* form
     *    resubmitted natively — so the actor sees one native passkey prompt
     *    at the moment they take the action, then the normal server
     *    response (redirect + flash message) for that action, never a
     *    detour through a separate "verify first" page or step.
     * 2. A [data-webauthn] button that ALSO carries data-step-up-passkey
     *    (only "Add a passkey": creating a second credential is itself
     *    step-up-gated, spec §15.5) — runCeremony() below runs this first,
     *    before its own register/authenticate ceremony, composing two
     *    native prompts back to back.
     */
    async function runStepUpCeremony() {
        const csrfInput = document.querySelector('[name="csrf_token"]');
        const csrfFields = csrfInput ? { csrf_token: csrfInput.value } : {};

        const optionsResp = await fetch('/account/stepup/passkey/options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams(csrfFields),
            credentials: 'same-origin',
        });

        if (!optionsResp.ok) {
            throw new Error('Could not start passkey verification.');
        }

        const optionsJson = await optionsResp.text();
        const credentialJson = await authenticate(optionsJson);

        const verifyBody = new URLSearchParams(csrfFields);
        verifyBody.set('credential', credentialJson);

        const verifyResp = await fetch('/account/stepup/passkey/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: verifyBody,
            credentials: 'same-origin',
        });
        const verifyJson = await verifyResp.json();

        if (!verifyResp.ok || !verifyJson.ok) {
            throw new Error(verifyJson.error || 'Passkey verification failed.');
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('form[data-step-up-passkey]').forEach(function (form) {
            form.addEventListener('submit', function (event) {
                event.preventDefault();

                const errorEl = form.querySelector('.step-up-error');
                if (errorEl) {
                    errorEl.textContent = '';
                }

                const submitBtn = form.querySelector('button[type="submit"]');
                if (submitBtn) {
                    submitBtn.disabled = true;
                }

                runStepUpCeremony().then(function () {
                    form.submit();
                }).catch(function (err) {
                    if (errorEl) {
                        errorEl.textContent = err.message || String(err);
                    }
                    if (submitBtn) {
                        submitBtn.disabled = false;
                    }
                });
            });
        });
    });

    async function runCeremony(button) {
        const errorEl = resolveErrorTarget(button);
        if (errorEl) {
            errorEl.textContent = '';
        }
        button.disabled = true;

        try {
            if (button.hasAttribute('data-step-up-passkey')) {
                await runStepUpCeremony();
            }

            const fieldNames = (button.dataset.extraFields || '').split(',').map(function (s) {
                return s.trim();
            }).filter(Boolean);

            const fields = {};
            fieldNames.forEach(function (name) {
                const el = document.querySelector('[name="' + name + '"]');
                if (el) {
                    fields[name] = el.value;
                }
            });

            const missing = fieldNames.filter(function (name) { return !fields[name]; });
            if (missing.length > 0) {
                throw new Error('Enter your email above first.');
            }

            const csrfInput = document.querySelector('[name="csrf_token"]');
            if (csrfInput) {
                fields.csrf_token = csrfInput.value;
            }

            const optionsBody = new URLSearchParams(fields);
            const optionsResp = await fetch(button.dataset.optionsUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: optionsBody,
                credentials: 'same-origin',
            });

            if (!optionsResp.ok) {
                throw new Error('Could not start the passkey ceremony.');
            }

            const optionsJson = await optionsResp.text();
            const credentialJson = button.dataset.webauthn === 'register'
                ? await register(optionsJson)
                : await authenticate(optionsJson);

            const verifyBody = new URLSearchParams(fields);
            verifyBody.set('credential', credentialJson);
            const labelInput = document.querySelector('[name="passkey_label"]');
            if (labelInput) {
                verifyBody.set('label', labelInput.value);
            }

            const verifyResp = await fetch(button.dataset.verifyUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: verifyBody,
                credentials: 'same-origin',
            });
            const verifyJson = await verifyResp.json();

            if (!verifyResp.ok || !verifyJson.ok) {
                throw new Error(verifyJson.error || 'Passkey verification failed.');
            }

            window.location = verifyJson.redirect || '/';
        } finally {
            button.disabled = false;
        }
    }
})();
