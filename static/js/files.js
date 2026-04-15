// Delete confirmation modal
let deleteFormId = null;

document.querySelectorAll('.delete-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
        deleteFormId = this.dataset.formId;
        document.getElementById('deleteFileName').textContent = this.dataset.fileName;
        new bootstrap.Modal(document.getElementById('deleteModal')).show();
    });
});

document.getElementById('confirmDeleteBtn').addEventListener('click', function() {
    if (deleteFormId) {
        document.getElementById(deleteFormId).submit();
    }
});

// Passkey management
(async () => {
    const listEl   = document.getElementById('passkey-list');
    const statusEl = document.getElementById('passkey-status');

    if (!passkeySupported()) {
        document.getElementById('add-passkey-btn').disabled = true;
        document.getElementById('add-passkey-btn').title    = 'Your browser does not support passkeys';
        return;
    }

    document.getElementById('add-passkey-btn').addEventListener('click', async () => {
        const name = prompt('Name this passkey (e.g. "MacBook Touch ID"):', 'My passkey');
        if (!name) return;

        statusEl.innerHTML = '<span class="text-muted small">Creating passkey…</span>';
        try {
            const result = await registerPasskey(name.trim() || 'My passkey');
            statusEl.innerHTML =
                `<span class="text-success small">✓ Passkey "<strong>${result.name}</strong>" registered. Refresh to see it in the list.</span>`;
        } catch (err) {
            statusEl.innerHTML =
                `<span class="text-danger small">✗ ${err.message}</span>`;
        }
    });
})();
