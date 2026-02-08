/* ==========================================================================
   Network Optimizer Pro – Main JavaScript
   ========================================================================== */

/**
 * Show loading overlay with optional message.
 * @param {string} [msg]
 */
function showLoading(msg) {
    const overlay = document.getElementById('loading-overlay');
    const text = document.getElementById('loading-text');
    if (text && msg) text.textContent = msg;
    if (overlay) overlay.classList.remove('hidden');
}

/** Hide loading overlay. */
function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) overlay.classList.add('hidden');
}

/**
 * POST request helper.
 * @param {string} url
 * @param {object} [body]
 * @returns {Promise<object>}
 */
async function apiPost(url, body) {
    const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined,
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
}

/**
 * GET request helper.
 * @param {string} url
 * @returns {Promise<object>}
 */
async function apiGet(url) {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
}

/**
 * Toggle restricted network mode.
 */
async function toggleRestricted() {
    const cb = document.getElementById('restrictedMode');
    try {
        await apiPost('/api/settings', { restricted_mode: cb.checked });
    } catch (e) {
        console.error('Failed to toggle restricted mode:', e);
    }
}

/**
 * Sort a table by column index (simple string/number sort).
 * @param {string} tableId
 * @param {number} colIndex
 */
function sortTable(tableId, colIndex) {
    const table = document.getElementById(tableId);
    if (!table) return;
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    // Determine current sort direction
    const th = table.querySelectorAll('th')[colIndex];
    const asc = th.dataset.sort !== 'asc';
    // Reset all
    table.querySelectorAll('th').forEach(h => delete h.dataset.sort);
    th.dataset.sort = asc ? 'asc' : 'desc';

    rows.sort((a, b) => {
        const aVal = a.cells[colIndex]?.textContent.trim() || '';
        const bVal = b.cells[colIndex]?.textContent.trim() || '';
        const aNum = parseFloat(aVal);
        const bNum = parseFloat(bVal);

        if (!isNaN(aNum) && !isNaN(bNum)) {
            return asc ? aNum - bNum : bNum - aNum;
        }
        return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
    });

    rows.forEach(row => tbody.appendChild(row));
}

// Load restricted mode setting on page load
document.addEventListener('DOMContentLoaded', async () => {
    try {
        const settings = await apiGet('/api/settings');
        const cb = document.getElementById('restrictedMode');
        if (cb) cb.checked = settings.restricted_mode;
    } catch (e) {
        // Ignore – settings will use defaults
    }
});
