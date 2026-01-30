/**
 * PLDT WiFi Manager - API Client & UI Components
 */

const API_BASE = '/api';



const Toast = {
    container: null,

    init() {
        if (this.container) return;

        this.container = document.createElement('div');
        this.container.id = 'toast-container';
        this.container.style.cssText = `
            position: fixed;
            top: 30px;
            right: 20px;
            z-index: 10000;
            display: flex;
            flex-direction: column;
            gap: 10px;
            pointer-events: none;
        `;
        document.body.appendChild(this.container);
    },

    show(message, type = 'info', duration = 3000) {
        this.init();

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        // Icon based on type
        let icon = '';
        switch (type) {
            case 'loading':
                icon = `<div class="toast-spinner"></div>`;
                break;
            case 'success':
                icon = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
                break;
            case 'error':
                icon = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
                break;
            default:
                icon = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
        }

        toast.innerHTML = `
            <div class="toast-icon">${icon}</div>
            <span class="toast-message">${message}</span>
        `;

        toast.style.cssText = `
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 20px;
            background: ${type === 'success' ? '#4CAF50' : type === 'error' ? '#D2272A' : type === 'loading' ? '#333' : '#666'};
            color: white;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            font-family: 'Montserrat', sans-serif;
            font-size: 14px;
            font-weight: 500;
            pointer-events: auto;
            animation: slideIn 0.3s ease;
            min-width: 250px;
        `;

        this.container.appendChild(toast);

        // Auto remove (except loading toasts)
        if (type !== 'loading' && duration > 0) {
            setTimeout(() => this.remove(toast), duration);
        }

        return toast;
    },

    remove(toast) {
        if (!toast || !toast.parentNode) return;
        toast.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    },

    loading(message) {
        return this.show(message, 'loading', 0);
    },

    success(message, duration = 3000) {
        return this.show(message, 'success', duration);
    },

    error(message, duration = 4000) {
        return this.show(message, 'error', duration);
    },

    info(message, duration = 3000) {
        return this.show(message, 'info', duration);
    }
};

// Add toast animations to document
const toastStyles = document.createElement('style');
toastStyles.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    .toast-spinner {
        width: 20px;
        height: 20px;
        border: 2px solid rgba(255,255,255,0.3);
        border-top-color: white;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
    }
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
`;
document.head.appendChild(toastStyles);



const api = {
    async get(endpoint) {
        try {
            const response = await fetch(`${API_BASE}${endpoint}`);
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            return null;
        }
    },

    async post(endpoint, data) {
        try {
            const response = await fetch(`${API_BASE}${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            return null;
        }
    }
};



const sidebarTemplate = `
    <a href="index.html" class="nav-item" data-page="home">
        <svg xmlns="http://www.w3.org/2000/svg" height="24px" viewBox="0 -960 960 960" width="24px">
            <path d="M480-427ZM240-120q-50 0-85-35t-35-85v-240q0-24 9-46t26-39l240-240q17-18 39.5-26.5T480-840q23 0 45 8.5t40 26.5l240 240q17 17 26 39t9 46v240q0 50-35 85t-85 35H240Zm0-80h480q17 0 28.5-11.5T760-240v-240q0-8-3-15t-9-13L595-662l-59 58 144 144v180H280v-180l258-258-30-30q-8-8-15.5-10t-12.5-2q-5 0-12.5 2T452-748L212-508q-6 6-9 13t-3 15v240q0 17 11.5 28.5T240-200Zm120-160h240v-67L480-547 360-427v67Z"/>
        </svg>
        Home
    </a>
    <a href="settings.html" class="nav-item" data-page="settings">
        <svg xmlns="http://www.w3.org/2000/svg" height="24px" viewBox="0 -960 960 960" width="24px" fill="#e3e3e3"><path d="m370-80-16-128q-13-5-24.5-12T307-235l-119 50L78-375l103-78q-1-7-1-13.5v-27q0-6.5 1-13.5L78-585l110-190 119 50q11-8 23-15t24-12l16-128h220l16 128q13 5 24.5 12t22.5 15l119-50 110 190-103 78q1 7 1 13.5v27q0 6.5-2 13.5l103 78-110 190-118-50q-11 8-23 15t-24 12L590-80H370Zm70-80h79l14-106q31-8 57.5-23.5T639-327l99 41 39-68-86-65q5-14 7-29.5t2-31.5q0-16-2-31.5t-7-29.5l86-65-39-68-99 42q-22-23-48.5-38.5T533-694l-13-106h-79l-14 106q-31 8-57.5 23.5T321-633l-99-41-39 68 86 64q-5 15-7 30t-2 32q0 16 2 31t7 30l-86 65 39 68 99-42q22 23 48.5 38.5T427-266l13 106Zm42-180q58 0 99-41t41-99q0-58-41-99t-99-41q-59 0-99.5 41T342-480q0 58 40.5 99t99.5 41Zm-2-140Z"/></svg>
        Settings
    </a>
`;



async function updateStatus() {
    const data = await api.get('/status');
    if (data) {
        setStatus(data.status);
    }
}

function setStatus(status) {
    const indicator = document.getElementById('statusIndicator');
    if (indicator) {
        indicator.className = `status-indicator ${status}`;
    }
}

// Device Table (Home Page)

let selectedDevices = new Set();
let deviceExpiries = {}; // Store expiry timestamps: { mac: expiryTimestamp }
let countdownInterval = null;

function updateCountdowns() {
    const now = Math.floor(Date.now() / 1000);
    let hasExpired = false;

    document.querySelectorAll('tr[data-mac]').forEach(row => {
        const mac = row.dataset.mac;
        const timeCell = row.children[4]; // Time is 5th column (index 4)
        const statusCell = row.children[6]; // Status is 7th column (index 6)

        if (deviceExpiries[mac]) {
            const remaining = deviceExpiries[mac] - now;
            if (remaining <= 0) {
                timeCell.textContent = 'EXPIRED';
                // Update status dot to red when expired
                const statusDot = statusCell.querySelector('.status-dot');
                if (statusDot && statusDot.classList.contains('green')) {
                    statusDot.classList.remove('green');
                    statusDot.classList.add('red');
                    hasExpired = true;
                }
            } else {
                const hours = Math.floor(remaining / 3600);
                const minutes = Math.floor((remaining % 3600) / 60);
                const seconds = remaining % 60;
                timeCell.textContent = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            }
        }
    });

    // If any device expired, refresh the table after a short delay to sync with server
    if (hasExpired) {
        setTimeout(() => loadDeviceTable(), 2000);
    }
}

// Track if this is the first load (show full overlay) or a refresh (hide overlay)
let isFirstDeviceLoad = true;

function showLoading(status) {
    const overlay = document.getElementById('loadingOverlay');
    const statusEl = document.getElementById('loadingStatus');
    if (overlay) {
        overlay.classList.remove('hidden');
    }
    if (statusEl && status) {
        statusEl.textContent = status;
    }
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    const spinner = document.querySelector('.loading-spinner');
    const statusEl = document.getElementById('loadingStatus');

    if (overlay) {
        overlay.classList.add('hidden');
    }

    // Reset error state for next load
    if (spinner) {
        spinner.classList.remove('error');
        spinner.innerHTML = '';
    }
    if (statusEl) {
        statusEl.classList.remove('error');
    }
}

function updateLoadingStatus(status) {
    const statusEl = document.getElementById('loadingStatus');
    if (statusEl) {
        statusEl.textContent = status;
    }
}

function showLoadingError(message) {
    const spinner = document.querySelector('.loading-spinner');
    const statusEl = document.getElementById('loadingStatus');

    // Replace spinner with X icon
    if (spinner) {
        spinner.classList.add('error');
        spinner.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
    }

    if (statusEl) {
        statusEl.textContent = message;
        statusEl.classList.add('error');
    }
}

async function loadDeviceTable() {
    const tbody = document.getElementById('deviceTableBody');
    if (!tbody) return;

    // Show loading overlay only on first load
    if (isFirstDeviceLoad) {
        // Simulate normal loading progression
        showLoading('Connecting to router...');
        await new Promise(resolve => setTimeout(resolve, 400));
        updateLoadingStatus('Authenticating...');

        // Check status to determine if we can proceed
        const status = await api.get('/status');

        if (!status) {
            showLoadingError('Unable to connect to server');
            await new Promise(resolve => setTimeout(resolve, 1500));
            hideLoading();
            isFirstDeviceLoad = false;
            return;
        }

        if (status.status === 'gray') {
            // No credentials saved
            showLoadingError('No account saved. Please configure credentials in Settings.');
            await new Promise(resolve => setTimeout(resolve, 1500));
            hideLoading();
            isFirstDeviceLoad = false;
            return;
        }

        if (status.status === 'red') {
            // Authentication failed
            showLoadingError('Authentication failed. Please check your credentials in Settings.');
            await new Promise(resolve => setTimeout(resolve, 1500));
            hideLoading();
            isFirstDeviceLoad = false;
            return;
        }

        // Status is green - proceed with loading
        updateLoadingStatus('Fetching connected devices...');
    }

    const devices = await api.get('/devices');

    if (isFirstDeviceLoad) {
        updateLoadingStatus('Processing device data...');
        await new Promise(resolve => setTimeout(resolve, 200));
    }

    if (!devices) {
        if (isFirstDeviceLoad) {
            showLoadingError('Failed to fetch devices');
            await new Promise(resolve => setTimeout(resolve, 1500));
            hideLoading();
            isFirstDeviceLoad = false;
        }
        return;
    }

    // Store expiry timestamps for client-side countdown
    deviceExpiries = {};
    devices.forEach(device => {
        if (device.expires) {
            deviceExpiries[device.mac] = device.expires;
        }
    });

    tbody.innerHTML = devices.map(device => `
        <tr data-mac="${device.mac}" class="${selectedDevices.has(device.mac) ? 'selected' : ''}">
            <td>${device.id}</td>
            <td>${device.name}</td>
            <td>${device.mac}</td>
            <td>${device.ip}</td>
            <td>${device.time}</td>
            <td>${device.connection}</td>
            <td><span class="status-dot ${device.status}"></span></td>
        </tr>
    `).join('');

    // Hide loading overlay after first successful load
    if (isFirstDeviceLoad) {
        updateLoadingStatus('Done!');
        await new Promise(resolve => setTimeout(resolve, 300));
        hideLoading();
        isFirstDeviceLoad = false;
    }

    // Start countdown interval if not already running
    if (!countdownInterval) {
        countdownInterval = setInterval(updateCountdowns, 1000);
    }

    // Add click handlers for selection
    tbody.querySelectorAll('tr').forEach(row => {
        row.addEventListener('click', () => {
            const mac = row.dataset.mac;
            if (selectedDevices.has(mac)) {
                selectedDevices.delete(mac);
                row.classList.remove('selected');
            } else {
                selectedDevices.add(mac);
                row.classList.add('selected');
            }
        });
    });
}

async function connectSelectedDevices() {
    if (selectedDevices.size === 0) {
        Toast.info('Please select at least one device');
        return;
    }

    const count = selectedDevices.size;
    const loadingToast = Toast.loading(`Connecting ${count} device${count > 1 ? 's' : ''}...`);

    let successCount = 0;
    let failCount = 0;

    for (const mac of selectedDevices) {
        // Get device's connection type from the table row (Connection is 6th column, index 5)
        const row = document.querySelector(`tr[data-mac="${mac}"]`);
        const connection = row ? row.children[5].textContent : "";

        const result = await api.post('/devices/connect', { mac, connection });
        if (result && result.success) {
            successCount++;
        } else {
            failCount++;
        }
    }

    Toast.remove(loadingToast);

    if (failCount === 0) {
        Toast.success(`Successfully connected ${successCount} device${successCount > 1 ? 's' : ''}`);
    } else if (successCount === 0) {
        Toast.error(`Failed to connect ${failCount} device${failCount > 1 ? 's' : ''}`);
    } else {
        Toast.info(`Connected ${successCount}, failed ${failCount}`);
    }

    selectedDevices.clear();
    await loadDeviceTable();
}

async function disconnectSelectedDevices() {
    if (selectedDevices.size === 0) {
        Toast.info('Please select at least one device');
        return;
    }

    const count = selectedDevices.size;
    const loadingToast = Toast.loading(`Disconnecting ${count} device${count > 1 ? 's' : ''}...`);

    let successCount = 0;
    let failCount = 0;

    for (const mac of selectedDevices) {
        // Get device's connection type from the table row (Connection is 6th column, index 5)
        const row = document.querySelector(`tr[data-mac="${mac}"]`);
        const connection = row ? row.children[5].textContent : "";

        const result = await api.post('/devices/disconnect', { mac, connection });
        if (result && result.success) {
            successCount++;
        } else {
            failCount++;
        }
    }

    Toast.remove(loadingToast);

    if (failCount === 0) {
        Toast.success(`Successfully disconnected ${successCount} device${successCount > 1 ? 's' : ''}`);
    } else if (successCount === 0) {
        Toast.error(`Failed to disconnect ${failCount} device${failCount > 1 ? 's' : ''}`);
    } else {
        Toast.info(`Disconnected ${successCount}, failed ${failCount}`);
    }

    selectedDevices.clear();
    await loadDeviceTable();
}



async function loadAuthStatus() {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    if (!usernameInput) return;

    const status = await api.get('/auth/status');
    if (status && status.username) {
        usernameInput.value = status.username;
    }
}

async function login() {
    const username = document.getElementById('username')?.value;
    const password = document.getElementById('password')?.value;

    if (!username || !password) {
        Toast.error('Please enter both username and password');
        return;
    }

    // Check if already logged in
    const status = await api.get('/status');
    if (status && status.status === 'green') {
        Toast.info('Already logged in');
        return;
    }

    const loadingToast = Toast.loading('Logging in...');

    const result = await api.post('/auth/login', { username, password });

    Toast.remove(loadingToast);

    if (result && result.success) {
        Toast.success('Login successful! Connected to router.');
        await updateStatus();
    } else {
        // Provide informative error messages
        let errorMessage = 'Login failed';
        if (result?.message) {
            if (result.message.toLowerCase().includes('authentication')) {
                errorMessage = 'Invalid username or password. Please check your credentials.';
            } else if (result.message.toLowerCase().includes('connection') || result.message.toLowerCase().includes('network')) {
                errorMessage = 'Unable to connect to router. Please check your network connection.';
            } else if (result.message.toLowerCase().includes('timeout')) {
                errorMessage = 'Connection timed out. The router may be unreachable.';
            } else {
                errorMessage = result.message;
            }
        }
        Toast.error(errorMessage);
    }
}

async function logout() {
    // Check if already logged out
    const status = await api.get('/status');
    if (status && status.status === 'gray') {
        Toast.info('No account is currently logged in');
        return;
    }

    const loadingToast = Toast.loading('Logging out...');

    await api.post('/auth/logout', {});
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    await updateStatus();

    Toast.remove(loadingToast);
    Toast.success('Logged out successfully');
}



let currentPrivateSsids = [];

async function loadAvailableSsids() {
    const dropdown = document.getElementById('ssidDropdown');
    if (!dropdown) return;

    const data = await api.get('/ssids/available');
    if (!data || !data.ssids) {
        dropdown.innerHTML = '<option value="">No WiFi devices connected</option>';
        dropdown.disabled = true;
        return;
    }

    const ssids = data.ssids;
    if (ssids.length === 0) {
        dropdown.innerHTML = '<option value="">No WiFi devices connected</option>';
        dropdown.disabled = true;
        return;
    }

    dropdown.disabled = false;
    dropdown.innerHTML = '<option value="">-- Select SSID --</option>' +
        ssids.map(ssid => `<option value="${ssid}">${ssid}</option>`).join('');
}

async function loadPrivateSsids() {
    const container = document.getElementById('ssidChipsContainer');
    if (!container) return;

    const data = await api.get('/settings/private-ssids');
    if (!data || !data.private_ssids) {
        currentPrivateSsids = [];
    } else {
        currentPrivateSsids = data.private_ssids;
    }

    renderSsidChips();
}

function renderSsidChips() {
    const container = document.getElementById('ssidChipsContainer');
    if (!container) return;

    if (currentPrivateSsids.length === 0) {
        container.innerHTML = '<span class="ssid-empty-message">No private SSIDs configured</span>';
        return;
    }

    container.innerHTML = currentPrivateSsids.map(ssid => `
        <span class="ssid-chip">
            ${ssid}
            <button class="ssid-chip-remove" data-ssid="${ssid}" title="Remove">&times;</button>
        </span>
    `).join('');

    // Add click handlers for remove buttons
    container.querySelectorAll('.ssid-chip-remove').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const ssid = btn.dataset.ssid;
            await removeSsid(ssid);
        });
    });
}

async function addSsid() {
    const dropdown = document.getElementById('ssidDropdown');
    if (!dropdown) return;

    const ssid = dropdown.value;
    if (!ssid) {
        Toast.info('Please select an SSID from the dropdown');
        return;
    }

    if (currentPrivateSsids.includes(ssid)) {
        Toast.info('This SSID is already in the list');
        return;
    }

    currentPrivateSsids.push(ssid);
    await savePrivateSsids();
    dropdown.value = '';
}

async function removeSsid(ssid) {
    currentPrivateSsids = currentPrivateSsids.filter(s => s !== ssid);
    await savePrivateSsids();
}

async function savePrivateSsids() {
    const loadingToast = Toast.loading('Saving...');

    const result = await api.post('/settings/private-ssids', { private_ssids: currentPrivateSsids });

    Toast.remove(loadingToast);

    if (result && result.success) {
        Toast.success('Private SSIDs updated');
        renderSsidChips();
    } else {
        Toast.error('Failed to save settings');
        // Reload to get actual state
        await loadPrivateSsids();
    }
}



function initComponents() {
    // Inject sidebar
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        sidebar.innerHTML = sidebarTemplate;
    }

    // Set active nav based on current page
    let currentPage = window.location.pathname.split('/').pop().replace('.html', '') || 'home';
    if (currentPage === 'index' || currentPage === '') currentPage = 'home';
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === currentPage);
    });

    // Update status indicator
    updateStatus();
    setInterval(updateStatus, 30000); // Update every 30 seconds

    // Page-specific initialization
    if (currentPage === 'home') {
        loadDeviceTable();
        setInterval(loadDeviceTable, 10000); // Refresh every 10 seconds

        // Connect/Disconnect buttons
        document.querySelectorAll('.table-actions .btn').forEach((btn, i) => {
            if (i === 0) btn.onclick = connectSelectedDevices;
            if (i === 1) btn.onclick = disconnectSelectedDevices;
        });
    }

    if (currentPage === 'settings') {
        loadAuthStatus();

        // Login/Logout buttons
        const loginBtn = document.getElementById('loginBtn');
        const logoutBtn = document.getElementById('logoutBtn');
        if (loginBtn) loginBtn.onclick = login;
        if (logoutBtn) logoutBtn.onclick = logout;

        // Private SSIDs management
        loadAvailableSsids();
        loadPrivateSsids();

        const addSsidBtn = document.getElementById('addSsidBtn');
        if (addSsidBtn) addSsidBtn.onclick = addSsid;

        // Password visibility toggle
        const toggleBtn = document.getElementById('togglePassword');
        const passwordInput = document.getElementById('password');
        if (toggleBtn && passwordInput) {
            toggleBtn.onclick = () => {
                const isPassword = passwordInput.type === 'password';
                passwordInput.type = isPassword ? 'text' : 'password';
                toggleBtn.title = isPassword ? 'Hide password' : 'Show password';
                // Update icon (eye-open vs eye-closed)
                toggleBtn.innerHTML = isPassword
                    ? `<svg xmlns="http://www.w3.org/2000/svg" height="20px" viewBox="0 -960 960 960" width="20px" fill="#666"><path d="M480-320q75 0 127.5-52.5T660-500q0-75-52.5-127.5T480-680q-75 0-127.5 52.5T300-500q0 75 52.5 127.5T480-320Zm0-72q-45 0-76.5-31.5T372-500q0-45 31.5-76.5T480-608q45 0 76.5 31.5T588-500q0 45-31.5 76.5T480-392Zm0 192q-146 0-266-81.5T40-500q54-137 174-218.5T480-800q146 0 266 81.5T920-500q-54 137-174 218.5T480-200Z"/></svg>`
                    : `<svg xmlns="http://www.w3.org/2000/svg" height="20px" viewBox="0 -960 960 960" width="20px" fill="#666"><path d="m644-428-58-58q9-47-27-88t-93-32l-58-58q17-8 34.5-12t37.5-4q75 0 127.5 52.5T660-500q0 20-4 37.5T644-428Zm128 126-58-56q38-29 67.5-63.5T832-500q-50-101-143.5-160.5T480-720q-29 0-57 4t-55 12l-62-62q41-17 84-25.5t90-8.5q151 0 269 83.5T920-500q-23 59-60.5 109.5T772-302Zm20 246L624-222q-35 11-70.5 16.5T480-200q-151 0-269-83.5T40-500q21-53 53-98.5t73-81.5L56-792l56-56 736 736-56 56ZM222-624q-29 26-53 57t-41 67q50 101 143.5 160.5T480-280q20 0 39-2.5t39-5.5l-36-38q-11 3-21 4.5t-21 1.5q-75 0-127.5-52.5T300-500q0-11 1.5-21t4.5-21l-84-82Z"/></svg>`;
            };
        }
    }
}

// Run on DOM ready
document.addEventListener('DOMContentLoaded', initComponents);

// Add CSS for selected rows
const style = document.createElement('style');
style.textContent = `
    tr.selected {
        background-color: rgba(210, 39, 42, 0.1) !important;
    }
    tr {
        cursor: pointer;
    }
    tr:hover {
        background-color: rgba(0, 0, 0, 0.02);
    }
`;
document.head.appendChild(style);
