/**
 * NETMapper SSH - Main JavaScript
 */

// API endpoint base URL
const API_BASE = '/api';

// Current page state
const state = {
    currentPage: 1,
    itemsPerPage: 10,
    totalItems: 0,
    currentFilters: {},
    chartInstances: {}
};

// DOM Ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize UI components
    initNavigation();
    initEventListeners();
    
    // Load initial data
    loadStats();
    loadRecentDevices();
    loadCredentials();
    loadSettings();
});

/**
 * Initialize navigation tabs
 */
function initNavigation() {
    // Make both nav links and navbar brand clickable for navigation
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link, .navbar-brand');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Get the target section ID
            const targetId = this.getAttribute('data-bs-target');
            if (!targetId) return; // Skip if no target is defined
            
            // Update active nav link (only for actual nav items, not the brand)
            document.querySelectorAll('.navbar-nav .nav-link').forEach(l => {
                l.classList.remove('active');
                if (l.getAttribute('data-bs-target') === targetId) {
                    l.classList.add('active');
                }
            });
            
            // Show selected content section
            document.querySelectorAll('.content-section').forEach(section => {
                section.classList.remove('active');
            });
            document.getElementById(targetId).classList.add('active');
        });
    });
}


/**
 * Initialize event listeners
 */
function initEventListeners() {
    // Search button
    document.getElementById('search-btn').addEventListener('click', function() {
        state.currentPage = 1;
        searchDevices();
    });
    
    // Clear button
    document.getElementById('clear-btn').addEventListener('click', function() {
        clearFilters();
    });
    
    // Export buttons
    document.getElementById('export-btn').addEventListener('click', function() {
        // Show export modal
        const exportModal = new bootstrap.Modal(document.getElementById('exportModal'));
        exportModal.show();
    });
    
    document.getElementById('export-csv-btn').addEventListener('click', function() {
        exportDevices('csv');
    });
    
    document.getElementById('export-json-btn').addEventListener('click', function() {
        exportDevices('json');
    });
    
    document.getElementById('start-export-btn').addEventListener('click', function() {
        const format = document.querySelector('input[name="exportFormat"]:checked').value;
        const useFilters = document.getElementById('use-filters').checked;
        
        if (useFilters) {
            exportDevices(format, getSearchFilters());
        } else {
            exportDevices(format);
        }
        
        // Close the modal
        const exportModal = bootstrap.Modal.getInstance(document.getElementById('exportModal'));
        exportModal.hide();
    });
    
    // Poll all switches button
    document.getElementById('poll-all-btn').addEventListener('click', function() {
        pollAllSwitches();
    });
    
    // Add credential form
    document.getElementById('save-credential-btn').addEventListener('click', function() {
        saveCredential();
    });
    
    // Import CSV button
    document.getElementById('import-csv-btn').addEventListener('click', function() {
        importCredentialsFromCSV();
    });
    
    // Settings form
    document.getElementById('settings-form').addEventListener('submit', function(e) {
        e.preventDefault();
        saveSettings();
    });
    
    // Cleanup button
    document.getElementById('cleanup-btn').addEventListener('click', function() {
        runCleanup();
    });
    
    // Enter key in search fields
    const searchInputs = document.querySelectorAll('#devices input');
    searchInputs.forEach(input => {
        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                document.getElementById('search-btn').click();
            }
        });
    });
}

/**
 * Load system statistics
 */
function loadStats() {
    showLoading();
    
    fetch(`${API_BASE}/stats`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Update statistics cards
            document.getElementById('total-devices').textContent = data.total_devices;
            document.getElementById('total-switches').textContent = data.total_switches;
            document.getElementById('latest-update').textContent = formatDateTime(data.newest_record);
            document.getElementById('oldest-record').textContent = formatDateTime(data.oldest_record);
            document.getElementById('recent-updates').textContent = data.updates_last_24h;
            
            // Update VLAN distribution chart
            if (data.vlan_distribution) {
                renderVLANChart(data.vlan_distribution);
            }
            
            hideLoading();
        })
        .catch(error => {
            console.error('Error loading stats:', error);
            showToast('Error', 'Failed to load system statistics', 'error');
            hideLoading();
        });
}

/**
 * Render VLAN distribution chart
 */
function renderVLANChart(vlanData) {
    const ctx = document.getElementById('vlan-chart').getContext('2d');
    
    // Destroy previous chart instance if it exists
    if (state.chartInstances.vlanChart) {
        state.chartInstances.vlanChart.destroy();
    }
    
    // Prepare data
    const labels = Object.keys(vlanData);
    const data = Object.values(vlanData);
    const backgroundColors = labels.map((_, i) => {
        // Generate different colors for each VLAN
        const hue = (i * 137) % 360; // Using golden angle for good distribution
        return `hsl(${hue}, 70%, 60%)`;
    });
    
    // Create new chart
    state.chartInstances.vlanChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Devices per VLAN',
                data: data,
                backgroundColor: backgroundColors,
                borderColor: 'rgba(0, 0, 0, 0.1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        title: function(tooltipItems) {
                            const item = tooltipItems[0];
                            return `VLAN ${item.label}`;
                        },
                        label: function(context) {
                            return `${context.parsed.y} devices`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Device Count'
                    },
                    ticks: {
                        precision: 0
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'VLAN ID'
                    }
                }
            }
        }
    });
}

/**
 * Load recent devices for the dashboard
 */
function loadRecentDevices() {
    showLoading();
    
    // Get the 10 most recent devices
    fetch(`${API_BASE}/mappings?days=1`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            const tableBody = document.getElementById('recent-devices-table');
            
            if (data.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="6" class="text-center">No recent device updates</td></tr>';
                hideLoading();
                return;
            }
            
            // Take only the first 10 devices
            const recentDevices = data.slice(0, 10);
            
            // Clear table
            tableBody.innerHTML = '';
            
            // Add rows
            recentDevices.forEach(device => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${device.mac_address}</td>
                    <td>${device.ip_address || '-'}</td>
                    <td>${device.vlan || '-'}</td>
                    <td>${device.switch_name || device.switch_ip}</td>
                    <td>${device.switch_port}</td>
                    <td>${formatDateTime(device.last_present)}</td>
                `;
                tableBody.appendChild(row);
            });
            
            hideLoading();
        })
        .catch(error => {
            console.error('Error loading recent devices:', error);
            const tableBody = document.getElementById('recent-devices-table');
            tableBody.innerHTML = '<tr><td colspan="6" class="text-center text-danger">Error loading data</td></tr>';
            hideLoading();
        });
}

/**
 * Search devices with filters
 */
function searchDevices() {
    showLoading();
    
    const filters = getSearchFilters();
    state.currentFilters = filters;
    
    // Build query string
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(filters)) {
        if (value) params.append(key, value);
    }
    
    fetch(`${API_BASE}/mappings?${params}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            state.totalItems = data.length;
            renderDevicesTable(data);
            hideLoading();
            
            // Show results count
            if (data.length > 0) {
                showToast('Search Results', `Found ${data.length} devices matching your criteria`);
            } else {
                showToast('Search Results', 'No devices found matching your criteria');
            }
        })
        .catch(error => {
            console.error('Error searching devices:', error);
            const tableBody = document.getElementById('devices-table');
            tableBody.innerHTML = '<tr><td colspan="7" class="text-center text-danger">Error loading data</td></tr>';
            hideLoading();
            showToast('Error', 'Failed to search devices', 'error');
        });
}

/**
 * Render devices table with pagination
 */
function renderDevicesTable(devices) {
    const tableBody = document.getElementById('devices-table');
    
    if (devices.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="7" class="text-center">No devices found</td></tr>';
        document.getElementById('pagination').innerHTML = '';
        return;
    }
    
    // Calculate pagination
    const totalPages = Math.ceil(devices.length / state.itemsPerPage);
    const startIndex = (state.currentPage - 1) * state.itemsPerPage;
    const endIndex = Math.min(startIndex + state.itemsPerPage, devices.length);
    const currentPageDevices = devices.slice(startIndex, endIndex);
    
    // Clear table
    tableBody.innerHTML = '';
    
    // Add rows
    currentPageDevices.forEach(device => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${device.mac_address}</td>
            <td>${device.ip_address || '-'}</td>
            <td>${device.vlan || '-'}</td>
            <td>${device.switch_name || device.switch_ip}</td>
            <td>${device.switch_port}</td>
            <td>${formatDateTime(device.first_seen) || '-'}</td>
            <td>${formatDateTime(device.last_present)}</td>
        `;
        tableBody.appendChild(row);
    });
    
    // Update pagination
    renderPagination(totalPages);
}

/**
 * Render pagination controls
 */
function renderPagination(totalPages) {
    const paginationElement = document.getElementById('pagination');
    paginationElement.innerHTML = '';
    
    if (totalPages <= 1) return;
    
    // Previous button
    const prevItem = document.createElement('li');
    prevItem.className = `page-item ${state.currentPage === 1 ? 'disabled' : ''}`;
    prevItem.innerHTML = `<a class="page-link" href="#" aria-label="Previous"><span aria-hidden="true">&laquo;</span></a>`;
    paginationElement.appendChild(prevItem);
    
    // Page numbers
    const maxDisplayedPages = 5;
    let startPage = Math.max(1, state.currentPage - Math.floor(maxDisplayedPages / 2));
    const endPage = Math.min(totalPages, startPage + maxDisplayedPages - 1);
    
    // Adjust startPage if we're near the end
    startPage = Math.max(1, endPage - maxDisplayedPages + 1);
    
    // First page if not visible
    if (startPage > 1) {
        const firstItem = document.createElement('li');
        firstItem.className = 'page-item';
        firstItem.innerHTML = `<a class="page-link" href="#">1</a>`;
        paginationElement.appendChild(firstItem);
        
        if (startPage > 2) {
            const ellipsisItem = document.createElement('li');
            ellipsisItem.className = 'page-item disabled';
            ellipsisItem.innerHTML = `<a class="page-link" href="#">...</a>`;
            paginationElement.appendChild(ellipsisItem);
        }
    }
    
    // Page numbers
    for (let i = startPage; i <= endPage; i++) {
        const pageItem = document.createElement('li');
        pageItem.className = `page-item ${i === state.currentPage ? 'active' : ''}`;
        pageItem.innerHTML = `<a class="page-link" href="#">${i}</a>`;
        paginationElement.appendChild(pageItem);
    }
    
    // Last page if not visible
    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            const ellipsisItem = document.createElement('li');
            ellipsisItem.className = 'page-item disabled';
            ellipsisItem.innerHTML = `<a class="page-link" href="#">...</a>`;
            paginationElement.appendChild(ellipsisItem);
        }
        
        const lastItem = document.createElement('li');
        lastItem.className = 'page-item';
        lastItem.innerHTML = `<a class="page-link" href="#">${totalPages}</a>`;
        paginationElement.appendChild(lastItem);
    }
    
    // Next button
    const nextItem = document.createElement('li');
    nextItem.className = `page-item ${state.currentPage === totalPages ? 'disabled' : ''}`;
    nextItem.innerHTML = `<a class="page-link" href="#" aria-label="Next"><span aria-hidden="true">&raquo;</span></a>`;
    paginationElement.appendChild(nextItem);
    
    // Add event listeners
    paginationElement.querySelectorAll('.page-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            if (this.getAttribute('aria-label') === 'Previous') {
                if (state.currentPage > 1) {
                    state.currentPage--;
                    searchDevices();
                }
            } else if (this.getAttribute('aria-label') === 'Next') {
                if (state.currentPage < totalPages) {
                    state.currentPage++;
                    searchDevices();
                }
            } else if (!this.textContent.includes('...')) {
                state.currentPage = parseInt(this.textContent);
                searchDevices();
            }
        });
    });
}

/**
 * Get search filters from form
 */
function getSearchFilters() {
    return {
        mac: document.getElementById('mac-filter').value.trim(),
        ip: document.getElementById('ip-filter').value.trim(),
        vlan: document.getElementById('vlan-filter').value.trim(),
        switch: document.getElementById('switch-filter').value.trim(),
        port: document.getElementById('port-filter').value.trim(),
        days: document.getElementById('days-filter').value.trim() || null
    };
}

/**
 * Clear search filters
 */
function clearFilters() {
    document.getElementById('mac-filter').value = '';
    document.getElementById('ip-filter').value = '';
    document.getElementById('vlan-filter').value = '';
    document.getElementById('switch-filter').value = '';
    document.getElementById('port-filter').value = '';
    document.getElementById('days-filter').value = '30';
    
    // Reset state
    state.currentPage = 1;
    state.currentFilters = {};
    
    // Clear table
    const tableBody = document.getElementById('devices-table');
    tableBody.innerHTML = '<tr><td colspan="7" class="text-center">Use the search filters above to find devices</td></tr>';
    document.getElementById('pagination').innerHTML = '';
}

/**
 * Load credentials
 */
function loadCredentials() {
    showLoading();
    
    fetch(`${API_BASE}/credentials`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            const tableBody = document.getElementById('credentials-table');
            
            if (data.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="5" class="text-center">No credentials found</td></tr>';
                hideLoading();
                return;
            }
            
            // Clear table
            tableBody.innerHTML = '';
            
            // Add rows
            data.forEach(credential => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${credential.name || credential.hostname}</td>
                    <td>${credential.hostname}</td>
                    <td>${credential.username}</td>
                    <td>${credential.port || 22}</td>
                    <td>
                        <button class="btn btn-sm btn-primary credential-poll-btn" data-hostname="${credential.hostname}">
                            <i class="bi bi-arrow-repeat"></i> Poll
                        </button>
                        <button class="btn btn-sm btn-danger credential-delete-btn" data-hostname="${credential.hostname}">
                            <i class="bi bi-trash"></i>
                        </button>
                    </td>
                `;
                tableBody.appendChild(row);
            });
            
            // Add event listeners for poll and delete buttons
            document.querySelectorAll('.credential-poll-btn').forEach(button => {
                button.addEventListener('click', function() {
                    const hostname = this.getAttribute('data-hostname');
                    pollSwitch(hostname);
                });
            });
            
            document.querySelectorAll('.credential-delete-btn').forEach(button => {
                button.addEventListener('click', function() {
                    const hostname = this.getAttribute('data-hostname');
                    deleteCredential(hostname);
                });
            });
            
            hideLoading();
        })
        .catch(error => {
            console.error('Error loading credentials:', error);
            const tableBody = document.getElementById('credentials-table');
            tableBody.innerHTML = '<tr><td colspan="5" class="text-center text-danger">Error loading credentials</td></tr>';
            hideLoading();
        });
}

/**
 * Save credential
 */
function saveCredential() {
    const hostname = document.getElementById('switch-hostname').value.trim();
    const username = document.getElementById('switch-username').value.trim();
    const password = document.getElementById('switch-password').value;
    const name = document.getElementById('switch-name').value.trim();
    const port = document.getElementById('switch-port').value.trim();
    
    if (!hostname || !username || !password) {
        showToast('Error', 'Hostname, username, and password are required', 'error');
        return;
    }
    
    showLoading();
    
    fetch(`${API_BASE}/credentials`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            hostname,
            username,
            password,
            name: name || hostname,
            port: port || 22
        })
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            hideLoading();
            
            if (data.success) {
                // Close modal
                const modal = bootstrap.Modal.getInstance(document.getElementById('addCredentialModal'));
                modal.hide();
                
                // Clear form
                document.getElementById('switch-hostname').value = '';
                document.getElementById('switch-username').value = '';
                document.getElementById('switch-password').value = '';
                document.getElementById('switch-name').value = '';
                document.getElementById('switch-port').value = '22';
                
                // Reload credentials
                loadCredentials();
                
                showToast('Success', 'Credential added successfully');
            } else {
                showToast('Error', data.message || 'Failed to add credential', 'error');
            }
        })
        .catch(error => {
            console.error('Error saving credential:', error);
            hideLoading();
            showToast('Error', 'Failed to add credential', 'error');
        });
}

/**
 * Delete credential
 */
function deleteCredential(hostname) {
    if (!confirm(`Are you sure you want to delete the credential for ${hostname}?`)) {
        return;
    }
    
    showLoading();
    
    fetch(`${API_BASE}/credentials/${hostname}`, {
        method: 'DELETE'
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            hideLoading();
            
            if (data.success) {
                loadCredentials();
                showToast('Success', `Deleted credential for ${hostname}`);
            } else {
                showToast('Error', data.message || 'Failed to delete credential', 'error');
            }
        })
        .catch(error => {
            console.error('Error deleting credential:', error);
            hideLoading();
            showToast('Error', 'Failed to delete credential', 'error');
        });
}

/**
 * Import credentials from CSV
 */
function importCredentialsFromCSV() {
    const fileInput = document.getElementById('csv-file');
    
    if (!fileInput.files || fileInput.files.length === 0) {
        showToast('Error', 'Please select a CSV file', 'error');
        return;
    }
    
    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);
    
    showLoading();
    
    fetch(`${API_BASE}/credentials/import`, {
        method: 'POST',
        body: formData
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            hideLoading();
            
            if (data.success) {
                // Close modal
                const modal = bootstrap.Modal.getInstance(document.getElementById('importCredentialsModal'));
                modal.hide();
                
                // Clear file input
                fileInput.value = '';
                
                // Reload credentials
                loadCredentials();
                
                showToast('Success', `Imported ${data.imported} credentials (${data.failed} failures)`);
            } else {
                showToast('Error', data.message || 'Failed to import credentials', 'error');
            }
        })
        .catch(error => {
            console.error('Error importing credentials:', error);
            hideLoading();
            showToast('Error', 'Failed to import credentials', 'error');
        });
}

/**
 * Poll a specific switch
 */
function pollSwitch(hostname) {
    // Find credential for the hostname
    showLoading();
    
    fetch(`${API_BASE}/credentials`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(credentials => {
            const credential = credentials.find(c => c.hostname === hostname);
            
            if (!credential) {
                throw new Error('Credential not found');
            }
            
            // Poll the switch
            return fetch(`${API_BASE}/poll`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    hostname: credential.hostname,
                    username: credential.username,
                    password: credential.password,
                    port: credential.port || 22,
                    name: credential.name
                })
            });
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            hideLoading();
            
            if (data.success) {
                showToast('Success', `Successfully polled ${hostname}, processed ${data.count} entries`);
                
                // Refresh data
                loadStats();
                loadRecentDevices();
                
                // Refresh device list if it's currently being displayed
                if (document.getElementById('devices').classList.contains('active')) {
                    searchDevices();
                }
            } else {
                showToast('Error', data.message || 'Failed to poll switch', 'error');
            }
        })
        .catch(error => {
            console.error('Error polling switch:', error);
            hideLoading();
            showToast('Error', `Failed to poll switch: ${error.message}`, 'error');
        });
}

/**
 * Poll all switches
 */
function pollAllSwitches() {
    if (!confirm('Are you sure you want to poll all switches? This may take some time.')) {
        return;
    }
    
    showLoading();
    
    fetch(`${API_BASE}/poll/all`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            hideLoading();
            
            if (data.success) {
                showToast('Success', `Successfully polled all switches, processed ${data.total_count} entries`);
                
                // Show details about individual switches
                const successCount = Object.values(data.results).filter(r => r.success).length;
                const failCount = Object.values(data.results).filter(r => !r.success).length;
                
                if (failCount > 0) {
                    console.warn('Some switches failed to poll:', 
                        Object.entries(data.results)
                            .filter(([_, result]) => !result.success)
                            .map(([hostname, result]) => `${hostname}: ${result.error}`));
                    
                    showToast('Warning', `${successCount} switches polled successfully, ${failCount} failures`, 'warning');
                }
                
                // Refresh data
                loadStats();
                loadRecentDevices();
                
                // Refresh device list if it's currently being displayed
                if (document.getElementById('devices').classList.contains('active')) {
                    searchDevices();
                }
            } else {
                showToast('Error', data.message || 'Failed to poll switches', 'error');
            }
        })
        .catch(error => {
            console.error('Error polling all switches:', error);
            hideLoading();
            showToast('Error', `Failed to poll switches: ${error.message}`, 'error');
        });
}

/**
 * Export devices to CSV or JSON
 */
function exportDevices(format, filters = null) {
    showLoading();
    
    // Build query parameters
    const params = new URLSearchParams();
    
    if (filters) {
        for (const [key, value] of Object.entries(filters)) {
            if (value) params.append(key, value);
        }
    }
    
    const endpointUrl = format === 'csv' 
        ? `${API_BASE}/export/csv` 
        : `${API_BASE}/export`;
    
    fetch(`${endpointUrl}?${params}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            hideLoading();
            
            if (data.success) {
                // Download the file
                window.location.href = `${API_BASE}/download/${data.file.split('/').pop()}`;
                
                showToast('Success', `Exported ${data.count} entries to ${format.toUpperCase()}`);
            } else {
                showToast('Error', data.message || 'Failed to export data', 'error');
            }
        })
        .catch(error => {
            console.error(`Error exporting to ${format}:`, error);
            hideLoading();
            showToast('Error', `Failed to export data: ${error.message}`, 'error');
        });
}

/**
 * Load settings
 */
function loadSettings() {
    showLoading();
    
    fetch(`${API_BASE}/config`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            hideLoading();
            
            // Update form fields
            document.getElementById('use-encryption').checked = data.use_encryption || false;
            document.getElementById('cleanup-days').value = data.cleanup_days || 30;
            document.getElementById('poll-interval').value = data.polling_interval || 3600;
            
            // Update system information
            document.getElementById('db-path').textContent = data.database_path || '-';
            document.getElementById('cred-path').textContent = data.credentials_path || '-';
            document.getElementById('encryption-status').textContent = data.use_encryption ? 'Enabled' : 'Disabled';
        })
        .catch(error => {
            console.error('Error loading settings:', error);
            hideLoading();
            showToast('Error', 'Failed to load settings', 'error');
        });
}

/**
 * Save settings
 */
function saveSettings() {
    const useEncryption = document.getElementById('use-encryption').checked;
    const cleanupDays = document.getElementById('cleanup-days').value;
    const pollInterval = document.getElementById('poll-interval').value;
    
    showLoading();
    
    fetch(`${API_BASE}/config`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            use_encryption: useEncryption,
            cleanup_days: parseInt(cleanupDays),
            polling_interval: parseInt(pollInterval)
        })
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            hideLoading();
            
            if (data.success) {
                showToast('Success', 'Settings saved successfully');
                
                // Update displayed settings
                document.getElementById('encryption-status').textContent = useEncryption ? 'Enabled' : 'Disabled';
            } else {
                showToast('Error', data.message || 'Failed to save settings', 'error');
            }
        })
        .catch(error => {
            console.error('Error saving settings:', error);
            hideLoading();
            showToast('Error', 'Failed to save settings', 'error');
        });
}

/**
 * Run cleanup
 */
function runCleanup() {
    const days = document.getElementById('cleanup-days').value;
    
    if (!confirm(`Are you sure you want to remove all entries older than ${days} days? This cannot be undone.`)) {
        return;
    }
    
    showLoading();
    
    fetch(`${API_BASE}/cleanup`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            days: parseInt(days)
        })
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            hideLoading();
            
            if (data.success) {
                showToast('Success', `Removed ${data.count} stale entries older than ${days} days`);
                
                // Refresh data
                loadStats();
                loadRecentDevices();
                
                // Refresh device list if it's currently being displayed
                if (document.getElementById('devices').classList.contains('active')) {
                    searchDevices();
                }
            } else {
                showToast('Error', data.message || 'Failed to run cleanup', 'error');
            }
        })
        .catch(error => {
            console.error('Error running cleanup:', error);
            hideLoading();
            showToast('Error', 'Failed to run cleanup', 'error');
        });
}

/**
 * Show a toast notification
 */
function showToast(title, message, type = 'success') {
    const toast = document.getElementById('alert-toast');
    const toastTitle = document.getElementById('toast-title');
    const toastMessage = document.getElementById('toast-message');
    
    // Set title and message
    toastTitle.textContent = title;
    toastMessage.textContent = message;
    
    // Set type-based styling
    toast.classList.remove('bg-success', 'bg-danger', 'bg-warning', 'text-dark');
    toastTitle.parentElement.classList.remove('bg-success', 'bg-danger', 'bg-warning', 'text-dark');
    
    switch (type) {
        case 'error':
            toast.classList.add('bg-danger', 'text-white');
            toastTitle.parentElement.classList.add('bg-danger', 'text-white');
            break;
        case 'warning':
            toast.classList.add('bg-warning', 'text-dark');
            toastTitle.parentElement.classList.add('bg-warning', 'text-dark');
            break;
        default:
            toast.classList.add('bg-success', 'text-white');
            toastTitle.parentElement.classList.add('bg-success', 'text-white');
    }
    
    // Show the toast
    const bsToast = new bootstrap.Toast(toast, { delay: 5000 });
    bsToast.show();
}

/**
 * Show loading overlay
 */
function showLoading() {
    document.getElementById('loading-overlay').classList.remove('d-none');
}

/**
 * Hide loading overlay
 */
function hideLoading() {
    document.getElementById('loading-overlay').classList.add('d-none');
}

/**
 * Format date and time
 */
function formatDateTime(dateString) {
    if (!dateString) return '-';
    
    try {
        const date = new Date(dateString);
        
        // Check if date is valid
        if (isNaN(date.getTime())) return dateString;
        
        return new Intl.DateTimeFormat('default', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        }).format(date);
    } catch (error) {
        console.error('Error formatting date:', error);
        return dateString;
    }
}
