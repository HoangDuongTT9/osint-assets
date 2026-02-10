// ==UserScript==
// @name         OSINT Phone Lookup Tool (Secure Edition)
// @namespace    http://tampermonkey.net/
// @version      2.0.0
// @description  Advanced OSINT tool with auto-update and remote kill-switch
// @author       Your Name
// @match        https://www.google.com/*
// @match        about:blank
// @match        https://uidphone.xyz/*
// @match        https://www.facebook.com/*
// @match        https://chat.zalo.me/*
// @icon         data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%234A90E2"><path d="M20.01 15.38c-1.23 0-2.42-.2-3.53-.56a.977.977 0 00-1.01.24l-1.57 1.97c-2.83-1.35-5.48-3.9-6.89-6.83l1.95-1.66c.27-.28.35-.67.24-1.02-.37-1.11-.56-2.3-.56-3.53 0-.54-.45-.99-.99-.99H4.19C3.65 3 3 3.24 3 3.99 3 13.28 10.73 21 20.01 21c.71 0 .99-.63.99-1.18v-3.45c0-.54-.45-.99-.99-.99z"/></svg>
// @grant        GM_openInTab
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_addStyle
// @grant        GM_xmlhttpRequest
// @grant        GM_registerMenuCommand
// @connect      gist.githubusercontent.com
// @connect      raw.githubusercontent.com
// @updateURL    https://raw.githubusercontent.com/YOUR_USERNAME/osint-tool/main/osint-phone-lookup-secure.meta.js
// @downloadURL  https://raw.githubusercontent.com/YOUR_USERNAME/osint-tool/main/osint-phone-lookup-secure.user.js
// @run-at       document-end
// ==/UserScript==

(function () {
    'use strict';

    // ==================== SECURITY CONFIGURATION ====================
    const SECURITY_CONFIG = {
        // License check URL (GitHub Gist - Base64 encoded)
        // TODO: Replace with your actual Gist URL encoded in Base64
        // Example: https://gist.githubusercontent.com/USERNAME/GIST_ID/raw/license.json
        LICENSE_URL: 'aHR0cHM6Ly9naXN0LmdpdGh1YnVzZXJjb250ZW50LmNvbS9Ib2FuZ0R1b25nVFQ5L2NmOGZiNGJkODJlN2U4OWYwYjEzNDIxYzBiYWNkMjY0L3Jhdy8xMmU2MWZiNzk0ZTRkNTBiOWQ1MmMyYmNlYzc5M2NkN2VmMTkwYmU5L2xpY2Vuc2VzLmpzb24=',

        // Cache duration (1 hour)
        CACHE_DURATION: 3600000,

        // Allow offline mode (false = maximum security)
        ALLOW_OFFLINE: false,

        // Current version
        CURRENT_VERSION: '2.0.0'
    };

    // ==================== CONFIGURATION ====================
    const CONFIG = {
        delayMin: 5000,
        delayMax: 10000,
        maxConcurrentTabs: 3,
        maxNumbersPerBatch: 10,
        storageKey: 'osint_phone_results',

        // Obfuscated search modules (URLs encoded in Base64)
        searchModules: [
            {
                id: 'facebook',
                name: 'Facebook',
                enabled: true,
                urlTemplate: 'aHR0cHM6Ly93d3cuZmFjZWJvb2suY29tL3NlYXJjaC9wb3N0cz9xPQ==',
                urlSuffix: 'JmZpbHRlcnM9ZXlKeVpXTmxiblJmY0c5emRITTZNQ0k2SWx0Y2ltNWhiV1ZjSWpwY0luSmxZMlZ1ZEY5d2IzTjBjMXdpTEZ3aVlYSm5jMXdpT2x3aVhDSmNJbjBpZlElM0Q=',
                autoFill: false,
                background: true
            },
            {
                id: 'google',
                name: 'Google',
                enabled: true,
                urlTemplate: 'aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbS9zZWFyY2g/cT0=',
                urlSuffix: '',
                autoFill: false,
                background: true
            },
            {
                id: 'quetsdt',
                name: 'QuetSDT',
                enabled: true,
                urlTemplate: 'aHR0cHM6Ly91aWRwaG9uZS54eXovc2Nhbi1zaW5nbGU=',
                urlSuffix: '',
                autoFill: true,
                background: false,
                selectors: {
                    input: '#uid2phone-link',
                    submit: '#uid2phone-btn'
                }
            },
            {
                id: 'zalo',
                name: 'Zalo',
                enabled: true,
                urlTemplate: 'aHR0cHM6Ly9jaGF0LnphbG8ubWUv',
                urlSuffix: '',
                autoFill: true,
                background: false,
                selectors: {
                    input: '#contact-search-input',
                    submit: null
                }
            }
        ]
    };

    // ==================== SECURITY MANAGER ====================
    class SecurityManager {
        static async validateLicense() {
            console.log('[Security] Validating license...');

            // Check if online
            if (!navigator.onLine) {
                if (SECURITY_CONFIG.ALLOW_OFFLINE) {
                    console.warn('[Security] Offline mode - using cached license');
                    return this.checkCachedLicense();
                } else {
                    this.showSecurityError('❌ Không có kết nối Internet. Script yêu cầu kết nối để xác thực.');
                    return false;
                }
            }

            try {
                const licenseUrl = atob(SECURITY_CONFIG.LICENSE_URL);

                const response = await new Promise((resolve, reject) => {
                    GM_xmlhttpRequest({
                        method: 'GET',
                        url: licenseUrl,
                        timeout: 10000,
                        onload: resolve,
                        onerror: reject,
                        ontimeout: reject
                    });
                });

                if (response.status !== 200) {
                    throw new Error(`HTTP ${response.status}`);
                }

                const licenseData = JSON.parse(response.responseText);

                // Cache license
                GM_setValue('license_cache', JSON.stringify({
                    data: licenseData,
                    timestamp: Date.now()
                }));

                // Check if active
                if (!licenseData.active) {
                    this.showSecurityError(
                        licenseData.message || '⚠️ Phiên bản này đã bị dừng hỗ trợ. Vui lòng liên hệ admin.'
                    );
                    return false;
                }

                // Check minimum version
                if (licenseData.minVersion && this.compareVersions(SECURITY_CONFIG.CURRENT_VERSION, licenseData.minVersion) < 0) {
                    this.showSecurityError(
                        `⚠️ Phiên bản script quá cũ. Yêu cầu tối thiểu: v${licenseData.minVersion}. Vui lòng cập nhật!`
                    );
                    return false;
                }

                console.log('[Security] ✅ License valid');
                return true;

            } catch (error) {
                console.error('[Security] License validation failed:', error);

                if (SECURITY_CONFIG.ALLOW_OFFLINE) {
                    console.warn('[Security] Using cached license due to error');
                    return this.checkCachedLicense();
                }

                this.showSecurityError('❌ Không thể xác thực license. Vui lòng kiểm tra kết nối Internet.');
                return false;
            }
        }

        static checkCachedLicense() {
            const cached = GM_getValue('license_cache', null);

            if (!cached) {
                console.error('[Security] No cached license found');
                return false;
            }

            try {
                const { data, timestamp } = JSON.parse(cached);
                const age = Date.now() - timestamp;

                if (age > SECURITY_CONFIG.CACHE_DURATION) {
                    console.warn('[Security] Cached license expired');
                    return false;
                }

                if (!data.active) {
                    this.showSecurityError('⚠️ License đã bị vô hiệu hóa');
                    return false;
                }

                console.log('[Security] ✅ Cached license valid');
                return true;

            } catch (e) {
                console.error('[Security] Error reading cached license:', e);
                return false;
            }
        }

        static compareVersions(v1, v2) {
            const parts1 = v1.split('.').map(Number);
            const parts2 = v2.split('.').map(Number);

            for (let i = 0; i < 3; i++) {
                if (parts1[i] > parts2[i]) return 1;
                if (parts1[i] < parts2[i]) return -1;
            }
            return 0;
        }

        static showSecurityError(message) {
            console.error('[Security]', message);

            const overlay = document.createElement('div');
            overlay.style.cssText = `
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                z-index: 999999999; display: flex; align-items: center; justify-content: center;
                font-family: 'Segoe UI', Arial, sans-serif;
            `;

            overlay.innerHTML = `
                <div style="background: rgba(255, 255, 255, 0.1); backdrop-filter: blur(20px);
                    padding: 50px; border-radius: 20px; text-align: center; max-width: 500px;
                    border: 1px solid rgba(255, 255, 255, 0.2); box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);">
                    <div style="font-size: 64px; margin-bottom: 20px;">🔒</div>
                    <h2 style="color: #ff6b6b; margin: 0 0 20px 0; font-size: 24px;">
                        OSINT Tool - Security Check Failed
                    </h2>
                    <p style="color: #ffffff; font-size: 16px; line-height: 1.6; margin: 0;">
                        ${message}
                    </p>
                    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.1);">
                        <p style="color: rgba(255,255,255,0.6); font-size: 12px; margin: 0;">
                            OSINT Phone Lookup Tool v${SECURITY_CONFIG.CURRENT_VERSION}
                        </p>
                    </div>
                </div>
            `;

            document.body.appendChild(overlay);

            // Remove UI elements
            const panel = document.getElementById('osint-panel');
            const floatBtn = document.getElementById('osint-toggle-btn');
            if (panel) panel.remove();
            if (floatBtn) floatBtn.remove();
        }
    }

    // Helper function to decode module URLs
    function decodeModuleUrl(module, phone = '') {
        const baseUrl = atob(module.urlTemplate);
        const suffix = module.urlSuffix ? atob(module.urlSuffix) : '';

        if (phone) {
            return baseUrl + encodeURIComponent(phone) + suffix;
        }
        return baseUrl + suffix;
    }

    // ==================== UTILITIES ====================
    class Utils {
        static randomDelay() {
            const delay = Math.floor(Math.random() * (CONFIG.delayMax - CONFIG.delayMin + 1)) + CONFIG.delayMin;
            return new Promise(resolve => setTimeout(resolve, delay));
        }

        static sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        static generateId() {
            return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        }

        static formatTimestamp() {
            return new Date().toLocaleString('vi-VN');
        }

        static parsePhoneNumbers(text) {
            return text
                .split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0)
                .filter(line => /^[0-9+\-\s()]+$/.test(line));
        }

        static showToast(message, type = 'info') {
            const toast = document.createElement('div');
            toast.className = `osint-toast osint-toast-${type}`;
            toast.textContent = message;
            document.body.appendChild(toast);

            setTimeout(() => toast.classList.add('show'), 100);
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        }
    }

    // ==================== DATA COLLECTOR ====================
    class DataCollector {
        static saveResult(phoneNumber, source, data) {
            const results = this.loadAllResults();

            if (!results[phoneNumber]) {
                results[phoneNumber] = {
                    phone: phoneNumber,
                    results: {},
                    timestamp: Utils.formatTimestamp(),
                    status: 'processing'
                };
            }

            results[phoneNumber].results[source] = data;
            results[phoneNumber].lastUpdate = Utils.formatTimestamp();

            GM_setValue(CONFIG.storageKey, JSON.stringify(results));
            return results[phoneNumber];
        }

        static loadAllResults() {
            const data = GM_getValue(CONFIG.storageKey, '{}');
            return JSON.parse(data);
        }

        static markComplete(phoneNumber) {
            const results = this.loadAllResults();
            if (results[phoneNumber]) {
                results[phoneNumber].status = 'completed';
                GM_setValue(CONFIG.storageKey, JSON.stringify(results));
            }
        }

        static clearResults() {
            GM_setValue(CONFIG.storageKey, '{}');
        }

        static exportToJSON() {
            const results = this.loadAllResults();
            const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `osint_results_${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
        }

        static exportToTXT() {
            const results = this.loadAllResults();
            let text = '========== OSINT PHONE LOOKUP RESULTS ==========\n\n';

            Object.values(results).forEach((item, index) => {
                text += `[${index + 1}] ${item.phone}\n`;
                text += `Status: ${item.status}\n`;
                text += `Timestamp: ${item.timestamp}\n`;

                if (item.results.facebook) {
                    text += `  Facebook: ${item.results.facebook.data || item.results.facebook.url || 'Opened'}\n`;
                }
                if (item.results.google) {
                    text += `  Google: ${item.results.google.data || item.results.google.url || 'Opened'}\n`;
                }
                if (item.results.quetsdt) {
                    text += `  QuetSDT: ${item.results.quetsdt.data || item.results.quetsdt.status || 'Submitted'}\n`;
                }
                if (item.results.zalo) {
                    text += `  Zalo: ${item.results.zalo.data || item.results.zalo.status || 'Searched'}\n`;
                }

                text += '\n' + '-'.repeat(50) + '\n\n';
            });

            const blob = new Blob([text], { type: 'text/plain;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `osint_results_${Date.now()}.txt`;
            a.click();
            URL.revokeObjectURL(url);
        }

        static exportToCSV() {
            const results = this.loadAllResults();
            const rows = [['Phone Number', 'Facebook Data', 'Google Data', 'QuetSDT Data', 'Zalo Data', 'Status', 'Timestamp']];

            Object.values(results).forEach(item => {
                rows.push([
                    item.phone,
                    item.results.facebook ? (item.results.facebook.data || 'Opened') : 'Pending',
                    item.results.google ? (item.results.google.data || 'Opened') : 'Pending',
                    item.results.quetsdt ? (item.results.quetsdt.data || 'Submitted') : 'Pending',
                    item.results.zalo ? (item.results.zalo.data || 'Searched') : 'Pending',
                    item.status,
                    item.timestamp
                ]);
            });

            const csv = rows.map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
            const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `osint_results_${Date.now()}.csv`;
            a.click();
            URL.revokeObjectURL(url);
        }
    }

    // ==================== TAB MANAGER ====================
    class TabManager {
        static openSearchTab(url, background = true) {
            return GM_openInTab(url, { active: !background, insert: true });
        }
    }

    // ==================== SEARCH MODULES ====================
    class SearchModules {
        static async executeFacebook(phoneNumber) {
            const module = CONFIG.searchModules.find(m => m.id === 'facebook');
            if (!module || !module.enabled) return null;

            const url = decodeModuleUrl(module, phoneNumber);
            TabManager.openSearchTab(url, module.background);

            const result = {
                url: url,
                status: 'opened',
                timestamp: Utils.formatTimestamp()
            };

            DataCollector.saveResult(phoneNumber, 'facebook', result);
            return result;
        }

        static async executeGoogle(phoneNumber) {
            const module = CONFIG.searchModules.find(m => m.id === 'google');
            if (!module || !module.enabled) return null;

            const url = decodeModuleUrl(module, phoneNumber);
            TabManager.openSearchTab(url, module.background);

            const result = {
                url: url,
                status: 'opened',
                timestamp: Utils.formatTimestamp()
            };

            DataCollector.saveResult(phoneNumber, 'google', result);
            return result;
        }

        static async executeQuetSDT(phoneNumber) {
            const module = CONFIG.searchModules.find(m => m.id === 'quetsdt');
            if (!module || !module.enabled) return null;

            const url = decodeModuleUrl(module);
            const tab = TabManager.openSearchTab(url, module.background);

            const result = {
                url: url,
                status: 'tab_opened',
                phone: phoneNumber,
                timestamp: Utils.formatTimestamp()
            };

            GM_setValue('quetsdt_pending_phone', phoneNumber);
            DataCollector.saveResult(phoneNumber, 'quetsdt', result);

            return result;
        }

        static async executeZalo(phoneNumber) {
            const module = CONFIG.searchModules.find(m => m.id === 'zalo');
            if (!module || !module.enabled) return null;

            const url = decodeModuleUrl(module);
            const tab = TabManager.openSearchTab(url, module.background);

            const result = {
                url: url,
                status: 'tab_opened',
                phone: phoneNumber,
                timestamp: Utils.formatTimestamp()
            };

            GM_setValue('zalo_pending_phone', phoneNumber);
            DataCollector.saveResult(phoneNumber, 'zalo', result);

            return result;
        }

        static async executeAll(phoneNumber) {
            const results = {};

            try {
                Utils.showToast(`🔍 Đang tra cứu: ${phoneNumber}`, 'info');

                results.facebook = await this.executeFacebook(phoneNumber);
                await Utils.sleep(1000);

                results.google = await this.executeGoogle(phoneNumber);
                await Utils.sleep(1000);

                results.quetsdt = await this.executeQuetSDT(phoneNumber);
                await Utils.sleep(1000);

                results.zalo = await this.executeZalo(phoneNumber);

                DataCollector.markComplete(phoneNumber);
                Utils.showToast(`✅ Hoàn thành: ${phoneNumber}`, 'success');

            } catch (error) {
                console.error('Error executing search:', error);
                Utils.showToast(`❌ Lỗi: ${phoneNumber}`, 'error');
            }

            return results;
        }
    }

    // ==================== QUEUE MANAGER ====================
    class QueueManager {
        constructor() {
            this.queue = [];
            this.currentIndex = 0;
            this.isRunning = false;
            this.isPaused = false;
        }

        loadFromInput(text) {
            const allNumbers = Utils.parsePhoneNumbers(text);
            const existingResults = DataCollector.loadAllResults();
            const existingCount = Object.keys(existingResults).length;

            if (allNumbers.length > CONFIG.maxNumbersPerBatch) {
                Utils.showToast(`⚠️ Giới hạn ${CONFIG.maxNumbersPerBatch} SĐT/lần. Chỉ lấy ${CONFIG.maxNumbersPerBatch} số đầu tiên.`, 'warning');
                this.queue = allNumbers.slice(0, CONFIG.maxNumbersPerBatch);
            } else {
                this.queue = allNumbers;
            }

            if (existingCount + this.queue.length > CONFIG.maxNumbersPerBatch) {
                const remaining = CONFIG.maxNumbersPerBatch - existingCount;
                if (remaining <= 0) {
                    Utils.showToast('❌ Đã đủ 10 SĐT. Vui lòng Export và Clear trước khi tiếp tục!', 'error');
                    this.showExportWarning();
                    return 0;
                }
                Utils.showToast(`⚠️ Chỉ có thể thêm ${remaining} SĐT nữa (đang có ${existingCount})`, 'warning');
                this.queue = this.queue.slice(0, remaining);
            }

            this.currentIndex = 0;
            return this.queue.length;
        }

        showExportWarning() {
            const modal = document.createElement('div');
            modal.className = 'osint-modal';
            modal.innerHTML = `
                <div class="osint-modal-content">
                    <h3>⚠️ Đã đạt giới hạn 10 SĐT</h3>
                    <p>Vui lòng Export kết quả và Clear dữ liệu trước khi tiếp tục tra cứu.</p>
                    <div class="osint-modal-buttons">
                        <button class="osint-btn osint-btn-export" id="modal-export-btn">💾 Export & Clear</button>
                        <button class="osint-btn osint-btn-stop" id="modal-cancel-btn">Đóng</button>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
            setTimeout(() => modal.classList.add('show'), 10);

            document.getElementById('modal-export-btn').addEventListener('click', () => {
                DataCollector.exportToJSON();
                setTimeout(() => {
                    if (confirm('Đã export xong. Xóa dữ liệu cũ để tiếp tục?')) {
                        DataCollector.clearResults();
                        Utils.showToast('✅ Đã xóa dữ liệu. Có thể tra cứu tiếp!', 'success');
                    }
                    modal.remove();
                }, 500);
            });

            document.getElementById('modal-cancel-btn').addEventListener('click', () => modal.remove());
        }

        async start() {
            if (this.queue.length === 0) {
                Utils.showToast('⚠️ Vui lòng nhập số điện thoại', 'warning');
                return;
            }

            this.isRunning = true;
            this.isPaused = false;
            UIManager.updateControlsState('running');

            Utils.showToast(`🚀 Bắt đầu xử lý ${this.queue.length} số điện thoại`, 'info');

            for (let i = this.currentIndex; i < this.queue.length; i++) {
                if (!this.isRunning) {
                    Utils.showToast('⏹️ Đã dừng', 'info');
                    break;
                }

                this.currentIndex = i;
                const phoneNumber = this.queue[i];

                UIManager.updateProgress(i + 1, this.queue.length);
                await SearchModules.executeAll(phoneNumber);

                if (i < this.queue.length - 1 && this.isRunning) {
                    const delay = Math.floor(Math.random() * (CONFIG.delayMax - CONFIG.delayMin + 1)) + CONFIG.delayMin;
                    Utils.showToast(`⏳ Chờ ${(delay / 1000).toFixed(1)}s trước khi tiếp tục...`, 'info');
                    await Utils.randomDelay();
                }
            }

            if (this.isRunning) {
                Utils.showToast('🎉 Hoàn thành toàn bộ!', 'success');
                this.isRunning = false;
                UIManager.updateControlsState('stopped');
            }
        }

        stop() {
            this.isRunning = false;
            this.isPaused = false;
            UIManager.updateControlsState('stopped');
        }

        reset() {
            this.queue = [];
            this.currentIndex = 0;
            this.isRunning = false;
            this.isPaused = false;
        }
    }

    // ==================== UI MANAGER ====================
    class UIManager {
        static init() {
            this.injectStyles();
            this.createFloatingButton();
            this.createControlPanel();
            this.attachEventListeners();
            setInterval(() => this.updateResultsDisplay(), 2000);
        }

        static injectStyles() {
            GM_addStyle(`
                :root {
                    --osint-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    --osint-success: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
                    --osint-danger: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
                    --osint-info: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
                    --osint-dark: #1a1a2e;
                    --osint-card: rgba(255, 255, 255, 0.1);
                    --osint-text: #ffffff;
                    --osint-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                }

                .osint-float-btn {
                    position: fixed; bottom: 30px; right: 30px; width: 60px; height: 60px;
                    background: var(--osint-primary); border-radius: 50%; display: flex;
                    align-items: center; justify-content: center; cursor: pointer;
                    box-shadow: var(--osint-shadow); z-index: 999999; transition: all 0.3s ease;
                    border: none;
                }

                .osint-float-btn:hover {
                    transform: scale(1.1) rotate(5deg);
                    box-shadow: 0 12px 48px rgba(102, 126, 234, 0.5);
                }

                .osint-float-btn::before {
                    content: '📞'; font-size: 28px;
                }

                .osint-panel {
                    position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%) scale(0);
                    width: 700px; max-height: 80vh; background: rgba(26, 26, 46, 0.95);
                    backdrop-filter: blur(20px); border-radius: 20px; box-shadow: var(--osint-shadow);
                    z-index: 1000000; opacity: 0; transition: all 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
                    border: 1px solid rgba(255, 255, 255, 0.1); overflow: hidden; display: flex;
                    flex-direction: column;
                }

                .osint-panel.show {
                    transform: translate(-50%, -50%) scale(1); opacity: 1;
                }

                .osint-header {
                    background: var(--osint-primary); padding: 20px 25px; display: flex;
                    justify-content: space-between; align-items: center;
                }

                .osint-title {
                    font-size: 22px; font-weight: 700; color: var(--osint-text); margin: 0;
                    display: flex; align-items: center; gap: 10px;
                }

                .osint-close {
                    background: rgba(255, 255, 255, 0.2); border: none; width: 32px; height: 32px;
                    border-radius: 8px; cursor: pointer; font-size: 20px; color: white;
                    transition: all 0.3s;
                }

                .osint-close:hover {
                    background: rgba(255, 255, 255, 0.3); transform: rotate(90deg);
                }

                .osint-body {
                    padding: 25px; overflow-y: auto; flex: 1;
                }

                .osint-section {
                    margin-bottom: 20px;
                }

                .osint-label {
                    display: block; color: var(--osint-text); font-weight: 600;
                    margin-bottom: 10px; font-size: 14px;
                }

                .osint-textarea {
                    width: 100%; min-height: 120px; background: rgba(255, 255, 255, 0.05);
                    border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 12px;
                    color: var(--osint-text); font-size: 14px; font-family: 'Consolas', monospace;
                    resize: vertical; transition: all 0.3s;
                }

                .osint-textarea:focus {
                    outline: none; border-color: rgba(102, 126, 234, 0.5);
                    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
                    background: rgba(255, 255, 255, 0.08);
                }

                .osint-controls {
                    display: flex; gap: 10px; margin-bottom: 20px;
                }

                .osint-btn {
                    flex: 1; padding: 12px 20px; border: none; border-radius: 12px;
                    font-weight: 600; font-size: 14px; cursor: pointer; transition: all 0.3s;
                    color: white; position: relative; overflow: hidden;
                }

                .osint-btn::before {
                    content: ''; position: absolute; top: 50%; left: 50%; width: 0; height: 0;
                    border-radius: 50%; background: rgba(255, 255, 255, 0.3);
                    transform: translate(-50%, -50%); transition: width 0.6s, height 0.6s;
                }

                .osint-btn:hover::before {
                    width: 300px; height: 300px;
                }

                .osint-btn-start { background: var(--osint-success); }
                .osint-btn-stop { background: var(--osint-danger); }
                .osint-btn-export { background: var(--osint-info); }
                .osint-btn-clear { background: linear-gradient(135deg, #fc4a1a 0%, #f7b733 100%); }

                .osint-btn:disabled {
                    opacity: 0.5; cursor: not-allowed;
                }

                .osint-btn:hover:not(:disabled) {
                    transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
                }

                .osint-progress-container {
                    margin-bottom: 20px;
                }

                .osint-progress-bar {
                    width: 100%; height: 8px; background: rgba(255, 255, 255, 0.1);
                    border-radius: 10px; overflow: hidden;
                }

                .osint-progress-fill {
                    height: 100%; background: var(--osint-success); width: 0%;
                    transition: width 0.3s; border-radius: 10px;
                }

                .osint-progress-text {
                    text-align: center; color: var(--osint-text); font-size: 12px; margin-top: 5px;
                }

                .osint-results {
                    background: rgba(255, 255, 255, 0.05); border-radius: 12px;
                    overflow: hidden; max-height: 300px; overflow-y: auto;
                }

                .osint-table {
                    width: 100%; border-collapse: collapse;
                }

                .osint-table th {
                    background: rgba(102, 126, 234, 0.3); color: var(--osint-text);
                    padding: 12px; text-align: left; font-size: 13px; font-weight: 600;
                    position: sticky; top: 0;
                }

                .osint-table td {
                    color: var(--osint-text); padding: 10px 12px; font-size: 12px;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
                }

                .osint-table tr:hover {
                    background: rgba(255, 255, 255, 0.05);
                }

                .osint-status-badge {
                    display: inline-block; padding: 4px 8px; border-radius: 6px;
                    font-size: 11px; font-weight: 600;
                }

                .osint-status-completed {
                    background: rgba(56, 239, 125, 0.2); color: #38ef7d;
                }

                .osint-status-processing {
                    background: rgba(79, 172, 254, 0.2); color: #4facfe;
                }

                .osint-toast {
                    position: fixed; bottom: 100px; right: 30px;
                    background: rgba(26, 26, 46, 0.95); backdrop-filter: blur(10px);
                    color: white; padding: 15px 20px; border-radius: 12px;
                    box-shadow: var(--osint-shadow); z-index: 1000001;
                    transform: translateX(400px); transition: transform 0.3s;
                    max-width: 300px; border-left: 4px solid #667eea;
                }

                .osint-toast.show { transform: translateX(0); }
                .osint-toast-success { border-left-color: #38ef7d; }
                .osint-toast-error { border-left-color: #eb3349; }
                .osint-toast-warning { border-left-color: #f6d365; }

                .osint-body::-webkit-scrollbar, .osint-results::-webkit-scrollbar {
                    width: 8px;
                }

                .osint-body::-webkit-scrollbar-track, .osint-results::-webkit-scrollbar-track {
                    background: rgba(255, 255, 255, 0.05); border-radius: 10px;
                }

                .osint-body::-webkit-scrollbar-thumb, .osint-results::-webkit-scrollbar-thumb {
                    background: rgba(102, 126, 234, 0.5); border-radius: 10px;
                }

                .osint-body::-webkit-scrollbar-thumb:hover, .osint-results::-webkit-scrollbar-thumb:hover {
                    background: rgba(102, 126, 234, 0.7);
                }

                .osint-modal {
                    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                    background: rgba(0, 0, 0, 0.7); backdrop-filter: blur(5px);
                    z-index: 1000001; display: flex; align-items: center; justify-content: center;
                    opacity: 0; transition: opacity 0.3s;
                }

                .osint-modal.show { opacity: 1; }

                .osint-modal-content {
                    background: rgba(26, 26, 46, 0.95); backdrop-filter: blur(20px);
                    padding: 30px; border-radius: 16px; max-width: 400px; text-align: center;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                }

                .osint-modal-content h3 {
                    color: #f6d365; margin: 0 0 15px 0; font-size: 20px;
                }

                .osint-modal-content p {
                    color: var(--osint-text); margin: 0 0 20px 0; line-height: 1.5;
                }

                .osint-modal-buttons {
                    display: flex; gap: 10px;
                }
            `);
        }

        static createFloatingButton() {
            const btn = document.createElement('button');
            btn.className = 'osint-float-btn';
            btn.id = 'osint-toggle-btn';
            document.body.appendChild(btn);
        }

        static createControlPanel() {
            const panel = document.createElement('div');
            panel.className = 'osint-panel';
            panel.id = 'osint-panel';
            panel.innerHTML = `
                <div class="osint-header">
                    <h2 class="osint-title"><span>📞</span>OSINT Phone Lookup Tool</h2>
                    <button class="osint-close" id="osint-close-btn">×</button>
                </div>
                <div class="osint-body">
                    <div class="osint-section">
                        <label class="osint-label">📋 Danh sách số điện thoại (mỗi dòng 1 số):</label>
                        <textarea class="osint-textarea" id="osint-input" placeholder="0123456789&#10;0987654321"></textarea>
                    </div>
                    <div class="osint-section">
                        <div class="osint-controls">
                            <button class="osint-btn osint-btn-start" id="osint-start-btn">▶️ Start</button>
                            <button class="osint-btn osint-btn-stop" id="osint-stop-btn" disabled>⏹️ Stop</button>
                            <button class="osint-btn osint-btn-clear" id="osint-clear-btn">🗑️ Clear</button>
                        </div>
                    </div>
                    <div class="osint-section">
                        <div class="osint-controls">
                            <button class="osint-btn osint-btn-export" id="osint-export-json-btn">💾 JSON</button>
                            <button class="osint-btn osint-btn-export" id="osint-export-csv-btn">📊 CSV</button>
                            <button class="osint-btn osint-btn-export" id="osint-export-xml-btn">📄 TXT</button>
                        </div>
                    </div>
                    <div class="osint-section osint-progress-container" style="display: none;">
                        <div class="osint-progress-bar">
                            <div class="osint-progress-fill" id="osint-progress-fill"></div>
                        </div>
                        <div class="osint-progress-text" id="osint-progress-text">0 / 0</div>
                    </div>
                    <div class="osint-section">
                        <label class="osint-label">📊 Kết quả:</label>
                        <div class="osint-results">
                            <table class="osint-table">
                                <thead>
                                    <tr>
                                        <th>SĐT</th><th>Facebook</th><th>Google</th>
                                        <th>QuetSDT</th><th>Zalo</th><th>Status</th>
                                    </tr>
                                </thead>
                                <tbody id="osint-results-body">
                                    <tr><td colspan="6" style="text-align: center; opacity: 0.5;">Chưa có kết quả</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            `;
            document.body.appendChild(panel);
        }

        static attachEventListeners() {
            const toggleBtn = document.getElementById('osint-toggle-btn');
            const closeBtn = document.getElementById('osint-close-btn');
            const panel = document.getElementById('osint-panel');
            const startBtn = document.getElementById('osint-start-btn');
            const stopBtn = document.getElementById('osint-stop-btn');
            const clearBtn = document.getElementById('osint-clear-btn');
            const exportJsonBtn = document.getElementById('osint-export-json-btn');
            const exportCsvBtn = document.getElementById('osint-export-csv-btn');
            const exportTxtBtn = document.getElementById('osint-export-xml-btn');

            toggleBtn.addEventListener('click', () => panel.classList.toggle('show'));
            closeBtn.addEventListener('click', () => panel.classList.remove('show'));

            startBtn.addEventListener('click', async () => {
                const input = document.getElementById('osint-input').value;
                const count = queueManager.loadFromInput(input);
                if (count > 0) await queueManager.start();
            });

            stopBtn.addEventListener('click', () => queueManager.stop());

            clearBtn.addEventListener('click', () => {
                const results = DataCollector.loadAllResults();
                const count = Object.keys(results).length;
                if (count === 0) {
                    Utils.showToast('⚠️ Không có dữ liệu để xóa', 'warning');
                    return;
                }
                if (confirm(`Bạn có chắc muốn xóa ${count} kết quả? Nên Export trước khi xóa!`)) {
                    DataCollector.clearResults();
                    Utils.showToast('✅ Đã xóa toàn bộ kết quả', 'success');
                }
            });

            exportJsonBtn.addEventListener('click', () => {
                DataCollector.exportToJSON();
                Utils.showToast('✅ Đã export JSON', 'success');
            });

            exportCsvBtn.addEventListener('click', () => {
                DataCollector.exportToCSV();
                Utils.showToast('✅ Đã export CSV', 'success');
            });

            exportTxtBtn.addEventListener('click', () => {
                DataCollector.exportToTXT();
                Utils.showToast('✅ Đã export TXT', 'success');
            });
        }

        static updateControlsState(state) {
            const startBtn = document.getElementById('osint-start-btn');
            const stopBtn = document.getElementById('osint-stop-btn');
            const input = document.getElementById('osint-input');
            const progressContainer = document.querySelector('.osint-progress-container');

            if (state === 'running') {
                startBtn.disabled = true;
                stopBtn.disabled = false;
                input.disabled = true;
                progressContainer.style.display = 'block';
            } else {
                startBtn.disabled = false;
                stopBtn.disabled = true;
                input.disabled = false;
            }
        }

        static updateProgress(current, total) {
            const fill = document.getElementById('osint-progress-fill');
            const text = document.getElementById('osint-progress-text');
            const percentage = (current / total) * 100;
            fill.style.width = `${percentage}%`;
            text.textContent = `${current} / ${total}`;
        }

        static updateResultsDisplay() {
            const tbody = document.getElementById('osint-results-body');
            const results = DataCollector.loadAllResults();
            const entries = Object.values(results);

            if (entries.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; opacity: 0.5;">Chưa có kết quả</td></tr>`;
                return;
            }

            tbody.innerHTML = entries.map(item => `
                <tr>
                    <td><strong>${item.phone}</strong></td>
                    <td>${item.results.facebook ? '✅' : '⏳'}</td>
                    <td>${item.results.google ? '✅' : '⏳'}</td>
                    <td>${item.results.quetsdt ? '✅' : '⏳'}</td>
                    <td>${item.results.zalo ? '✅' : '⏳'}</td>
                    <td><span class="osint-status-badge osint-status-${item.status}">
                        ${item.status === 'completed' ? '✓ Hoàn thành' : '⏳ Đang xử lý'}
                    </span></td>
                </tr>
            `).join('');
        }
    }

    // ==================== TYPING SIMULATION ====================
    function typeIntoInput(element, text, delayMs = null) {
        return new Promise((resolve) => {
            let index = 0;
            function typeNextChar() {
                if (index < text.length) {
                    const char = text[index];
                    element.value += char;
                    element.dispatchEvent(new KeyboardEvent('keydown', { key: char, bubbles: true, cancelable: true }));
                    element.dispatchEvent(new KeyboardEvent('keypress', { key: char, bubbles: true, cancelable: true }));
                    element.dispatchEvent(new Event('input', { bubbles: true }));
                    element.dispatchEvent(new KeyboardEvent('keyup', { key: char, bubbles: true, cancelable: true }));
                    index++;
                    const delay = delayMs || (50 + Math.random() * 50);
                    setTimeout(typeNextChar, delay);
                } else {
                    element.dispatchEvent(new Event('change', { bubbles: true }));
                    resolve();
                }
            }
            typeNextChar();
        });
    }

    // ==================== AUTO-FILL FOR QUETSDT ====================
    function detectAndAutoFillQuetSDT() {
        if (!window.location.href.includes('uidphone.xyz')) return;

        const pendingPhone = GM_getValue('quetsdt_pending_phone', null);
        if (!pendingPhone) return;

        const module = CONFIG.searchModules.find(m => m.id === 'quetsdt');
        if (!module || !module.autoFill) return;

        setTimeout(() => {
            const inputSelector = module.selectors.input;
            const submitSelector = module.selectors.submit;
            const inputElement = document.querySelector(inputSelector);
            const submitElement = document.querySelector(submitSelector);

            if (inputElement && submitElement) {
                console.log('[OSINT] Auto-filling QuetSDT with:', pendingPhone);
                inputElement.click();
                setTimeout(() => {
                    inputElement.focus();
                    inputElement.value = '';
                    setTimeout(async () => {
                        await typeIntoInput(inputElement, pendingPhone, 60);
                        console.log('[OSINT] QuetSDT typing complete');
                        setTimeout(() => {
                            submitElement.click();
                            console.log('[OSINT] QuetSDT form submitted');
                            DataCollector.saveResult(pendingPhone, 'quetsdt', {
                                status: 'submitted',
                                timestamp: Utils.formatTimestamp()
                            });
                            GM_setValue('quetsdt_pending_phone', null);
                        }, 500);
                    }, 200);
                }, 200);
            } else {
                console.warn('[OSINT] QuetSDT selectors not found.');
                Utils.showToast('⚠️ Không tìm thấy form QuetSDT. Vui lòng cập nhật selectors!', 'warning');
            }
        }, 4000);
    }

    // ==================== AUTO-FILL FOR ZALO ====================
    function detectAndAutoFillZalo() {
        if (!window.location.href.includes('chat.zalo.me')) return;

        const pendingPhone = GM_getValue('zalo_pending_phone', null);
        if (!pendingPhone) return;

        const module = CONFIG.searchModules.find(m => m.id === 'zalo');
        if (!module || !module.autoFill) return;

        setTimeout(() => {
            const inputSelector = module.selectors.input;
            const inputElement = document.querySelector(inputSelector);

            if (inputElement) {
                console.log('[OSINT] Auto-filling Zalo with:', pendingPhone);
                try {
                    inputElement.style.border = '3px solid red';
                    inputElement.style.backgroundColor = '#fff0f0';
                    inputElement.focus();

                    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                    nativeInputValueSetter.call(inputElement, pendingPhone);

                    const inputEvent = new Event('input', { bubbles: true });
                    inputElement.dispatchEvent(inputEvent);

                    console.log('[OSINT] Zalo value set:', pendingPhone);

                    setTimeout(() => {
                        inputElement.style.border = '';
                        inputElement.style.backgroundColor = '';
                    }, 1000);

                    setTimeout(() => {
                        inputElement.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
                        inputElement.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', bubbles: true }));
                        console.log('[OSINT] Zalo search triggered');

                        DataCollector.saveResult(pendingPhone, 'zalo', {
                            status: 'search_triggered',
                            data: 'Đã điền số điện thoại',
                            timestamp: Utils.formatTimestamp()
                        });
                        GM_setValue('zalo_pending_phone', null);
                    }, 500);

                } catch (err) {
                    console.error('[OSINT] Error in Zalo auto-fill:', err);
                }
            } else {
                console.error('[OSINT] Zalo input not found');
                Utils.showToast('⚠️ Không tìm thấy input Zalo. Vui lòng kiểm tra selector!', 'warning');
            }
        }, 5000);
    }

    // ==================== INITIALIZATION WITH SECURITY CHECK ====================
    const queueManager = new QueueManager();

    async function initializeScript() {
        console.log('[OSINT] Starting security validation...');

        // Validate license first
        const isValid = await SecurityManager.validateLicense();

        if (!isValid) {
            console.error('[OSINT] Security validation failed. Script terminated.');
            return;
        }

        console.log('[OSINT] ✅ Security validation passed');

        // Initialize UI on master pages
        if (window.location.href.includes('google.com') || window.location.href.includes('about:blank')) {
            UIManager.init();
            Utils.showToast('🚀 OSINT Tool Ready! (Secure Edition v2.0.0)', 'success');
        }

        // Auto-fill on QuetSDT page
        if (window.location.href.includes('uidphone.xyz')) {
            detectAndAutoFillQuetSDT();
        }

        // Auto-fill on Zalo page
        if (window.location.href.includes('chat.zalo.me')) {
            detectAndAutoFillZalo();
        }
    }

    // Run initialization when page loads
    window.addEventListener('load', initializeScript);

    // Register menu command
    if (typeof GM_registerMenuCommand !== 'undefined') {
        GM_registerMenuCommand('🔄 Clear All Results', () => {
            if (confirm('Bạn có chắc muốn xóa toàn bộ kết quả?')) {
                DataCollector.clearResults();
                Utils.showToast('🗑️ Đã xóa toàn bộ kết quả', 'info');
            }
        });
    }

    console.log('[OSINT Phone Lookup Tool] Loaded successfully! Version 2.0.0 (Secure Edition)');

})();

