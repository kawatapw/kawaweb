/**
 * Kawata-Web Main Entry Point
 * Modernized JavaScript with proper dependency management and race condition prevention
 */

// ============================================================================
// 1. DEPENDENCY MANAGEMENT & INITIALIZATION
// ============================================================================

class KawataApp {
    constructor() {
        this.modules = new Map();
        this.isInitialized = false;
        this.initPromise = null;
        this.logger = null;
        this.componentPromises = new Map(); // Track component loading promises
    }

    /**
     * Initialize the application
     * @returns {Promise<void>}
     */
    async init() {
        if (this.initPromise) return this.initPromise;
        
        this.initPromise = this._initialize();
        return this.initPromise;
    }

    async _initialize() {
        try {
            // Wait for DOM to be ready
            if (document.readyState === 'loading') {
                await new Promise(resolve => document.addEventListener('DOMContentLoaded', resolve));
            }

            // Initialize logger first
            await this._initLogger();
            
            // Load core dependencies
            await this._loadDependencies();
            
            // Register modules
            this._registerModules();
            
            // Initialize components
            await this._initComponents();
            
            this.isInitialized = true;
            this.logger.info('APP', 'Kawata-Web initialized successfully');
            
        } catch (error) {
            console.error('[KawataApp] Initialization failed:', error);
            throw error;
        }
    }

    async _initLogger() {
        // Wait for ColorfulLogger to be available
        await this._waitForGlobal('ColorfulLogger', 5000);
        
        window.kawataLogger = ColorfulLogger;
        this.logger = ColorfulLogger.init({
            level: 'DEBUG',
            name: 'Kawata-Web',
            showTimestamp: true,
        });
        const logger = this.logger;
    }

    async _loadDependencies() {
        const dependencies = [
            { name: 'd3', url: 'https://d3js.org/d3.v7.min.js', timeout: 10000 },
            { name: 'jQuery', url: 'https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.slim.min.js', timeout: 10000 },
            { name: 'timeago', url: 'https://cdnjs.cloudflare.com/ajax/libs/timeago.js/4.0.2/timeago.min.js', timeout: 5000 },
        ];

        // Load dependencies sequentially to reduce memory pressure
        for (const dep of dependencies) {
            try {
                await this._loadScript(dep);
            } catch (error) {
                this.logger.warn('DEPENDENCY', `Failed to load ${dep.name}:`, error.message);
                // Continue with other dependencies
            }
        }
    }

    async _loadScript({ name, url, timeout }) {
        if (window[name]) {
            this.logger.debug('DEPENDENCY', `${name} already loaded`);
            return;
        }

        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = url;
            script.async = true;
            
            const timer = setTimeout(() => {
                script.remove();
                reject(new Error(`${name} load timeout`));
            }, timeout);

            script.onload = () => {
                clearTimeout(timer);
                this.logger.info('DEPENDENCY', `${name} loaded`);
                resolve();
            };

            script.onerror = () => {
                clearTimeout(timer);
                this.logger.error('DEPENDENCY', `${name} failed to load`);
                reject(new Error(`${name} load failed`));
            };

            document.head.appendChild(script);
        });
    }

    async _initComponents() {
        // Load event bus first — panels depend on EventBus class
        try {
            await this._loadComponent('/static/js/utils/eventBus.js', 'eventBus');
        } catch (error) {
            this.logger.error('COMPONENT', 'EventBus failed to load', error);
        }

        // Load navbar second (critical component)
        try {
            await this._loadComponent('/static/js/components/navbar.js', 'navbar');
        } catch (error) {
            this.logger.error('COMPONENT', 'Navbar failed to load', error);
        }

        // Load misc.js first — defines mixin_formatting / mixin_conversion used by other components
        try {
            await this._loadComponent('/static/js/components/misc.js', 'misc-components');
        } catch (error) {
            this.logger.error('COMPONENT', 'Misc components failed to load', error);
        }

        // Load new modular user profile components
        // These provide a modern, provide/inject-based architecture
        try {
            // Load user utilities first (dependencies for controller/provider)
            await this._loadComponent('/static/js/components/user/utils/constants.js', 'user-constants');
            await this._loadComponent('/static/js/components/user/utils/formatters.js', 'user-formatters');
            
            // Load core controller and provider
            await this._loadComponent('/static/js/components/user/user-data-controller.js', 'user-data-controller');
            await this._loadComponent('/static/js/components/user/user-data-provider.js', 'user-data-provider');
            
            // Load all individual user components (these register themselves with Vue)
            const userComponents = [
              'user-avatar',
              'user-name',
              'user-badges',
              'user-status',
              'user-stats',
              'user-card',
              'user-profile'
            ];
            
            for (const componentName of userComponents) {
              const path = `/static/js/components/user/components/${componentName}.js`;
              await this._loadComponent(path, componentName);
            }
            
            this.logger.info('COMPONENT', 'New user profile component system loaded');
        } catch (error) {
            this.logger.error('COMPONENT', 'Failed to load new user components', error);
        }

        // Load other components in parallel with proper error handling
        const componentPromises = [
            this._loadComponent('/static/js/utils/portal.js', 'portal').catch(() => {}),
            this._loadComponent('/static/js/components/shaders.js', 'shaders').catch(() => {}),
            this._loadComponent('/static/js/components/beatmap.js', 'beatmap').catch(() => {}),
            this._loadComponent('/static/js/components/score.js', 'score').catch(() => {}),
            this._loadComponent('/static/js/pages/panels/panels.js', 'panels').catch(() => {}),
            this._loadComponent('/static/js/pages/panels/beatmap.js', 'beatmap-panel').catch(() => {}),
            this._loadComponent('/static/js/pages/panels/score.js', 'score-panel').catch(() => {}),
        ];

        await Promise.allSettled(componentPromises);
    }

    async _loadComponent(url, name) {
        // Check if already loading
        if (this.componentPromises.has(name)) {
            return this.componentPromises.get(name);
        }

        const promise = new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = url;
            script.async = true;

            script.onload = () => {
                this.logger.info('COMPONENT', `${name} loaded`);
                // Clean up the promise from the map after successful load
                this.componentPromises.delete(name);
                resolve();
            };

            script.onerror = () => {
                this.logger.error('COMPONENT', `${name} failed to load`);
                // Clean up the promise from the map after failed load
                this.componentPromises.delete(name);
                reject(new Error(`Component ${name} failed`));
            };

            document.head.appendChild(script);
        });

        this.componentPromises.set(name, promise);
        return promise;
    }

    _registerModules() {
        // Register utility modules
        this.modules.set('difficulty', new DifficultyModule(this.logger));
        this.modules.set('utils', new UtilsModule(this.logger));
    }

    /**
     * Wait for a global variable to be defined
     * @param {string} globalName - Name of the global variable
     * @param {number} timeout - Timeout in ms
     * @returns {Promise<void>}
     */
    _waitForGlobal(globalName, timeout = 5000) {
        return new Promise((resolve, reject) => {
            if (window[globalName]) {
                resolve();
                return;
            }

            const start = Date.now();
            let intervalId;
            
            const check = () => {
                if (window[globalName]) {
                    clearInterval(intervalId);
                    resolve();
                } else if (Date.now() - start > timeout) {
                    clearInterval(intervalId);
                    reject(new Error(`Timeout waiting for ${globalName}`));
                }
            };
            
            // Check immediately
            check();
            
            // Use interval instead of recursive setTimeout
            intervalId = setInterval(check, 50);
            
            // Cleanup on resolve/reject
            const cleanup = () => {
                clearInterval(intervalId);
            };
            
            // Add cleanup to promise
            Promise.resolve().then(cleanup).catch(cleanup);
        });
    }

    /**
     * Get a registered module
     * @param {string} name
     * @returns {Object|null}
     */
    getModule(name) {
        return this.modules.get(name) || null;
    }

    /**
     * Cleanup method to prevent memory leaks
     */
    cleanup() {
        // Clear component promises
        this.componentPromises.clear();
        
        // Clear modules
        this.modules.clear();
        
        // Reset initialization state
        this.isInitialized = false;
        this.initPromise = null;
        
        // Remove DOMContentLoaded event listener if it exists
        if (domContentLoadedHandler) {
            document.removeEventListener('DOMContentLoaded', domContentLoadedHandler);
            domContentLoadedHandler = null;
        }
        
        if (this.logger) {
            this.logger.info('APP', 'Kawata-Web cleanup completed');
        }
    }
}

// ============================================================================
// 2. MODULE SYSTEM
// ============================================================================

class DifficultyModule {
    constructor(logger) {
        this.logger = logger;
        this.cache = new Map();
        this.scale = null;
        this._initScale();
    }

    _initScale() {
        if (!window.d3) {
            this.logger.warn('DIFFICULTY', 'D3 not available yet');
            return;
        }

        this.scale = d3.scaleLinear()
            .domain([0.1, 1.25, 2, 2.5, 3.3, 4.2, 4.9, 5.8, 6.7, 7.7, 9])
            .clamp(true)
            .range([
                '#4290FB', '#4FC0FF', '#4FFFD5', '#7CFF4F', '#F6F05C',
                '#FF8068', '#FF4E6F', '#C645B8', '#6563DE', '#18158E', '#000000'
            ])
            .interpolate(d3.interpolateRgb.gamma(2.2));
    }

    /**
     * Get RGB color for star rating
     * @param {number|string} stars
     * @returns {string} RGB string
     */
    getRGB(stars) {
        // Return cached value if available
        const cacheKey = String(stars);
        if (this.cache.has(cacheKey)) {
            return this.cache.get(cacheKey);
        }

        // Handle null/undefined
        if (!stars) {
            return '200, 200, 200';
        }

        // Ensure D3 is loaded
        if (!this.scale) {
            this._initScale();
            if (!this.scale) return '200, 200, 200';
        }

        try {
            const color = d3.color(this.scale(parseFloat(stars)));
            const rgb = color ? `${color.r}, ${color.g}, ${color.b}` : '200, 200, 200';
            
            // Cache the result
            this.cache.set(cacheKey, rgb);
            
            return rgb;
        } catch (error) {
            this.logger.error('DIFFICULTY', 'Color calculation failed', error);
            return '200, 200, 200';
        }
    }

    /**
     * Clear cache
     */
    clearCache() {
        this.cache.clear();
        this.logger.debug('DIFFICULTY', 'Cache cleared');
    }
}

class UtilsModule {
    constructor(logger) {
        this.logger = logger;
    }

    /**
     * Format number with commas
     * @param {number} num
     * @returns {string}
     */
    formatNumber(num) {
        if (num === null || num === undefined) return '0';
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }

    /**
     * Debounce function
     * @param {Function} func
     * @param {number} wait
     * @returns {Function}
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    /**
     * Throttle function
     * @param {Function} func
     * @param {number} limit
     * @returns {Function}
     */
    throttle(func, limit) {
        let inThrottle;
        return function(...args) {
            if (!inThrottle) {
                func(...args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
}

// ============================================================================
// 3. GLOBAL EXPORTS (Backward Compatibility)
// ============================================================================

/**
 * Legacy global function for difficulty colors
 * @deprecated Use window.kawataApp.getModule('difficulty').getRGB() instead
 */
window.getDifficultyRGB = function(stars) {
    if (!window.kawataApp || !window.kawataApp.isInitialized) {
        // Fallback for early calls
        if (!stars) return '200, 200, 200';
        try {
            if (window.d3) {
                const scale = d3.scaleLinear()
                    .domain([0.1, 1.25, 2, 2.5, 3.3, 4.2, 4.9, 5.8, 6.7, 7.7, 9])
                    .clamp(true)
                    .range(['#4290FB', '#4FC0FF', '#4FFFD5', '#7CFF4F', '#F6F05C', '#FF8068', '#FF4E6F', '#C645B8', '#6563DE', '#18158E', '#000000'])
                    .interpolate(d3.interpolateRgb.gamma(2.2));
                const color = d3.color(scale(parseFloat(stars)));
                return color ? `${color.r}, ${color.g}, ${color.b}` : '200, 200, 200';
            }
        } catch (e) {
            console.error('[DifficultyColor]', e);
        }
        return '200, 200, 200';
    }
    
    return window.kawataApp.getModule('difficulty').getRGB(stars);
};

// ============================================================================
// 4. MEMORY MONITOR
// ============================================================================
// ============================================================================
// 5. APPLICATION BOOTSTRAP
// ============================================================================

// Create and initialize the application
window.kawataApp = new KawataApp();

// Store DOMContentLoaded handler for cleanup
let domContentLoadedHandler = null;

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    domContentLoadedHandler = () => {
        window.kawataApp.init().catch(error => {
            console.error('Failed to initialize Kawata-Web:', error);
        });
        // Remove the event listener after it fires
        document.removeEventListener('DOMContentLoaded', domContentLoadedHandler);
        domContentLoadedHandler = null;
    };
    document.addEventListener('DOMContentLoaded', domContentLoadedHandler);
} else {
    window.kawataApp.init().catch(error => {
        console.error('Failed to initialize Kawata-Web:', error);
    });
}

// Export for module systems (if ever used)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { KawataApp, DifficultyModule, UtilsModule };
}