// Global constant for the storage key
const DEBUG_SECTIONS_STORAGE_KEY = 'KawataLoggerDebugSections';

/**
 * Colorful Logger for Browser
 * A standalone logger with color formatting, log levels, sections,
 * performance tracking, assertions, and grouping, similar to advanced Node.js and plugin loggers.
 * It provides a drop-in replacement for basic console logging with enhanced features
 * and includes a Vue.js plugin for easy integration.
 *
 * @module ColorfulLogger
 *
 * @property {object} LEVELS - Defines log levels and their associated styling.
 *   - TRACE: Detailed information, usually only of interest when diagnosing problems.
 *   - DEBUG: Fine-grained informational events that are most useful to debug an application.
 *   - INFO: Informational messages that highlight the progress of the application at coarse-grained level.
 *   - WARN: Potentially harmful situations.
 *   - ERROR: Error events that might still allow the application to continue running.
 *   - FATAL: Very severe error events that will presumably lead the application to abort.
 *   - SILENT: Turn off all logging.
 *
 * @property {number} currentLevel - The minimum level for messages to be logged. Defaults to DEBUG.
 * @property {string} name - The name of the logger instance, displayed in logs. Defaults to 'App'.
 * @property {boolean} showTimestamp - Whether to display a timestamp in log messages. Defaults to true.
 * @property {boolean} showLevel - Whether to display the log level in log messages. Defaults to true.
 * @property {string[]} debugSections - An array of section names for which debug logs should be displayed.
 *   If empty or not specified, debug logs are shown based on `currentLevel`.
 *   If `['ALL']`, all debug sections are shown.
 * @property {Map<string, number>} perfTimers - Internal map for tracking performance measurements.
 * @property {object} SECTION_COLORS - Predefined colors for different log sections.
 *
 * @method init(options) - Initializes the logger with custom options.
 *   @param {object} options - Configuration options.
 *     @param {string|number} [options.level='DEBUG'] - Initial log level.
 *     @param {string} [options.name='App'] - Logger name.
 *     @param {boolean} [options.showTimestamp=true] - Show timestamp.
 *     @param {boolean} [options.showLevel=true] - Show log level.
 *     @param {string[]} [options.debugSections=[]] - Array of sections to enable debug logging for.
 *       Use `['ALL']` to enable all debug sections.
 * @method setLevel(level) - Sets the current log level.
 * @method setName(name) - Sets the logger name.
 * @method setDebugSections(sections) - Sets the debug sections.
 * @method trace(section, ...args) - Logs a TRACE message. `section` is optional.
 * @method debug(section, ...args) - Logs a DEBUG message. `section` is required for filtering.
 * @method info(section, ...args) - Logs an INFO message. `section` is optional.
 * @method warn(section, ...args) - Logs a WARN message. `section` is optional.
 * @method error(section, ...args) - Logs an ERROR message. `section` is optional.
 * @method fatal(section, ...args) - Logs a FATAL message. `section` is optional.
 * @method child(name) - Creates a child logger with an extended name.
 * @method perfStart(name) - Starts a performance timer.
 * @method perfEnd(name, extra) - Ends a performance timer and logs the duration.
 * @method assert(condition, section, message, data, hard) - Asserts a condition, logs an error if false.
 * @method groupDebug(section, title, fn) - Creates a collapsed log group for debug messages.
 * @method install(Vue, options) - Vue.js plugin installation method.
 *
 * @example
 * // Regular JavaScript Usage
 * const logger = ColorfulLogger.init({
 *     level: 'DEBUG',
 *     name: 'MyWebApp',
 *     showTimestamp: true,
 *     debugSections: ['UI', 'API'] // Only show debug logs for 'UI' and 'API' sections
 * });
 *
 * logger.info('UI', 'User clicked button');
 * logger.debug('API', 'Fetching data for user', { userId: 123 }); // Will show
 * logger.debug('RENDER', 'Component re-rendered'); // Will NOT show (not in debugSections)
 * logger.warn('Config', 'Missing configuration file');
 * logger.error('Auth', 'Authentication failed', new Error('Invalid credentials'));
 *
 * logger.perfStart('loadData');
 * // ... some asynchronous operation ...
 * setTimeout(() => {
 *   logger.perfEnd('loadData', { items: 100 }); // Logs 'loadData (XXX ms)'
 * }, 500);
 *
 * logger.assert(1 === 2, 'Logic', 'One does not equal two!', { value1: 1, value2: 2 });
 *
 * logger.groupDebug('UI', 'Initializing UI components', () => {
 *   logger.debug('UI', 'Header initialized');
 *   logger.debug('UI', 'Sidebar initialized');
 * });
 *
 * @example
 * // Vue.js Usage
 * // In your main.js or app entry file:
 * import Vue from 'vue';
 * // ... ColorfulLogger code ...
 *
 * Vue.use(ColorfulLogger, {
 *     level: 'INFO',
 *     name: 'VueApp',
 *     showTimestamp: true,
 *     debugSections: ['Components']
 * });
 *
 * // In a Vue component:
 * export default {
 *   name: 'MyComponent', // Important for child logger naming
 *   created() {
 *     this.$log.info('Lifecycle', 'Component created');
 *     this.$log.debug('Components', 'Component specific debug message'); // Will show if 'Components' is in debugSections
 *     this.$log.warn('Data', 'No data loaded yet');
 *   }
 * }
 */
(function() {
    const ColorfulLogger = {
        // Log levels with their colors for pills
        LEVELS: {
            TRACE: { value: 0, color: '#6c757d', textColor: 'white', style: 'font-weight: normal' }, // Dark grey
            DEBUG: { value: 1, color: '#0dcaf0', textColor: '#111', style: 'font-weight: normal' }, // Light blue
            INFO: { value: 2, color: '#0d6efd', textColor: 'white', style: 'font-weight: bold' }, // Blue
            WARN: { value: 3, color: '#ffc107', textColor: '#111', style: 'font-weight: bold' }, // Yellow
            ERROR: { value: 4, color: '#dc3545', textColor: 'white', style: 'font-weight: bold' }, // Red
            FATAL: { value: 5, color: '#dc3545', textColor: 'white', style: 'font-weight: bold' }, // Red (same as error, but distinct level)
            SILENT: { value: 6, color: '', textColor: '', style: '' }
        },

        // Current log level
        currentLevel: 1, // DEBUG by default

        // Logger name/prefix
        name: 'App',

        // Show timestamp in logs
        showTimestamp: true,

        // Show log level in logs
        showLevel: true,

        // Sections for which debug logs are enabled. Use ['ALL'] for all sections.
        debugSections: [], // Default to empty, will be populated by init

        // Internal map for performance timers
        perfTimers: new Map(),

        // Base style for all pills
        BASE_PILL_STYLE: 'padding:2px 6px;border-radius:999px;font-weight:600;font-size:11px;',

        // Logger Name Pill Style
        NAME_PILL_STYLE: 'background:#0d6efd;color:white;', // Blue background for logger name

        // Timestamp Pill Style
        TIMESTAMP_PILL_STYLE: 'background:#6c757d;color:white;font-weight:normal;', // Dark grey for timestamp

        // Special Pill Styles
        PERF_PILL_STYLE: 'background:#c6a0f6;color:#111;', // Purple for PERF
        ASSERT_PILL_STYLE: 'background:#ed8796;color:#111;', // Red for ASSERT

        // Section colors
        SECTION_COLORS: {
            DEFAULT: '#b7bdf8', // Light purple
            UI: '#8aadf4',      // Light blue
            API: '#a6da95',     // Light green
            DATA: '#eed49f',    // Light yellow
            AUTH: '#f5a97f',    // Light orange
            CONFIG: '#91d7e3',  // Cyan
            RENDER: '#c6a0f6',  // Purple
            LIFECYCLE: '#c6a0f6', // Purple
            LOGIC: '#a6da95',   // Light green
            EVENT: '#91d7e3',   // Cyan
            STORAGE: '#eed49f', // Light yellow
            NETWORK: '#f5a97f', // Light orange
            UTIL: '#b7bdf8',     // Light purple
            SCORE: '#91d7e3' // Example for score-card component
        },

        // Known sections for argument parsing (for `_parseArgs` helper) - Kept for reference, but _parseArgs is more flexible now
        _KNOWN_SECTIONS: [
            "UI", "API", "DATA", "AUTH", "CONFIG", "RENDER", "PERF", "LIFECYCLE", "LOGIC", "EVENT", "STORAGE", "NETWORK", "UTIL", "SCORE", "COMPONENTS"
        ],

        // Initialize the logger
        init: function(options = {}) {
            // 1. Load from localStorage first, this is the highest priority for initial state
            let initialDebugSections = [];
            const storedDebugSections = localStorage.getItem(DEBUG_SECTIONS_STORAGE_KEY);
            if (storedDebugSections) {
                try {
                    const sections = JSON.parse(storedDebugSections);
                    if (Array.isArray(sections)) {
                        initialDebugSections = sections.map(s => s.trim().toUpperCase());
                    }
                } catch (e) {
                    console.warn('ColorfulLogger: Could not parse stored debug sections from localStorage. Clearing it.', e);
                    localStorage.removeItem(DEBUG_SECTIONS_STORAGE_KEY);
                }
            }

            // 2. Apply general options
            if (options.level !== undefined) {
                this.setLevel(options.level);
            }

            if (options.name !== undefined) {
                this.name = options.name;
            }

            if (options.showTimestamp !== undefined) {
                this.showTimestamp = !!options.showTimestamp;
            }

            if (options.showLevel !== undefined) {
                this.showLevel = !!options.showLevel;
            }

            // 3. Determine final debugSections: options.debugSections > localStorage > default empty
            if (options.debugSections !== undefined) {
                this.debugSections = Array.isArray(options.debugSections) ? options.debugSections.map(s => s.toUpperCase()) : [];
                // If options explicitly set it, save this new state to localStorage
                localStorage.setItem(DEBUG_SECTIONS_STORAGE_KEY, JSON.stringify(this.debugSections));
                this.info('Config', `Initialized debug sections from options: [${this.debugSections.join(', ')}]`);
            } else {
                // No debugSections in options, so use the initialDebugSections loaded from localStorage
                this.debugSections = initialDebugSections;
                if (this.debugSections.length > 0) {
                    this.info('Config', `Loaded debug sections from localStorage: [${this.debugSections.join(', ')}]`);
                }
            }

            // Return the logger for chaining
            return this;
        },

        // Set the log level
        setLevel: function(level) {
            if (typeof level === 'string') {
                const levelName = level.toUpperCase();
                if (this.LEVELS[levelName]) {
                    this.currentLevel = this.LEVELS[levelName].value;
                }
            } else if (typeof level === 'number') {
                this.currentLevel = level;
            }
            return this;
        },

        // Set the logger name
        setName: function(name) {
            this.name = name;
            return this;
        },

        // Set debug sections AND persist to localStorage
        setDebugSections: function(sections) {
            this.debugSections = Array.isArray(sections) ? sections.map(s => s.trim().toUpperCase()) : [];
            // Persist to localStorage whenever setDebugSections is explicitly called
            localStorage.setItem(DEBUG_SECTIONS_STORAGE_KEY, JSON.stringify(this.debugSections));
            return this;
        },

        // Check if a debug section is enabled
        _isDebugEnabled: function(section) {
            if (!section) {
                // If no section is provided, debug logs are only shown if 'ALL' is enabled.
                return this.debugSections.includes('ALL');
            }
            const upperSection = section.toUpperCase();
            if (this.debugSections.includes('ALL')) return true;
            return this.debugSections.includes(upperSection);
        },

        // Format the log message with pills (message is returned separately now)
        _formatPillParts: function(levelName, section, logType, message) {
            const levelInfo = this.LEVELS[levelName];

            const formatParts = [];
            const styleParts = [];

            // Helper to add a pill
            const addPill = (text, style) => {
                formatParts.push(`%c${text}`);
                styleParts.push(this.BASE_PILL_STYLE + style);
            };

            // 1. Logger Name Pill
            addPill(this.name, this.NAME_PILL_STYLE);

            // 2. Timestamp Pill (if enabled)
            if (this.showTimestamp) {
                const now = new Date();
                const hours = String(now.getHours()).padStart(2, '0');
                const minutes = String(now.getMinutes()).padStart(2, '0');
                const seconds = String(now.getSeconds()).padStart(2, '0');
                const milliseconds = String(now.getMilliseconds()).padStart(3, '0');
                addPill(`${hours}:${minutes}:${seconds}.${milliseconds}`, this.TIMESTAMP_PILL_STYLE + 'margin-left:4px;');
            }

            // 3. Log Type Pill (e.g., PERF, ASSERT, GROUP)
            if (logType === 'PERF') {
                addPill('PERF', this.PERF_PILL_STYLE + 'margin-left:4px;');
            } else if (logType === 'ASSERT') {
                addPill('ASSERT', this.ASSERT_PILL_STYLE + 'margin-left:4px;');
            } else if (logType !== 'GROUP' && this.showLevel) { // Only show level pill if not a group and showLevel is true
                // 4. Level Pill (if not special log type)
                addPill(levelName, `background:${levelInfo.color};color:${levelInfo.textColor};${levelInfo.style};margin-left:4px;`);
            }

            // 5. Section Pill (if provided)
            if (section) {
                const sectionColor = this.SECTION_COLORS[section.toUpperCase()] || this.SECTION_COLORS.DEFAULT;
                addPill(section.toUpperCase(), `background:${sectionColor};color:#111;margin-left:4px;`);
            }

            // Combine all parts. The actual message will be passed separately.
            const finalFormatString = formatParts.join(' ');

            return {
                formatString: finalFormatString,
                styles: styleParts,
                originalMessage: message // Return the message separately
            };
        },

        // Helper to parse section and message from args for methods where section is optional
        _parseArgs: function(args) {
            let section = null;
            let message = '';
            let dataArgs = [];

            // If the first argument is a string and the second is also a string,
            // assume the first is a section and the second is the message.
            if (args.length >= 2 && typeof args[0] === 'string' && typeof args[1] === 'string') {
                section = args[0];
                message = args[1];
                dataArgs = args.slice(2);
            }
            // If only the first argument is a string, assume it's the message (no section)
            else if (args.length >= 1 && typeof args[0] === 'string') {
                message = args[0];
                dataArgs = args.slice(1);
            }
            // Otherwise, no string message or section, all are dataArgs
            else {
                dataArgs = args.slice(0);
            }
            return { section, message, dataArgs };
        },

        // Helper to parse section and message from args, specifically for debug where section is "required"
        _parseDebugArgs: function(args) {
            let section = null;
            let message = '';
            let dataArgs = [];

            // For debug, assume the first string argument is always the section.
            if (args.length > 0 && typeof args[0] === 'string') {
                section = args[0];
                // The second argument is the message, if it's a string
                message = typeof args[1] === 'string' ? args[1] : '';
                // Remaining arguments are data
                dataArgs = args.slice(2);
            } else {
                // If no string is provided as the first arg, then no section and no message
                dataArgs = args.slice(0); // All args are data
            }
            return { section, message, dataArgs };
        },

        // Log methods for each level
        trace: function(...args) {
            if (this.currentLevel <= this.LEVELS.TRACE.value) {
                const { section, message, dataArgs } = this._parseArgs(args);
                const formatted = this._formatPillParts('TRACE', section, 'LOG', message);
                if (formatted.originalMessage) {
                    console.log(formatted.formatString, ...formatted.styles, formatted.originalMessage, ...dataArgs);
                } else {
                    console.log(formatted.formatString, ...formatted.styles, ...dataArgs);
                }
            }
            return this;
        },

        debug: function(...args) {
            const { section, message, dataArgs } = this._parseDebugArgs(args); // Use the new helper
            if (this.currentLevel <= this.LEVELS.DEBUG.value && this._isDebugEnabled(section)) {
                const formatted = this._formatPillParts('DEBUG', section, 'LOG', message);
                if (formatted.originalMessage) {
                    console.log(formatted.formatString, ...formatted.styles, formatted.originalMessage, ...dataArgs);
                } else {
                    console.log(formatted.formatString, ...formatted.styles, ...dataArgs);
                }
            }
            return this;
        },

        info: function(...args) {
            if (this.currentLevel <= this.LEVELS.INFO.value) {
                const { section, message, dataArgs } = this._parseArgs(args);
                const formatted = this._formatPillParts('INFO', section, 'LOG', message);
                if (formatted.originalMessage) {
                    console.info(formatted.formatString, ...formatted.styles, formatted.originalMessage, ...dataArgs);
                } else {
                    console.info(formatted.formatString, ...formatted.styles, ...dataArgs);
                }
            }
            return this;
        },

        warn: function(...args) {
            if (this.currentLevel <= this.LEVELS.WARN.value) {
                const { section, message, dataArgs } = this._parseArgs(args);
                const formatted = this._formatPillParts('WARN', section, 'LOG', message);
                if (formatted.originalMessage) {
                    console.warn(formatted.formatString, ...formatted.styles, formatted.originalMessage, ...dataArgs);
                } else {
                    console.warn(formatted.formatString, ...formatted.styles, ...dataArgs);
                }
            }
            return this;
        },

        error: function(...args) {
            if (this.currentLevel <= this.LEVELS.ERROR.value) {
                const { section, message, dataArgs } = this._parseArgs(args);
                const formatted = this._formatPillParts('ERROR', section, 'LOG', message);
                if (formatted.originalMessage) {
                    console.error(formatted.formatString, ...formatted.styles, formatted.originalMessage, dataArgs);
                } else {
                    console.error(formatted.formatString, ...formatted.styles, ...dataArgs);
                }
            }
            return this;
        },

        fatal: function(...args) {
            if (this.currentLevel <= this.LEVELS.FATAL.value) {
                const { section, message, dataArgs } = this._parseArgs(args);
                const formatted = this._formatPillParts('FATAL', section, 'LOG', message);
                if (formatted.originalMessage) {
                    console.error(formatted.formatString, ...formatted.styles, formatted.originalMessage, ...dataArgs);
                } else {
                    console.error(formatted.formatString, ...formatted.styles, ...dataArgs);
                }
            }
            return this;
        },

        // Create a child logger with a different name
        child: function(name) {
            const childLogger = Object.create(this);
            childLogger.name = this.name + ':' + name;
            // Child loggers inherit parent's debugSections and perfTimers map by prototype chain.
            return childLogger;
        },

        // Performance tracking
        perfStart: function(name) {
            // Perf logs are tied to DEBUG level and the 'PERF' debug section
            if (this.currentLevel <= this.LEVELS.DEBUG.value && this._isDebugEnabled('PERF')) {
                this.perfTimers.set(name, performance.now());
            }
        },

        perfEnd: function(name, extra) {
            if (this.currentLevel <= this.LEVELS.DEBUG.value && this._isDebugEnabled('PERF')) {
                const start = this.perfTimers.get(name);
                if (start === undefined) {
                    this.warn('PERF', `perfEnd called for non-existent timer: ${name}`);
                    return;
                }
                this.perfTimers.delete(name);
                const duration = performance.now() - start;
                const message = `${name} (${duration.toFixed(2)} ms)`;
                // Use INFO level for perf logs, but with the PERF logType pill
                const formatted = this._formatPillParts('INFO', 'PERF', 'PERF', message);
                if (extra !== undefined) {
                    console.log(formatted.formatString, ...formatted.styles, formatted.originalMessage, extra);
                } else {
                    console.log(formatted.formatString, ...formatted.styles, formatted.originalMessage);
                }
            }
        },

        // Assertions
        assert: function(condition, section, message, data, hard = false) {
            // Assertions are typically debug-related, but can be critical.
            // We'll tie them to ERROR level and section filtering.
            if (this.currentLevel <= this.LEVELS.ERROR.value && this._isDebugEnabled(section)) {
                if (!condition) {
                    const formatted = this._formatPillParts('ERROR', section, 'ASSERT', message);
                    if (data !== undefined) {
                        console.error(formatted.formatString, ...formatted.styles, formatted.originalMessage, data);
                    } else {
                        console.error(formatted.formatString, ...formatted.styles, formatted.originalMessage);
                    }

                    if (hard) {
                        throw new Error(`[${this.name} ASSERT - ${section}] ${message}`);
                    }
                }
            }
        },

        // Grouping debug logs
        groupDebug: function(section, title, fn) {
            // Group debug logs are tied to DEBUG level and section filtering
            if (this.currentLevel <= this.LEVELS.DEBUG.value && this._isDebugEnabled(section)) {
                const formatted = this._formatPillParts('DEBUG', section, 'GROUP', title);
                // For groupCollapsed, the title should follow the pills directly.
                console.groupCollapsed(formatted.formatString + (formatted.originalMessage ? ' ' + formatted.originalMessage : ''), ...formatted.styles);
                try {
                    fn();
                } finally {
                    console.groupEnd();
                }
            }
        },

        // Vue.js plugin
        install: function(Vue, options = {}) {
            // Initialize with options
            this.init(options);

            // Add to Vue prototype
            Vue.prototype.$log = this;

            // Log initialization as info
            this.info('Lifecycle', 'ColorfulLogger initialized as Vue plugin.'); // Use the logger here

            // Add a mixin to create component-specific loggers
            Vue.mixin({
                created: function() {
                    // Create a component-specific logger if the component has a name
                    if (this.$options.name) {
                        this.$log = ColorfulLogger.child(this.$options.name);
                    }
                }
            });
        },

        // New methods for console control and persistence
        // Enable debug sections via a comma-separated string or array
        enableDebug: function(sectionsInput) {
            let sectionsArray = [];
            if (typeof sectionsInput === 'string') {
                sectionsArray = sectionsInput.split(',').map(s => s.trim().toUpperCase()).filter(s => s);
            } else if (Array.isArray(sectionsInput)) {
                sectionsArray = sectionsInput.map(s => s.trim().toUpperCase()).filter(s => s);
            } else if (sectionsInput === 'ALL') { // Allow 'ALL' as a string
                sectionsArray = ['ALL'];
            }
            this.setDebugSections(sectionsArray); // This will now also save to localStorage
            this.info('Config', `Debug sections enabled: [${this.debugSections.join(', ')}]`);
            return this;
        },

        // Clear all debug sections
        disableDebug: function() {
            this.setDebugSections([]); // This will now also save an empty array to localStorage
            this.info('Config', 'All debug sections disabled.');
            return this;
        },

        // Clear all stored debug sections from localStorage
        clearStoredDebugSections: function() {
            localStorage.removeItem(DEBUG_SECTIONS_STORAGE_KEY);
            this.info('Config', 'Cleared stored debug sections from localStorage.');
            return this;
        }
    };

    // Expose to global scope
    window.ColorfulLogger = ColorfulLogger;

    // --- Initial Setup and URL Parameter Handling ---
    // The init method now handles loading from localStorage directly.
    // The `debugSections` option in Vue.use/init will override localStorage for that specific initialization.
    // URL parameters will then override both and also persist their value.

    // This block now simply calls init with the desired default options.
    // We omit `debugSections` from the options here, so `init` will primarily rely on localStorage.
    if (typeof Vue !== 'undefined' && Vue.use) {
        Vue.use(ColorfulLogger, {
            level: 'DEBUG',
            name: 'Kawata-Web',
            showTimestamp: true,
            showLevel: true,
            // Omit debugSections here. `init` will load from localStorage or default to empty.
        });
    } else {
        ColorfulLogger.init({
            level: 'DEBUG',
            name: 'Kawata-Web',
            showTimestamp: true,
            showLevel: true,
            // Omit debugSections here. `init` will load from localStorage or default to empty.
        });
    }

    // URL parameters should still override everything and persist their value.
    const urlParams = new URLSearchParams(window.location.search);
    const logLevelParam = urlParams.get('logLevel');
    if (logLevelParam && ColorfulLogger.LEVELS[logLevelParam.toUpperCase()]) {
        ColorfulLogger.setLevel(logLevelParam.toUpperCase());
        ColorfulLogger.info('Config', `Overriding log level with URL param: ${logLevelParam}`);
    }

    const debugSectionsParam = urlParams.get('debugSections');
    if (debugSectionsParam) {
        // This will call setDebugSections, which saves to localStorage.
        ColorfulLogger.setDebugSections(debugSectionsParam.split(',').map(s => s.trim().toUpperCase()));
        ColorfulLogger.info('Config', `Overriding debug sections with URL param: [${debugSectionsParam}]`);
    }
})();
