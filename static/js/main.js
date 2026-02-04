
// sticky header
$(window).scroll(() => {
    var header = document.getElementById("navbar");
    var sticky = header.offsetTop;

    if (window.pageYOffset > sticky) {
        header.classList.add("minimized");
    } else {
        header.classList.remove("minimized");
    }
});

//toggle navbar for mobile
function togglenavbar() {
    document.getElementById('navbar').classList.toggle("is-active");
    document.getElementById('navbar-burger').classList.toggle("is-active");
}

// Mobile dropdown toggle
document.addEventListener('click', function(e) {
  var link = e.target.closest('.navbar-item.has-dropdown > .navbar-link');
  if (!link) return;

  // Only on mobile (when hamburger is visible)
  if (window.innerWidth >= 1024) return;

  e.preventDefault();
  var parent = link.parentElement;

  // Close other open dropdowns
  document.querySelectorAll('.navbar-item.has-dropdown.is-active').forEach(function(el) {
    if (el !== parent) el.classList.remove('is-active');
  });

  parent.classList.toggle('is-active');
});

// Initialize ColorfulLogger
window.kawataLogger = ColorfulLogger;
const logger = ColorfulLogger.init({
    level: 'DEBUG',
    name: 'Kawata-Web',
    showTimestamp: true,
});

/**
 * Portal Popup System
 * 
 * A comprehensive popup management system that ensures popups always appear on top of other 
 * elements by using a fixed-position portal container. This system works seamlessly with both 
 * regular HTML elements and Vue components, providing automatic positioning, event handling, 
 * and dynamic element support.
 * 
 * @class PopupPortal
 * @description Creates a portal-based popup system that clones and manages popups in a 
 *              dedicated container to ensure proper z-index stacking and positioning.
 * 
 * @example
 * // Basic usage with HTML elements
 * <div data-popup-trigger>
 *   <button>Hover me</button>
 *   <div data-popup class="my-popup">Popup content</div>
 * </div>
 * 
 * // Auto-initializes on DOMContentLoaded
 * // Access via: window.defaultPopupPortal
 * 
 * @example
 * // Custom configuration
 * const portal = new PopupPortal({
 *   showOnHover: true,
 *   showOnClick: false,
 *   positionStrategy: 'bottom',
 *   offset: 15,
 *   onShow: (popupId, trigger, popup) => {
 *     console.log('Popup shown:', popupId);
 *   }
 * });
 * 
 * @example
 * // Vue directive usage
 * <div v-portal-popup>
 *   <button>Hover me</button>
 *   <div class="my-popup">Popup content</div>
 * </div>
 * 
 * // Vue prototype access
 * this.$popupPortal.show('trigger-id');
 * 
 * @example
 * // Manual control
 * const portal = new PopupPortal();
 * portal.show('my-trigger-id');  // Show popup
 * portal.hide('my-trigger-id');  // Hide popup
 * portal.hideAllPopups();        // Hide all popups
 * portal.destroy();              // Clean up and remove portal
 * 
 * @fires PopupPortal#show - When a popup is shown
 * @fires PopupPortal#hide - When a popup is hidden
 * 
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/MutationObserver} MutationObserver API
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/Element/getBoundingClientRect} getBoundingClientRect API
 * 
 * @author Kawata Web Team
 * @version 1.0.0
 * @license MIT
 * 
 * @todo Add support for touch events on mobile devices
 * @todo Add animation customization options
 * @todo Add support for multiple popups on same trigger
 */
(function() {
    if (window.Vue && !window.beatmapBus) {
        window.beatmapBus = new Vue();
    }
    if (window.Vue && !window.scoreBus) {
        window.scoreBus = new Vue();
    }
    // Create a container for all portaled popups
    const createPortalContainer = () => {
      const container = document.createElement('div');
      container.id = 'popup-portal-container';
      container.style.position = 'fixed';
      container.style.top = '0';
      container.style.left = '0';
      container.style.width = '100%';
      container.style.height = '100%';
      container.style.pointerEvents = 'none';
      container.style.zIndex = '9999';
      container.style.overflow = 'visible';
      document.body.appendChild(container);
      return container;
    };
  
    // Get or create the portal container
    const getPortalContainer = () => {
      return document.getElementById('popup-portal-container') || createPortalContainer();
    };
  
    // Main portal class
    class PopupPortal {
      /**
       * Creates a new PopupPortal instance.
       * 
       * @constructor
       * @param {Object} [options={}] - Configuration options for the portal
       * @param {string} [options.triggerSelector='[data-popup-trigger]'] - CSS selector for popup triggers
       * @param {string} [options.popupSelector='[data-popup]'] - CSS selector for popup elements
       * @param {string} [options.activeClass='popup-active'] - Class added to trigger when popup is visible
       * @param {boolean} [options.showOnHover=true] - Show popup on mouse hover
       * @param {boolean} [options.showOnClick=false] - Toggle popup on click
       * @param {boolean} [options.closeOnClickOutside=true] - Close popup when clicking outside
       * @param {boolean} [options.closeOnEsc=true] - Close popup when pressing Escape key
       * @param {number} [options.animationDuration=300] - Fade animation duration in milliseconds
       * @param {string} [options.positionStrategy='auto'] - Position strategy: 'auto', 'top', 'bottom', 'left', 'right'
       * @param {number} [options.offset=10] - Pixel offset from trigger element
       * @param {number} [options.zIndex=9999] - Z-index for portal container
       * @param {Function|null} [options.onShow=null] - Callback when popup is shown
       * @param {Function|null} [options.onHide=null] - Callback when popup is hidden
       * 
       * @example
       * // Default configuration
       * const portal = new PopupPortal();
       * 
       * @example
       * // Custom configuration
       * const portal = new PopupPortal({
       *   showOnHover: false,
       *   showOnClick: true,
       *   positionStrategy: 'bottom',
       *   offset: 15,
       *   onShow: (id, trigger, popup) => {
       *     console.log('Popup shown:', id);
       *   }
       * });
       * 
       * @description
       * <b>Position Strategy Options:</b>
       * - 'auto': Automatically detects best position based on available space
       * - 'top': Positions popup above the trigger
       * - 'bottom': Positions popup below the trigger
       * - 'left': Positions popup to the left of the trigger
       * - 'right': Positions popup to the right of the trigger
       * 
       * <b>Event Handling:</b>
       * - Hover mode: Shows on mouseenter, hides on mouseleave
       * - Click mode: Toggles visibility on click
       * - Click outside: Closes popup when clicking outside both trigger and popup
       * - Escape key: Closes the active popup
       * 
       * @fires PopupPortal#show - When popup becomes visible
       * @fires PopupPortal#hide - When popup becomes hidden
       * 
       * @see {@link PopupPortal#init} Initialization process
       * @see {@link PopupPortal#setupTriggers} Trigger setup
       * @see {@link PopupPortal#positionPopup} Positioning logic
       */
      constructor(options = {}) {
        this.options = Object.assign({
          triggerSelector: '[data-popup-trigger]',
          popupSelector: '[data-popup]',
          activeClass: 'popup-active',
          showOnHover: true,
          showOnClick: false,
          closeOnClickOutside: true,
          closeOnEsc: true,
          animationDuration: 300,
          positionStrategy: 'auto', // 'auto', 'top', 'bottom', 'left', 'right'
          offset: 10,
          zIndex: 9999,
          onShow: null,
          onHide: null
        }, options);
        
        // Map storing all popup references
        // Key: popupId (string), Value: { trigger, originalPopup, portaledPopup, visible, hideTimeout }
        this.popups = new Map();
        
        // Currently active/visible popup ID
        this.activePopup = null;
        
        // Reference to the portal container element
        this.portalContainer = getPortalContainer();
        
        // Initialize the portal system
        this.init();
      }
      
      /**
       * Initializes the popup portal system.
       * 
       * @private
       * @description
       * This method is automatically called by the constructor and performs the following:
       * 1. Scans the DOM for existing popup triggers and sets them up
       * 2. Creates a MutationObserver to handle dynamically added elements
       * 3. Registers global event listeners for click-outside and escape key
       * 4. Adds resize and scroll listeners to update popup positions
       * 
       * @fires PopupPortal#init - When initialization is complete
       * 
       * @see {@link PopupPortal#setupTriggers} Sets up existing triggers
       * @see {@link PopupPortal#setupMutationObserver} Sets up dynamic element detection
       * @see {@link PopupPortal#handleDocumentClick} Click-outside handler
       * @see {@link PopupPortal#handleKeyDown} Escape key handler
       * @see {@link PopupPortal#updatePositions} Position update handler
       */
      init() {
        // Initialize for existing elements
        this.setupTriggers();
        
        // Set up mutation observer to handle dynamically added elements
        this.setupMutationObserver();
        
        // Global event listeners
        if (this.options.closeOnClickOutside) {
          document.addEventListener('click', this.handleDocumentClick.bind(this));
        }
        
        if (this.options.closeOnEsc) {
          document.addEventListener('keydown', this.handleKeyDown.bind(this));
        }
        
        // Handle window resize and scroll
        // Use passive event listeners for better performance
        window.addEventListener('resize', this.updatePositions.bind(this));
        window.addEventListener('scroll', this.updatePositions.bind(this), { passive: true, capture: true });
      }

      /**
       * Clones event handlers from source element to destination element.
       * 
       * @private
       * @param {HTMLElement} source - The original element with events to copy
       * @param {HTMLElement} destination - The target element to receive events
       * 
       * @description
       * This method handles two types of event cloning:
       * 
       * <b>Vue.js Events:</b>
       * - Detects Vue components via source.__vue__
       * - Observes attribute changes for Vue event directives (@click, v-on:click)
       * - Copies existing event attributes to the cloned element
       * 
       * <b>Regular DOM Events:</b>
       * - Manually copies common mouse/touch events
       * - Creates new events and dispatches them on the original element
       * - Preserves event bubbling and cancelable properties
       * 
       * @example
       * // Vue component with events
       * <div @click="handleClick" v-on:mousedown="handleDown">
       *   <button>Click me</button>
       * </div>
       * 
       * // Regular DOM events
       * <button onclick="alert('clicked')">Click me</button>
       * 
       * @note
       * This is a workaround for the fact that cloneNode() doesn't copy event listeners.
       * For Vue components, we use MutationObserver to catch dynamic attribute changes.
       * 
       * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/Node/cloneNode} cloneNode limitations
       * @see {@link https://vuejs.org/v2/guide/events.html} Vue Event Handling
       */
      cloneEvents(source, destination) {
        // Clone Vue event handlers
        if (window.Vue && source.__vue__) {
          // We need to preserve Vue event handlers
          // This is a bit hacky but should work for most cases
          const observer = new MutationObserver((mutations) => {
            mutations.forEach(mutation => {
              if (mutation.type === 'attributes' && mutation.attributeName.startsWith('@') || 
                  mutation.attributeName.startsWith('v-on:')) {
                const attrName = mutation.attributeName;
                const attrValue = source.getAttribute(attrName);
                destination.setAttribute(attrName, attrValue);
              }
            });
          });
          
          observer.observe(source, { attributes: true });
          
          // Copy existing event attributes
          Array.from(source.attributes).forEach(attr => {
            if (attr.name.startsWith('@') || attr.name.startsWith('v-on:')) {
              destination.setAttribute(attr.name, attr.value);
            }
          });
        }
        
        // For regular DOM events, we need to manually copy them
        const eventNames = ['click', 'mousedown', 'mouseup', 'touchstart', 'touchend'];
        eventNames.forEach(eventName => {
          destination.addEventListener(eventName, (e) => {
            // Create a new event
            const newEvent = new Event(eventName, {
              bubbles: e.bubbles,
              cancelable: e.cancelable
            });
            
            // Dispatch it on the original element
            source.dispatchEvent(newEvent);
          });
        });
      }

      /**
       * Scans the DOM and sets up all popup triggers.
       * 
       * @private
       * @description
       * Finds all elements matching the triggerSelector and initializes each one.
       * This is called during initialization and when new elements are added to the DOM.
       * 
       * @see {@link PopupPortal#setupTrigger} Individual trigger setup
       * @see {@link PopupPortal#setupMutationObserver} Dynamic element detection
       */
      setupTriggers() {
        const triggers = document.querySelectorAll(this.options.triggerSelector);
        triggers.forEach(trigger => this.setupTrigger(trigger));
      }
      
      /**
       * Sets up a single popup trigger element.
       * 
       * @private
       * @param {HTMLElement} trigger - The trigger element to set up
       * 
       * @description
       * This method performs the following operations:
       * 1. Checks if the trigger is already initialized (prevents duplicates)
       * 2. Finds the popup element within the trigger
       * 3. Generates a unique ID for the popup
       * 4. Clones the popup and moves it to the portal container
       * 5. Clones event handlers from original to cloned popup
       * 6. Stores references in the popups Map
       * 7. Removes the original popup from the DOM
       * 8. Adds event listeners based on configuration
       * 
       * @example
       * // HTML structure
       * <div data-popup-trigger>
       *   <button>Hover me</button>
       *   <div data-popup class="my-popup">Content</div>
       * </div>
       * 
       * @example
       * // After setup, the DOM becomes:
       * <div data-popup-trigger data-popup-id="popup-abc123" data-portal-initialized="true">
       *   <button>Hover me</button>
       * </div>
       * <!-- Portal container -->
       * <div id="popup-portal-container">
       *   <div id="popup-abc123" class="my-popup" style="position: fixed;">Content</div>
       * </div>
       * 
       * @note
       * The original popup is removed from the trigger and moved to the portal container
       * to ensure proper z-index stacking and prevent clipping issues.
       * 
       * @see {@link PopupPortal#cloneEvents} Event cloning
       * @see {@link PopupPortal#showPopup} Show logic
       * @see {@link PopupPortal#hidePopup} Hide logic
       */
      setupTrigger(trigger) {
        // Skip if already initialized
        if (trigger.dataset.portalInitialized) return;
        
        // Find the popup element
        const popup = trigger.querySelector(this.options.popupSelector);
        if (!popup) return;
        
        // Mark as initialized
        trigger.dataset.portalInitialized = 'true';
        
        // Generate unique ID for this popup
        const popupId = `popup-${Math.random().toString(36).substr(2, 9)}`;
        trigger.dataset.popupId = popupId;
        
        // Clone the popup and move it to the portal container
        const clonedPopup = popup.cloneNode(true);
        // Clone events from original popup to cloned popup
        this.cloneEvents(popup, clonedPopup);
        clonedPopup.id = popupId;
        clonedPopup.style.position = 'fixed';
        clonedPopup.style.zIndex = this.options.zIndex;
        clonedPopup.style.opacity = '0';
        clonedPopup.style.visibility = 'hidden';
        clonedPopup.style.pointerEvents = 'auto';
        clonedPopup.style.transition = `opacity ${this.options.animationDuration}ms ease, visibility ${this.options.animationDuration}ms ease`;
        
        // Store references
        this.popups.set(popupId, {
          trigger,
          originalPopup: popup,
          portaledPopup: clonedPopup,
          visible: false
        });
        
        // Remove the original popup
        popup.parentNode.removeChild(popup);
        
        // Add the cloned popup to the portal container
        this.portalContainer.appendChild(clonedPopup);
        
        // Add event listeners
        if (this.options.showOnHover) {
          trigger.addEventListener('mouseenter', () => this.showPopup(popupId));
          trigger.addEventListener('mouseleave', () => this.hidePopup(popupId));
          
          // Keep popup visible when hovering over it
          clonedPopup.addEventListener('mouseenter', () => {
            const popupData = this.popups.get(popupId);
            if (popupData) {
              clearTimeout(popupData.hideTimeout);
            }
          });
          
          // Hide popup when leaving it
          clonedPopup.addEventListener('mouseleave', () => this.hidePopup(popupId));
        }
        
        if (this.options.showOnClick) {
          trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const popupData = this.popups.get(popupId);
            if (popupData && popupData.visible) {
              this.hidePopup(popupId);
            } else {
              this.showPopup(popupId);
            }
          });
        }
      }
      
      /**
       * Sets up a MutationObserver to detect dynamically added popup triggers.
       * 
       * @private
       * @description
       * Monitors the document body for child list mutations (element additions).
       * When new elements are added, it scans for popup triggers and initializes them.
       * This enables the portal system to work with:
       * - AJAX-loaded content
       * - Vue.js component updates
       * - Dynamic DOM manipulation
       * - Single-page application navigation
       * 
       * @example
       * // After AJAX content is loaded:
       * fetch('/api/content').then(html => {
       *   document.getElementById('container').innerHTML = html;
       *   // MutationObserver automatically detects and sets up new triggers
       * });
       * 
       * @note
       * The observer watches the entire document body with subtree: true
       * to catch mutations at any depth in the DOM tree.
       * 
       * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/MutationObserver} MutationObserver API
       * @see {@link PopupPortal#setupTriggers} Trigger setup method
       */
      setupMutationObserver() {
        const observer = new MutationObserver((mutations) => {
          let shouldScan = false;
          
          mutations.forEach(mutation => {
            if (mutation.type === 'childList' && mutation.addedNodes.length) {
              shouldScan = true;
            }
          });
          
          if (shouldScan) {
            this.setupTriggers();
          }
        });
        
        observer.observe(document.body, {
          childList: true,
          subtree: true
        });
      }
      
      /**
       * Positions a popup relative to its trigger element.
       * 
       * @private
       * @param {string} popupId - The unique ID of the popup to position
       * 
       * @description
       * Calculates and applies the optimal position for a popup based on:
       * 1. The configured position strategy (auto, top, bottom, left, right)
       * 2. Available space around the trigger element
       * 3. CSS classes on the popup element (position-top, position-bottom, etc.)
       * 4. Viewport boundaries to prevent clipping
       * 
       * <b>Positioning Logic:</b>
       * - <b>Auto:</b> Calculates available space in all directions and picks the largest
       * - <b>Top:</b> Positions above trigger, centered horizontally
       * - <b>Bottom:</b> Positions below trigger, centered horizontally
       * - <b>Left:</b> Positions to the left, centered vertically
       * - <b>Right:</b> Positions to the right, centered vertically
       * 
       * @example
       * // Auto positioning (default)
       * const portal = new PopupPortal({ positionStrategy: 'auto' });
       * // Popup will appear in the direction with most available space
       * 
       * @example
       * // Fixed positioning
       * const portal = new PopupPortal({ positionStrategy: 'bottom' });
       * // Popup will always appear below the trigger
       * 
       * @example
       * // CSS class override
       * <div data-popup class="position-top">...</div>
       * // CSS class takes precedence over positionStrategy option
       * 
       * @note
       * Uses getBoundingClientRect() for accurate positioning calculations.
       * Applies transform: translateX/Y(-50%) for centering.
       * 
       * @see {@link PopupPortal#constrainToViewport} Viewport constraint logic
       * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/Element/getBoundingClientRect} getBoundingClientRect
       */
      positionPopup(popupId) {
        const popupData = this.popups.get(popupId);
        if (!popupData) return;
        
        const { trigger, portaledPopup } = popupData;
        const triggerRect = trigger.getBoundingClientRect();
        
        // First, reset any previous positioning to get accurate dimensions
        portaledPopup.style.top = 'auto';
        portaledPopup.style.bottom = 'auto';
        portaledPopup.style.left = 'auto';
        portaledPopup.style.right = 'auto';
        portaledPopup.style.transform = 'none';
        
        // Get the popup's actual dimensions
        const popupRect = portaledPopup.getBoundingClientRect();
        
        let position = this.options.positionStrategy;
        
        // Auto-detect best position if set to auto
        if (position === 'auto') {
          const spaceTop = triggerRect.top;
          const spaceBottom = window.innerHeight - triggerRect.bottom;
          const spaceLeft = triggerRect.left;
          const spaceRight = window.innerWidth - triggerRect.right;
          
          // Prioritize bottom and top over left/right for better UX
          // Also consider the popup's actual height
          const spaceTopWithHeight = spaceTop - popupRect.height;
          const spaceBottomWithHeight = spaceBottom - popupRect.height;
          
          // Choose the direction with most space, but prefer bottom/top
          if (spaceBottomWithHeight >= spaceTopWithHeight && spaceBottomWithHeight >= 0) {
            position = 'bottom';
          } else if (spaceTopWithHeight >= 0) {
            position = 'top';
          } else if (spaceRight >= spaceLeft && spaceRight >= 0) {
            position = 'right';
          } else if (spaceLeft >= 0) {
            position = 'left';
          } else {
            // No space in any direction, default to bottom with viewport constraint
            position = 'bottom';
          }
        }
        
        // Get position from popup's class if available
        if (portaledPopup.classList.contains('position-top')) position = 'top';
        if (portaledPopup.classList.contains('position-bottom')) position = 'bottom';
        if (portaledPopup.classList.contains('position-left')) position = 'left';
        if (portaledPopup.classList.contains('position-right')) position = 'right';
        
        // Remove any existing position classes
        portaledPopup.classList.remove('position-top', 'position-bottom', 'position-left', 'position-right');
        
        // Add the current position class
        portaledPopup.classList.add(`position-${position}`);
        
        const offset = this.options.offset;
        
        // Position based on strategy
        switch (position) {
          case 'top':
            portaledPopup.style.bottom = (window.innerHeight - triggerRect.top + offset) + 'px';
            portaledPopup.style.left = (triggerRect.left + triggerRect.width / 2) + 'px';
            portaledPopup.style.transform = 'translateX(-50%)';
            break;
          case 'bottom':
            portaledPopup.style.top = (triggerRect.bottom + offset) + 'px';
            portaledPopup.style.left = (triggerRect.left + triggerRect.width / 2) + 'px';
            portaledPopup.style.transform = 'translateX(-50%)';
            break;
          case 'left':
            portaledPopup.style.right = (window.innerWidth - triggerRect.left + offset) + 'px';
            portaledPopup.style.top = (triggerRect.top + triggerRect.height / 2) + 'px';
            portaledPopup.style.transform = 'translateY(-50%)';
            break;
          case 'right':
            portaledPopup.style.left = (triggerRect.right + offset) + 'px';
            portaledPopup.style.top = (triggerRect.top + triggerRect.height / 2) + 'px';
            portaledPopup.style.transform = 'translateY(-50%)';
            break;
        }
        
        // Check if popup still doesn't fit and reposition if necessary
        const rect = portaledPopup.getBoundingClientRect();
        
        // If popup is clipped at the top and there's space below, reposition to bottom
        if (rect.top < 0 && triggerRect.bottom + offset + rect.height < window.innerHeight) {
          portaledPopup.style.top = (triggerRect.bottom + offset) + 'px';
          portaledPopup.style.bottom = 'auto';
          portaledPopup.style.left = (triggerRect.left + triggerRect.width / 2) + 'px';
          portaledPopup.style.transform = 'translateX(-50%)';
          portaledPopup.classList.remove('position-top');
          portaledPopup.classList.add('position-bottom');
        }
        
        // If popup is clipped at the bottom and there's space above, reposition to top
        if (rect.bottom > window.innerHeight && triggerRect.top - offset - rect.height > 0) {
          portaledPopup.style.bottom = (window.innerHeight - triggerRect.top + offset) + 'px';
          portaledPopup.style.top = 'auto';
          portaledPopup.style.left = (triggerRect.left + triggerRect.width / 2) + 'px';
          portaledPopup.style.transform = 'translateX(-50%)';
          portaledPopup.classList.remove('position-bottom');
          portaledPopup.classList.add('position-top');
        }
        
        // If popup is clipped at the left and there's space to the right, reposition to right
        if (rect.left < 0 && triggerRect.right + offset + rect.width < window.innerWidth) {
          portaledPopup.style.left = (triggerRect.right + offset) + 'px';
          portaledPopup.style.right = 'auto';
          portaledPopup.style.top = (triggerRect.top + triggerRect.height / 2) + 'px';
          portaledPopup.style.transform = 'translateY(-50%)';
          portaledPopup.classList.remove('position-left');
          portaledPopup.classList.add('position-right');
        }
        
        // If popup is clipped at the right and there's space to the left, reposition to left
        if (rect.right > window.innerWidth && triggerRect.left - offset - rect.width > 0) {
          portaledPopup.style.right = (window.innerWidth - triggerRect.left + offset) + 'px';
          portaledPopup.style.left = 'auto';
          portaledPopup.style.top = (triggerRect.top + triggerRect.height / 2) + 'px';
          portaledPopup.style.transform = 'translateY(-50%)';
          portaledPopup.classList.remove('position-right');
          portaledPopup.classList.add('position-left');
        }
        
        // Final viewport constraint check
        this.constrainToViewport(portaledPopup);
      }
      
      /**
       * Constrains a popup to stay within the viewport boundaries.
       * 
       * @private
       * @param {HTMLElement} popup - The popup element to constrain
       * 
       * @description
       * Checks if the popup is positioned outside the viewport and adjusts
       * its position to ensure it remains fully visible without stretching.
       * 
       * <b>Adjustments:</b>
       * - If left edge is off-screen: Sets left to 10px
       * - If right edge is off-screen: Sets right to 10px
       * - If top edge is off-screen: Sets top to 10px
       * - If bottom edge is off-screen: Sets bottom to 10px
       * 
       * @example
       * // Popup positioned too far right
       * // Before: left: 1500px (off-screen on 1920px width)
       * // After: right: 10px (visible on screen)
       * 
       * @note
       * This is a simple constraint that may cause overlap with other elements.
       * For more sophisticated collision detection, consider using a library like Popper.js.
       * 
       * @see {@link PopupPortal#positionPopup} Positioning logic
       * @see {@link https://popper.js.org/} Popper.js (alternative for advanced positioning)
       */
      constrainToViewport(popup) {
        const rect = popup.getBoundingClientRect();
        
        // Check if popup is outside viewport and adjust position
        // Only adjust if the popup is actually off-screen, not just close to the edge
        if (rect.left < 0) {
          popup.style.left = '10px';
          popup.style.right = 'auto';
          popup.style.transform = 'translateX(0)';
        }
        
        if (rect.right > window.innerWidth) {
          popup.style.right = '10px';
          popup.style.left = 'auto';
          popup.style.transform = 'translateX(0)';
        }
        
        if (rect.top < 0) {
          popup.style.top = '10px';
          popup.style.bottom = 'auto';
          popup.style.transform = 'translateY(0)';
        }
        
        if (rect.bottom > window.innerHeight) {
          popup.style.bottom = '10px';
          popup.style.top = 'auto';
          popup.style.transform = 'translateY(0)';
        }
      }
      
      /**
       * Shows a popup by its ID.
       * 
       * @private
       * @param {string} popupId - The unique ID of the popup to show
       * 
       * @description
       * Makes a popup visible by:
       * 1. Clearing any pending hide timeout
       * 2. Positioning the popup relative to its trigger
       * 3. Setting opacity to 1 and visibility to visible
       * 4. Adding the active class to the trigger element
       * 5. Updating internal state (visible flag and activePopup)
       * 6. Calling the onShow callback if provided
       * 
       * @fires PopupPortal#show - When popup becomes visible
       * 
       * @example
       * // Triggered by hover
       * trigger.addEventListener('mouseenter', () => this.showPopup(popupId));
       * 
       * @example
       * // Triggered by click
       * trigger.addEventListener('click', () => this.showPopup(popupId));
       * 
       * @note
       * Uses CSS transitions for smooth fade-in animation.
       * The popup is positioned before showing to ensure correct placement.
       * 
       * @see {@link PopupPortal#positionPopup} Positioning logic
       * @see {@link PopupPortal#hidePopup} Hide logic
       */
      showPopup(popupId) {
        const popupData = this.popups.get(popupId);
        if (!popupData) return;
        
        // Clear any pending hide timeout
        if (popupData.hideTimeout) {
          clearTimeout(popupData.hideTimeout);
        }
        
        // Make popup visible before positioning to get accurate dimensions
        const { trigger, portaledPopup } = popupData;
        portaledPopup.style.opacity = '1';
        portaledPopup.style.visibility = 'visible';
        
        // Position the popup
        this.positionPopup(popupId);
        
        // Add active class to trigger
        trigger.classList.add(this.options.activeClass);
        
        // Add active class to popup for animation
        portaledPopup.classList.add('active');
        
        // Update state
        popupData.visible = true;
        this.activePopup = popupId;
        
        // Call onShow callback if provided
        if (typeof this.options.onShow === 'function') {
          this.options.onShow(popupId, trigger, portaledPopup);
        }
      }
      
      /**
       * Hides a popup by its ID.
       * 
       * @private
       * @param {string} popupId - The unique ID of the popup to hide
       * 
       * @description
       * Hides a popup with a small delay to allow smooth interaction:
       * 1. Sets a 50ms timeout before hiding (allows cursor to move to popup)
       * 2. Sets opacity to 0 and visibility to hidden
       * 3. Removes the active class from the trigger element
       * 4. Updates internal state (visible flag and activePopup)
       * 5. Calls the onHide callback if provided
       * 
       * @fires PopupPortal#hide - When popup becomes hidden
       * 
       * @example
       * // Triggered by mouseleave
       * trigger.addEventListener('mouseleave', () => this.hidePopup(popupId));
       * 
       * @example
       * // Triggered by clicking outside
       * document.addEventListener('click', (e) => {
       *   if (!trigger.contains(e.target) && !popup.contains(e.target)) {
       *     this.hidePopup(popupId);
       *   }
       * });
       * 
       * @note
       * The 50ms delay prevents flickering when moving cursor from trigger to popup.
       * If the cursor enters the popup during this delay, the timeout is cleared.
       * 
       * @see {@link PopupPortal#showPopup} Show logic
       * @see {@link PopupPortal#handleDocumentClick} Click-outside handler
       */
      hidePopup(popupId) {
        const popupData = this.popups.get(popupId);
        if (!popupData) return;
        
        // Set a timeout to hide the popup (allows moving from trigger to popup)
        popupData.hideTimeout = setTimeout(() => {
          const { trigger, portaledPopup } = popupData;
          portaledPopup.style.opacity = '0';
          portaledPopup.style.visibility = 'hidden';
          
          // Remove active class from trigger
          trigger.classList.remove(this.options.activeClass);
          
          // Remove active class from popup for animation
          portaledPopup.classList.remove('active');
          
          // Update state
          popupData.visible = false;
          if (this.activePopup === popupId) {
            this.activePopup = null;
          }
          
          // Call onHide callback if provided
          if (typeof this.options.onHide === 'function') {
            this.options.onHide(popupId, trigger, portaledPopup);
          }
        }, 50); // Small delay to allow moving cursor to popup
      }
      
      /**
       * Hides all visible popups.
       * 
       * @public
       * @description
       * Iterates through all registered popups and hides each one.
       * Useful for cleanup or when you need to close all popups at once.
       * 
       * @example
       * // Close all popups
       * portal.hideAllPopups();
       * 
       * @example
       * // On route change (SPA)
       * router.beforeEach((to, from, next) => {
       *   portal.hideAllPopups();
       *   next();
       * });
       * 
       * @see {@link PopupPortal#hidePopup} Individual hide logic
       */
      hideAllPopups() {
        this.popups.forEach((_, popupId) => {
          this.hidePopup(popupId);
        });
      }
      
      /**
       * Updates positions of all visible popups.
       * 
       * @private
       * @description
       * Recalculates and reapplies positions for all currently visible popups.
       * Called automatically on window resize and scroll events.
       * 
       * @example
       * // Triggered by window resize
       * window.addEventListener('resize', () => this.updatePositions());
       * 
       * @example
       * // Triggered by window scroll
       * window.addEventListener('scroll', () => this.updatePositions(), true);
       * 
       * @note
       * Only updates visible popups to avoid unnecessary calculations.
       * 
       * @see {@link PopupPortal#positionPopup} Positioning logic
       */
      updatePositions() {
        this.popups.forEach((popupData, popupId) => {
          if (popupData.visible) {
            this.positionPopup(popupId);
          }
        });
      }
      
      /**
       * Handles clicks outside of popups and triggers.
       * 
       * @private
       * @param {MouseEvent} e - The click event
       * 
       * @description
       * Closes the active popup when the user clicks outside both the trigger
       * and the popup element. This provides a natural way to dismiss popups.
       * 
       * @example
       * // Event listener setup
       * document.addEventListener('click', this.handleDocumentClick.bind(this));
       * 
       * @example
       * // User interaction
       * // Click anywhere outside: popup closes
       * // Click on trigger or popup: popup stays open
       * 
       * @note
       * Only works if closeOnClickOutside option is enabled.
       * Uses contains() to check if click target is within trigger or popup.
       * 
       * @see {@link PopupPortal#hidePopup} Hide logic
       * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/Node/contains} Node.contains()
       */
      handleDocumentClick(e) {
        if (!this.activePopup) return;
        
        const popupData = this.popups.get(this.activePopup);
        if (!popupData) return;
        
        const { trigger, portaledPopup } = popupData;
        
        // Check if click is outside both trigger and popup
        if (!trigger.contains(e.target) && !portaledPopup.contains(e.target)) {
          this.hidePopup(this.activePopup);
        }
      }
      
      /**
       * Handles keyboard events for popup control.
       * 
       * @private
       * @param {KeyboardEvent} e - The keyboard event
       * 
       * @description
       * Closes the active popup when the Escape key is pressed.
       * Provides keyboard accessibility for popup dismissal.
       * 
       * @example
       * // Event listener setup
       * document.addEventListener('keydown', this.handleKeyDown.bind(this));
       * 
       * @example
       * // User interaction
       * // Press Escape: active popup closes
       * 
       * @note
       * Only works if closeOnEsc option is enabled.
       * 
       * @see {@link PopupPortal#hidePopup} Hide logic
       * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/KeyboardEvent/key} KeyboardEvent.key
       */
      handleKeyDown(e) {
        if (e.key === 'Escape' && this.activePopup) {
          this.hidePopup(this.activePopup);
        }
      }
      
      /**
       * Manually shows a popup by trigger element ID.
       * 
       * @public
       * @param {string} triggerId - The ID of the trigger element
       * 
       * @description
       * Public API method to programmatically show a popup.
       * Useful for custom controls or programmatic triggers.
       * 
       * @example
       * // HTML
       * <div id="my-trigger" data-popup-trigger>
       *   <button>Click me</button>
       *   <div data-popup>Popup content</div>
       * </div>
       * 
       * // JavaScript
       * const portal = new PopupPortal();
       * portal.show('my-trigger'); // Shows the popup
       * 
       * @example
       * // With Vue
       * this.$popupPortal.show('my-trigger');
       * 
       * @see {@link PopupPortal#showPopup} Internal show logic
       */
      show(triggerId) {
        const trigger = document.getElementById(triggerId);
        if (trigger && trigger.dataset.popupId) {
          this.showPopup(trigger.dataset.popupId);
        }
      }
      
      /**
       * Manually hides a popup by trigger element ID.
       * 
       * @public
       * @param {string} triggerId - The ID of the trigger element
       * 
       * @description
       * Public API method to programmatically hide a popup.
       * Useful for custom controls or programmatic triggers.
       * 
       * @example
       * // HTML
       * <div id="my-trigger" data-popup-trigger>
       *   <button>Click me</button>
       *   <div data-popup>Popup content</div>
       * </div>
       * 
       * // JavaScript
       * const portal = new PopupPortal();
       * portal.show('my-trigger');  // Shows the popup
       * portal.hide('my-trigger');  // Hides the popup
       * 
       * @example
       * // With Vue
       * this.$popupPortal.hide('my-trigger');
       * 
       * @see {@link PopupPortal#hidePopup} Internal hide logic
       */
      hide(triggerId) {
        const trigger = document.getElementById(triggerId);
        if (trigger && trigger.dataset.popupId) {
          this.hidePopup(trigger.dataset.popupId);
        }
      }
      
      /**
       * Destroys the popup portal and cleans up all resources.
       * 
       * @public
       * @description
       * Removes all event listeners, deletes the portal container,
       * and cleans up all popup references. Call this when you're done
       * with the portal to prevent memory leaks.
       * 
       * @example
       * // Cleanup when component is destroyed
       * const portal = new PopupPortal();
       * // ... use portal ...
       * portal.destroy();
       * 
       * @example
       * // Vue component cleanup
       * beforeDestroy() {
       *   if (this.$popupPortal) {
       *     this.$popupPortal.destroy();
       *   }
       * }
       * 
       * @note
       * After calling destroy(), the portal instance should not be used again.
       * Create a new instance if you need popups again.
       * 
       * @see {@link PopupPortal#init} Initialization
       */
      destroy() {
        document.removeEventListener('click', this.handleDocumentClick);
        document.removeEventListener('keydown', this.handleKeyDown);
        window.removeEventListener('resize', this.updatePositions);
        window.removeEventListener('scroll', this.updatePositions, true);
        
        // Remove the portal container
        if (this.portalContainer && this.portalContainer.parentNode) {
          this.portalContainer.parentNode.removeChild(this.portalContainer);
        }
      }
    }
  
    // Make available globally
    window.PopupPortal = PopupPortal;
    
    // Vue plugin
    if (window.Vue) {
      /**
       * Vue.js Plugin Integration
       * 
       * @description
       * Provides seamless integration with Vue.js applications through:
       * 1. Prototype injection: this.$popupPortal
       * 2. Custom directive: v-portal-popup
       * 
       * @example
       * // Access via prototype
       * this.$popupPortal.show('trigger-id');
       * this.$popupPortal.hide('trigger-id');
       * this.$popupPortal.hideAllPopups();
       * 
       * @example
       * // Use directive
       * <div v-portal-popup>
       *   <button>Hover me</button>
       *   <div class="my-popup">Popup content</div>
       * </div>
       * 
       * @example
       * // In Vue component
       * export default {
       *   mounted() {
       *     // Portal is automatically available
       *   },
       *   beforeDestroy() {
       *     // Clean up if needed
       *     if (this.$popupPortal) {
       *       this.$popupPortal.destroy();
       *     }
       *   }
       * }
       */
      window.Vue.prototype.$popupPortal = new PopupPortal();
      
      /**
       * Vue Directive: v-portal-popup
       * 
       * @description
       * Vue directive that automatically sets up popup triggers.
       * Applies data attributes and initializes the portal system.
       * 
       * @example
       * // Basic usage
       * <div v-portal-popup>
       *   <button>Hover me</button>
       *   <div data-popup>Popup content</div>
       * </div>
       * 
       * @example
       * // With custom popup class
       * <div v-portal-popup>
       *   <button>Hover me</button>
       *   <div class="beatmap-mini-popup">Popup content</div>
       * </div>
       * 
       * @example
       * // In Vue template
       * <template>
       *   <div v-portal-popup>
       *     <button>Hover me</button>
       *     <div data-popup>Popup content</div>
       *   </div>
       * </template>
       * 
       * @note
       * The directive automatically adds data-popup-trigger attribute
       * and looks for data-popup or .beatmap-mini-popup elements.
       * 
       * @see {@link https://vuejs.org/v2/guide/custom-directive.html} Vue Directives
       */
      window.Vue.directive('portal-popup', {
        bind(el, binding, vnode) {
          // Add data attributes
          el.setAttribute('data-popup-trigger', '');
          
          // Find popup element
          const popup = el.querySelector('[data-popup]');
          if (!popup) {
            // If no popup is found, look for the first element that might be a popup
            const possiblePopup = el.querySelector('.beatmap-mini-popup');
            if (possiblePopup) {
              possiblePopup.setAttribute('data-popup', '');
            }
          }

          // Initialize after Vue has rendered
          setTimeout(() => {
            window.Vue.prototype.$popupPortal.setupTrigger(el);
          }, 0);
        },
        
        unbind(el) {
          // Clean up if needed
          if (el.dataset.popupId) {
            const popupData = window.Vue.prototype.$popupPortal.popups.get(el.dataset.popupId);
            if (popupData && popupData.portaledPopup.parentNode) {
              popupData.portaledPopup.parentNode.removeChild(popupData.portaledPopup);
            }
            window.Vue.prototype.$popupPortal.popups.delete(el.dataset.popupId);
          }
        }
      });
    }
  
    /**
     * Auto-Initialization
     * 
     * @description
     * Automatically creates a default PopupPortal instance when the DOM is ready.
     * This provides zero-configuration popup support for non-Vue applications.
     * 
     * @example
     * // HTML (no JavaScript required)
     * <div data-popup-trigger>
     *   <button>Hover me</button>
     *   <div data-popup>Popup content</div>
     * </div>
     * 
     * @example
     * // Access the default portal
     * window.defaultPopupPortal.show('trigger-id');
     * window.defaultPopupPortal.hide('trigger-id');
     * 
     * @example
     * // Custom configuration (override default)
     * document.addEventListener('DOMContentLoaded', () => {
     *   if (window.defaultPopupPortal) {
     *     window.defaultPopupPortal.destroy();
     *   }
     *   window.defaultPopupPortal = new PopupPortal({
     *     showOnHover: false,
     *     showOnClick: true
     *   });
     * });
     * 
     * @fires PopupPortal#init - When default portal is created
     * 
     * @see {@link PopupPortal#constructor} Constructor options
     */
    document.addEventListener('DOMContentLoaded', () => {
      // Initialize for non-Vue elements
      const defaultPortal = new PopupPortal();
      window.defaultPopupPortal = defaultPortal;
    });
  })();

/* Helper Functions */
  /**
   * Difficulty Color Mapper
   * 
   * Maps osu! beatmap difficulty stars to RGB color values for visual representation.
   * Uses a linear scale with specific domain points and color interpolation to create
   * a smooth gradient from easy (blue) to extremely difficult (black).
   * 
   * @function getDifficultyRGB
   * @global
   * 
   * @param {number|string} stars - The star rating of the beatmap (0.1 to 9.0)
   * @returns {string} RGB color string in format "r, g, b" (e.g., "66, 144, 251")
   * 
   * @example
   * // Get color for a 5-star map
   * const color = window.getDifficultyRGB(5.0);
   * // Returns: "198, 69, 184" (purple)
   * 
   * @example
   * // Use in CSS
   * element.style.backgroundColor = `rgb(${window.getDifficultyRGB(3.5)})`;
   * 
   * @example
   * // Handle undefined/null
   * const color = window.getDifficultyRGB(null);
   * // Returns: "200, 200, 200" (gray - default)
   * 
   * @description
   * <b>Color Scale Breakdown:</b>
   * - 0.1 - 1.25 stars: #4290FB (Light Blue)
   * - 1.25 - 2.0 stars: #4FC0FF (Cyan)
   * - 2.0 - 2.5 stars: #4FFFD5 (Teal)
   * - 2.5 - 3.3 stars: #7CFF4F (Green)
   * - 3.3 - 4.2 stars: #F6F05C (Yellow)
   * - 4.2 - 4.9 stars: #FF8068 (Orange)
   * - 4.9 - 5.8 stars: #FF4E6F (Red)
   * - 5.8 - 6.7 stars: #C645B8 (Magenta)
   * - 6.7 - 7.7 stars: #6563DE (Purple)
   * - 7.7 - 9.0 stars: #18158E (Dark Blue)
   * - 9.0+ stars: #000000 (Black)
   * 
   * @requires d3.js - D3.js library for color interpolation
   * @throws {Error} Logs error to console if color calculation fails
   * 
   * @see {@link https://github.com/d3/d3-scale} D3 Scale Documentation
   * @see {@link https://github.com/d3/d3-color} D3 Color Documentation
   * 
   * @author osu!Akatsuki / Kawata Team
   * @version 1.0.0
   * 
   * @todo Add support for custom color schemes
   * @todo Add caching for frequently accessed star ratings
   */
  window.getDifficultyRGB = function (stars) {
    if (!stars) return '200, 200, 200';
  
    try {
      const scale = d3.scaleLinear()
        .domain([0.1, 1.25, 2, 2.5, 3.3, 4.2, 4.9, 5.8, 6.7, 7.7, 9])
        .clamp(true)
        .range([
          '#4290FB', '#4FC0FF', '#4FFFD5', '#7CFF4F', '#F6F05C',
          '#FF8068', '#FF4E6F', '#C645B8', '#6563DE', '#18158E', '#000000'
        ])
        .interpolate(d3.interpolateRgb.gamma(2.2));
      
      const color = d3.color(scale(parseFloat(stars)));
      return color ? `${color.r}, ${color.g}, ${color.b}` : '200, 200, 200';
    } catch (e) {
      console.error('[DifficultyColor]', e);
      return '200, 200, 200';
    }
  };
