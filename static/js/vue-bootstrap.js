// vue-bootstrap.js
// Lightweight Vue 2 app manager with template support and safe mounting

window.VueApps = Object.create(null)
window.VueMountedEls = new Set()

/**
 * Safely bootstrap a Vue app on a DOM element
 * @param {string} name - Unique name for the app
 * @param {Object} options - Vue options
 *   - el: string selector
 *   - templateId: optional string ID for template in vue-templates.html
 */
window.bootstrapVue = function (name, options) {
  if (VueApps[name]) {
    console.warn(`[Vue] App "${name}" already bootstrapped`)
    return VueApps[name]
  }

  const el = document.querySelector(options.el)
  if (!el) return null

  if (VueMountedEls.has(el)) {
    console.warn(`[Vue] Element "${options.el}" is already mounted`)
    return null
  }

  // Use template from ID if provided
  if (options.templateId) {
    const tplEl = document.getElementById(options.templateId)
    if (tplEl) options.template = tplEl.innerHTML
    else console.warn(`[Vue] Template ID "${options.templateId}" not found`)
  }

  // Add cleanup hooks to options
  const originalBeforeDestroy = options.beforeDestroy
  const originalDestroyed = options.destroyed
  
  options.beforeDestroy = function() {
    // Clean up event listeners
    if (this.$options && this.$options.events) {
      Object.keys(this.$options.events).forEach(event => {
        this.$off(event)
      })
    }
    
    // Call original beforeDestroy if it exists
    if (originalBeforeDestroy) {
      originalBeforeDestroy.call(this)
    }
  }
  
  options.destroyed = function() {
    // Clean up any remaining event listeners
    this.$off()
    
    // Call original destroyed if it exists
    if (originalDestroyed) {
      originalDestroyed.call(this)
    }
    
    // Remove from tracking sets
    VueMountedEls.delete(el)
    delete VueApps[name]
    
    console.log(`[Vue] App "${name}" cleaned up`)
  }

  const app = new Vue(options)
  VueApps[name] = app
  VueMountedEls.add(el)

  return app
}

/**
 * Safely destroy a Vue app
 * @param {string} name - Name of the app to destroy
 */
window.destroyVue = function (name) {
  const app = VueApps[name]
  if (app) {
    app.$destroy()
    console.log(`[Vue] App "${name}" destroyed`)
  }
}

/**
 * Clean up all Vue apps
 */
window.cleanupAllVue = function () {
  Object.keys(VueApps).forEach(name => {
    destroyVue(name)
  })
  VueApps = Object.create(null)
  VueMountedEls.clear()
  console.log('[Vue] All apps cleaned up')
}
