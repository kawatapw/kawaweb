// ================= GLOBAL EVENT BUSES =================
// Use lightweight event buses instead of full Vue instances
// This prevents memory leaks from Vue's reactivity system
class EventBus {
  constructor() {
    this.listeners = {};
  }
  
  $on(event, callback) {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(callback);
  }
  
  $off(event, callback) {
    if (!this.listeners[event]) return;
    
    if (callback) {
      const index = this.listeners[event].indexOf(callback);
      if (index > -1) {
        this.listeners[event].splice(index, 1);
      }
    } else {
      this.listeners[event] = [];
    }
  }
  
  $emit(event, ...args) {
    if (!this.listeners[event]) return;
    
    // Create a copy to avoid issues if listeners are removed during iteration
    const callbacks = [...this.listeners[event]];
    callbacks.forEach(callback => {
      try {
        callback(...args);
      } catch (err) {
        logger.error(`EventBus`,`Error in listener for ${event}:`, err);
      }
    });
  }
  
  $destroy() {
    this.listeners = {};
  }
}
