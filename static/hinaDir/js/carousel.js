/**
 * Lightweight Carousel Component
 * Auto-advancing, pause-on-hover, dot navigation, touch swipe.
 * No library dependencies — pure vanilla JS.
 *
 * Usage:
 *   <div class="kw-carousel" data-carousel data-delay="5000" data-loop="true">
 *     <div class="kw-carousel-track">
 *       <div class="kw-carousel-slide">...</div>
 *       <div class="kw-carousel-slide">...</div>
 *     </div>
 *     <div class="kw-carousel-dots"></div>
 *     <button class="kw-carousel-prev">‹</button>
 *     <button class="kw-carousel-next">›</button>
 *   </div>
 *
 * Or via JS:
 *   new KwCarousel(element, { delay: 5000, loop: true });
 */
(function () {
  'use strict';

  class KwCarousel {
    constructor(el, opts = {}) {
      this.el = el;
      this.track = el.querySelector('.kw-carousel-track');
      this.slides = Array.from(this.track.children);
      this.dotContainer = el.querySelector('.kw-carousel-dots');
      this.prevBtn = el.querySelector('.kw-carousel-prev');
      this.nextBtn = el.querySelector('.kw-carousel-next');

      this.current = 0;
      this.count = this.slides.length;
      this.delay = parseInt(opts.delay || el.dataset.delay || 5000, 10);
      this.loop = opts.loop !== undefined ? opts.loop : el.dataset.loop !== 'false';
      this.autoplayTimer = null;
      this.progressTimer = null;
      this.paused = false;

      this._buildDots();
      this._bindEvents();
      this._goTo(0, false);
      this._startAutoplay();
    }

    _buildDots() {
      if (!this.dotContainer) return;
      this.dotContainer.innerHTML = '';
      for (let i = 0; i < this.count; i++) {
        const dot = document.createElement('button');
        dot.className = 'kw-carousel-dot';
        dot.setAttribute('type', 'button');
        dot.setAttribute('aria-label', 'Slide ' + (i + 1));
        // Progress bar inside dot
        const bar = document.createElement('span');
        bar.className = 'kw-carousel-dot-progress';
        dot.appendChild(bar);
        dot.addEventListener('click', () => this.goTo(i));
        this.dotContainer.appendChild(dot);
      }
      this.dots = Array.from(this.dotContainer.children);
    }

    _bindEvents() {
      if (this.prevBtn) this.prevBtn.addEventListener('click', () => this.prev());
      if (this.nextBtn) this.nextBtn.addEventListener('click', () => this.next());

      // Pause on hover
      this.el.addEventListener('mouseenter', () => { this.paused = true; this._stopAutoplay(); });
      this.el.addEventListener('mouseleave', () => { this.paused = false; this._startAutoplay(); });

      // Touch swipe
      let startX = 0;
      let deltaX = 0;
      this.track.addEventListener('touchstart', (e) => { startX = e.touches[0].clientX; }, { passive: true });
      this.track.addEventListener('touchmove', (e) => { deltaX = e.touches[0].clientX - startX; }, { passive: true });
      this.track.addEventListener('touchend', () => {
        if (Math.abs(deltaX) > 50) {
          deltaX < 0 ? this.next() : this.prev();
        }
        deltaX = 0;
      });
    }

    _goTo(index, animate = true) {
      if (index < 0) index = this.loop ? this.count - 1 : 0;
      if (index >= this.count) index = this.loop ? 0 : this.count - 1;
      this.current = index;

      // Update slide classes
      this.slides.forEach((slide, i) => {
        slide.classList.toggle('active', i === index);
        slide.classList.toggle('prev', i < index);
        slide.classList.toggle('next', i > index);
        // Scale: active = 1.02, others = 0.95 with opacity 0.5
        if (i === index) {
          slide.style.transform = 'scale(1.02)';
          slide.style.opacity = '1';
        } else {
          slide.style.transform = 'scale(0.95)';
          slide.style.opacity = '0.5';
        }
      });

      // Scroll the track
      if (this.slides[index]) {
        const slideWidth = this.slides[index].offsetWidth;
        const trackWidth = this.track.offsetWidth;
        const offset = this.slides[index].offsetLeft - (trackWidth / 2) + (slideWidth / 2);
        this.track.style.scrollBehavior = animate ? 'smooth' : 'auto';
        this.track.scrollLeft = offset;
      }

      // Update dots
      this._updateDots();
    }

    _updateDots() {
      if (!this.dots) return;
      this.dots.forEach((dot, i) => {
        dot.classList.toggle('active', i === this.current);
        const bar = dot.querySelector('.kw-carousel-dot-progress');
        if (bar) {
          if (i === this.current) {
            bar.style.animation = 'none';
            // Force reflow
            void bar.offsetHeight;
            bar.style.animation = `carousel-progress ${this.delay}ms linear forwards`;
          } else {
            bar.style.animation = 'none';
            bar.style.width = '0';
          }
        }
      });
    }

    _startAutoplay() {
      this._stopAutoplay();
      if (this.paused) return;
      this.autoplayTimer = setInterval(() => this.next(), this.delay);
      this._updateDots(); // restart progress animation
    }

    _stopAutoplay() {
      if (this.autoplayTimer) {
        clearInterval(this.autoplayTimer);
        this.autoplayTimer = null;
      }
    }

    goTo(index) {
      this._goTo(index);
      this._startAutoplay();
    }

    next() {
      this._goTo(this.current + 1);
      if (!this.paused) this._startAutoplay();
    }

    prev() {
      this._goTo(this.current - 1);
      if (!this.paused) this._startAutoplay();
    }

    destroy() {
      this._stopAutoplay();
    }
  }

  // Auto-init carousels with [data-carousel]
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-carousel]').forEach((el) => {
      el._kwCarousel = new KwCarousel(el);
    });
  });

  // Export
  window.KwCarousel = KwCarousel;
})();
