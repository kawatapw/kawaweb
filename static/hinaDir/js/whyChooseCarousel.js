/**
 * ============================================================================
 * Component: Why Choose Us Carousel
 * ============================================================================
 *
 * Reusable carousel component for feature highlights.
 * Uses the KwCarousel class for auto-advance, touch, and dot navigation.
 *
 * Props:
 * @param {Array} cards - Array of { icon, title, description, image } objects
 * @param {Number} delay - Auto-advance delay in ms (default: 5000)
 *
 * Usage:
 *   <why-choose-carousel :cards="carouselCards" :delay="5000"></why-choose-carousel>
 *
 * @component why-choose-carousel
 */
(function () {
  'use strict';

  Vue.component('why-choose-carousel', {
    name: 'WhyChooseCarousel',

    props: {
      cards: {
        type: Array,
        required: true,
      },
      delay: {
        type: Number,
        default: 5000,
      },
    },

    data: function () {
      return {
        carouselInstance: null,
      };
    },

    mounted: function () {
      var self = this;
      this.$nextTick(function () {
        var el = self.$refs.carousel;
        if (el && window.KwCarousel) {
          self.carouselInstance = new window.KwCarousel(el, {
            delay: self.delay,
            loop: true,
          });
        }
      });
    },

    beforeDestroy: function () {
      if (this.carouselInstance) {
        this.carouselInstance.destroy();
        this.carouselInstance = null;
      }
    },

    template: '#why-choose-carousel-template',
  });
})();
