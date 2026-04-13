/**
 * ============================================================================
 * Component: Ranked Beatmaps Grid
 * ============================================================================
 *
 * Reusable beatmap card grid component. Displays beatmaps with cover art,
 * title/artist, difficulty icons, and ranked-by info.
 *
 * Props:
 * @param {Array} maps - Array of beatmap objects from the backend. Each has:
 *   { id, set_id, title, artist, creator, diffs: [...], mod: { id, name }, play_count? }
 * @param {String} title - Section title (default: "Recently Ranked")
 * @param {String} subtitle - Section subtitle (default: "Fresh maps added to the ranked pool")
 * @param {Boolean} showPlayCount - Show play count instead of mod info (default: false)
 * @param {String} domain - Server domain for avatar URLs
 *
 * Usage:
 *   <ranked-beatmaps :maps="rankedMaps" domain="kawata.pw"></ranked-beatmaps>
 *   <ranked-beatmaps :maps="trendingMaps" title="Most Played" show-play-count domain="kawata.pw"></ranked-beatmaps>
 *
 * @component ranked-beatmaps
 */
(function () {
  'use strict';

  Vue.component('ranked-beatmaps', {
    name: 'RankedBeatmaps',

    props: {
      maps: {
        type: Array,
        required: true,
      },
      title: {
        type: String,
        default: 'Recently Ranked',
      },
      subtitle: {
        type: String,
        default: 'Fresh maps added to the ranked pool',
      },
      showPlayCount: {
        type: Boolean,
        default: false,
      },
      domain: {
        type: String,
        default: function () {
          return window.domain || '';
        },
      },
    },

    computed: {
      hasMaps: function () {
        return this.maps && this.maps.length > 0;
      },
    },

    methods: {
      coverUrl: function (map) {
        var setId = map.set_id || map.setId || 0;
        return 'https://assets.ppy.sh/beatmaps/' + setId + '/covers/cover.jpg';
      },
      avatarUrl: function (modId) {
        return 'https://a.' + this.domain + '/' + (modId || 1);
      },
      modName: function (map) {
        if (map.mod && map.mod.name) return map.mod.name;
        return 'Staff';
      },
      modId: function (map) {
        if (map.mod && map.mod.id) return map.mod.id;
        return 1;
      },
      formatPlays: function (count) {
        if (!count) return '0';
        return Number(count).toLocaleString();
      },
    },

    template: '#ranked-beatmaps-template',
  });
})();
