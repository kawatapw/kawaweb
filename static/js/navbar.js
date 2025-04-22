
var searchBus = new Vue();
new Vue({
    el: '#search-icon',
    data: {
        isAnimating: false
    },
    methods: {
        showSearchWindow: function() {
            searchBus.$emit('show-search-window');
        },
        startAnimation: function() {
            this.isAnimating = true;
        },
        stopAnimation: function() {
            this.isAnimating = false;
        }
    }
});
new Vue({
    el: '#search-window',
    data: {
        show: false,
        query: '',
        players: [],
        playersLoading: false,
        maps: [],
        mapsLoading: false,
        typingTimeout: null, // Timeout used to delay the search
        currentAudio: null
    },
    methods: {
        close: function() {
            this.show = false;
            this.resetQuery();
        },
        search: async function() {
            this.players = [];
            this.maps = [];
            this.playersLoading = true;
            this.mapsLoading = true;

            if (this.query !== '') {
                // Search for players
                const playersResponse = await fetch("https://api." + domain + "/v1/search_players?limit=10&q=" + this.query);
                const playersData = await playersResponse.json();
                if (playersData["result"]) {
                    this.players = playersData["result"];
                }

                // Search for maps
                const mapsResponse = await fetch("https://osu.direct/api/search?amount=10"+"&query=" + this.query);
                const mapsData = await mapsResponse.json();
                if (mapsData) {
                    this.maps = mapsData;
                }
            }

            this.playersLoading = false;
            this.mapsLoading = false;
        },
        handleInput: function() {
                clearTimeout(this.typingTimeout); // Clear previous timeout

                // Calculate the delay based on the number of characters typed
                const characterCount = this.query.length;
                let delay = 1500 - (characterCount * 100);
                delay = Math.max(delay, 500); // Ensure the minimum delay is 500 milliseconds

                // Set a new timeout to run the search after the calculated delay
                this.typingTimeout = setTimeout(() => {
                        this.search();
                }, delay);
        },
        resetQuery: function() {
            this.query = '';
        },
        interract: function(setId) {
            const audioElement = document.getElementById('audio-' + setId);
            if (this.currentAudio && this.currentAudio !== audioElement) {
                this.currentAudio.pause();
            }
            if (audioElement.paused) {
                audioElement.play();
            } else {
                audioElement.pause();
            }
            this.currentAudio = audioElement;
        }
    },
    created: function() {
        searchBus.$on('show-search-window', () => {
            this.show = true;
            this.$nextTick(() => {
                this.$refs.searchInput.focus();
            });
        });
    },
    mounted: function() {
        let images = document.querySelectorAll('.bm-search .image-container');

        images.forEach(img => {
          img.addEventListener('mouseover', function() {
            this.classList.add('pan');
          });
        
          img.addEventListener('mouseout', function() {
            this.classList.remove('pan');
          });
        });
    },
    template: `
        <div id="search-window" class="modal" v-bind:class="{ 'is-active': show }" style="z-index: 21;">
            <div class="modal-background" @click="close"></div>
            <div id="search" class="modal-content" v-if="show">
                <div id="search-box" class="box search-fg">
                    <div id="sw-search" class="field">
                        <p class="search-input control has-icons-left">
                            <input class="input" type="search" placeholder="Search..." v-model="query" @input="handleInput" ref="searchInput">
                            <span class="icon is-left">
                                <i class="fas fa-search"></i>
                            </span>
                        </p>
                    </div>
                    <div class="search-divider"></div>
                    <div class="search-container">
                        <h2 class="title is-4">Players</h2>
                        <div class="results-container" id="players-container">
                            <div v-if="playersLoading">Loading...</div>
                            <div v-else-if="players.length === 0">No players found</div>
                            <a v-else v-for="player in players" :key="player.info.id" :href="'/u/' +player.info.id" class="player-search-result">
                                <!-- Display the player search result here -->
                                <div class="avatar">
                                    <img :src="'https://a.${domain}/' + player.info.id" @error="this.onerror=null; this.src='https://a.${domain}/-1'">
                                </div>
                                <div class="player">
                                    <h3>{{ player.info.name }}</h3>
                                </div>
                                <div class="player-stats">
                                    <a id="ranks">
                                        <p>Rank: {{ player.stats[player.info.preferred_mode].rank }}</p>
                                        <p>Country Rank: {{ player.stats[player.info.preferred_mode].country_rank }}</p>
                                    </a>
                                    <a id="performance">
                                        <p>PP: {{ player.stats[player.info.preferred_mode].pp }}</p>
                                        <p>Acc: {{ player.stats[player.info.preferred_mode].acc }}</p>
                                    </a>
                                    <a id="score">
                                        <a id="rscore">
                                            <p>Ranked Score:</p>
                                            <p>{{ player.stats[player.info.preferred_mode].rscore }}</p>
                                        </a>
                                        <a id="tscore">
                                            <p>Total Score:</p>
                                            <p>{{ player.stats[player.info.preferred_mode].tscore }}</p>
                                        </a>
                                    </a>
                                </div>
                                <div v-if="player.info.clan" class="player-clan">
                                    <h2>{{ player.info.clan.name }}</h2>
                                    <h1>[{{ player.info.clan.tag }}]</h1>
                                </div>
                            </a>
                            </div>
                            <div class="search-divider"></div>
                            <h2 class="title is-4">Beatmaps</h2>
                            <div class="results-container" id="beatmaps-container">
                                <div v-if="mapsLoading">Loading...</div>
                            <div v-else-if="maps.length === 0">No maps found</div>
                            <div v-for="map in maps" :key="map.SetID" class="bm-search-result" :id="map.SetID">
                                <a class="bm-search-result-container">
                                    <div class="tab">
                                        <!-- Display the beatmap search result here -->
                                        <a :href="'https://osu.ppy.sh/b/' + map.ChildrenBeatmaps[0].BeatmapID">
                                            <h3>{{ map.Title }}</h3>
                                        </a>
                                        <a :href="'https://osu.ppy.sh/b/' + map.ChildrenBeatmaps[0].BeatmapID">
                                            <h4>{{ map.Artist }} // {{ map.Creator }}</h4>
                                        </a>
                                        <div class="buttons">
                                            <a @click="interract(map.SetID)">
                                                <div class="play-div">
                                                    <i class="fas fa-play" :id="'play-' + map.SetID">
                                                        <audio :src="'https://b.ppy.sh/preview/' + map.SetID + '.mp3'" :id="'audio-' + map.SetID"></audio>
                                                    </i>
                                                </div>
                                            </a>
                                            <a :href="'https://osu.direct/d/' + map.SetID">
                                                <div class="download-div">
                                                    <i class="fas fa-download"></i>
                                                </div>
                                            </a>
                                        </div>
                                        </br>
                                        <div class="mini-icons">
                                            <div v-for="(childMap, index) in map.ChildrenBeatmaps" :key="childMap.BeatmapID" v-if="index < 15" :data-title="childMap.DiffName + ' <br> ' + childMap.DifficultyRating + '⭐'">
                                                <img :src="'/static/images/icons/mode-' + ['osu', 'taiko', 'fruits', 'mania'][childMap.Mode] + '.png'">
                                            </div>
                                            <div v-if="map.ChildrenBeatmaps.length > 15">.</div>
                                        </div>
                                    </div>
                                    <img id="bm-image" :src="'https://assets.ppy.sh/beatmaps/' + map.SetID + '/covers/card@2x.jpg'" @error="this.onerror=null; this.src='/static/default-bg.png'">
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    `
});
