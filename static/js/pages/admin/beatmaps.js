new Vue({
    el: "#beatmaps",
    delimiters: ["<%", "%>"],
    data() {
        return {
            flags: window.flags,
            reqs: {},
            beatmaps: {},
        }
    },
    async beforeCreate() {
    },
    created() {
        this.$log.info('Beatmaps.js Beatmaps Page Created');
    },
    methods: {
        
        editMap(beatmap) {
            editMapBus.$emit('showEditBeatmapPanel', beatmap);
        },
    },
    computed: {
    }
});
var editMapBus = new Vue();
new Vue({
    el: "#editBeatmapWindow",
    delimiters: ["<%", "%>"],
    data() {
        return {
            flags: window.flags,
            show: false,
            beatmap: {},
            postresponse: null,
            postresponsestatus: null,
            postresponsetimer: 0,
            selectedAction: {}, // Changed from null to object
        }
    },
    methods: {
        close: function() {
            this.show = false;
            this.selectedAction = {}; // Reset to empty object
        },
        selectAction(actionType, diffId) {
            // If the same action for the same diff is clicked again, select 'deny'
            if (this.selectedAction[diffId] === actionType) {
                this.$set(this.selectedAction, diffId, 'deny');
            } else {
                // Otherwise, select the new action for this diff
                this.$set(this.selectedAction, diffId, actionType);
            }
        },
        async postAction(url, formData) {
            const params = new URLSearchParams();
            for (const [key, value] of Object.entries(formData)) {
                params.append(key, value);
            }

            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: params
            });

            this.postresponsetimer = 5;
            this.postresponse = await response.json(); // Parse the response as JSON
            this.postresponsestatus = response.status; 
            const message = this.postresponse.message; // Get the message from the JSON response

            let timer = setInterval(() => {
                this.postresponsetimer--;
                if (this.postresponsetimer === 0) {
                    clearInterval(timer);
                    this.postresponse = null;
                }
            }, 1000);

            return message; // Return the message from the JSON response
        },
        submitMapChanges() {
            const statusMap = {
                'rank': 'Ranked',
                'approve': 'Approved',
                'qualify': 'Qualified',
                'love': 'Loved',
                'unrank': 'Pending', // Or 'Graveyard'/-2 depending on desired logic
                'deny': 'Graveyard' // Or 'Pending'/0 depending on desired logic
            };
            // Ensure statuses array matches the one in computed: statusInfo
            const statuses = ['Pending', 'Update Available', 'Ranked', 'Approved', 'Qualified', 'Loved', 'Graveyard', 'WIP']; // Added Graveyard/WIP based on statusMap

            let diffsPayload = [];
            const mainDiffId = this.beatmap.map_info.id;

            // Process the main requested difficulty
            const mainAction = this.selectedAction[mainDiffId];
            const mainCurrentStatusIndex = this.beatmap.map_info.status;
            const mainStatus = mainAction
                ? statusMap[mainAction]
                : (statuses[mainCurrentStatusIndex] || 'Pending'); // Default to Pending if index out of bounds

            diffsPayload.push({
                difficulty_id: mainDiffId,
                status: mainStatus
            });

            // Process other difficulties in the set
            this.beatmap.map_diffs.forEach(diff => {
                const diffId = diff.id;
                const diffAction = this.selectedAction[diffId];
                const diffCurrentStatusIndex = diff.status; // Assuming diff.status holds the numeric status code
                const diffStatus = diffAction
                    ? statusMap[diffAction]
                    : (statuses[diffCurrentStatusIndex] || 'Pending'); // Default to Pending

                diffsPayload.push({
                    difficulty_id: diffId,
                    status: diffStatus
                });
            });

            const payload = {
                Map: {
                    set_id: this.beatmap.map_info.set_id,
                    diffs: diffsPayload
                }
            };
            this.$log.debug('real', this.beatmap);
            this.$log.debug('real', payload);
            this.postAction('/admin/action/editmap', { 
                targets: [this.beatmap.map_info.id, ...this.beatmap.map_diffs.map(diff => diff.id)], 
                data: JSON.stringify(payload) 
            });
        },
    },
    created: function() {
        editMapBus.$on('showEditBeatmapPanel', (map) => {
            this.$log.debug('Edit Beatmap Window Triggered')
            this.$log.debug(map);
            this.beatmap = map;
            this.$log.debug(this.beatmap);
            this.show = true;
        });
    },
    computed: {
        statusInfo() {
            const statuses = ['Pending', 'Update Available', 'Ranked', 'Approved', 'Qualified', 'Loved', 'Graveyard', 'WIP']; // Ensure this matches array used in submitMapChanges
            const statusClasses = ['pending', 'update', 'ranked', 'approved', 'qualified', 'loved', 'unranked', 'wip']; // Added classes for Graveyard/WIP
            const status = this.beatmap.map_info.status;
            return {
                text: statuses[status] || 'Pending', // Default text
                class: statusClasses[status] || 'pending' // Default class
            };
        },
    },
    template: `
        <div class="modal" id="editBeatmapWindow" v-bind:class="{ 'is-active': show }">
            <div class="modal-background" @click="close"></div>
            <div data-panel="changeBeatmapStatus" id="beatmap-window" class="modal-content" v-if="show">
                <div class="main-block">
                    <div class="banner" :style="'background-image: linear-gradient(rgba(0, 0, 0, 0.5), rgba(0, 0, 0, 0.5)), url(https://assets.ppy.sh/beatmaps/' + beatmap['map_info']['set_id'] + '/covers/card@2x.jpg)'">
                        <h1 class="title"><% beatmap['map_info']['title'] %></br><% beatmap['map_info']['artist'] %></h1>
                    </div>
                    <div class="beatmap-requester">
                        <h1 class="title">Requested By</h1>
                        <h2><img :src="'/static/images/flags/' + beatmap.player.country.toUpperCase() + '.png'" class="user-flag">
                        <span class="bgf"><% beatmap['player']['name'] %></span></h2>
                    </div>
                    <div :class="'status ' + statusInfo.class">
                        <h3><% statusInfo.text %></h3>
                    </div>
                    <div class="download-links">
                        <div class="download">
                            <a :href="'https://osu.ppy.sh/b/' + beatmap['map_info']['id']">
                                <button class="button"><i class="fas fa-external-link-alt"></i>View on osu! Website</button>
                            </a>
                        </div>
                        <div class="download">
                            <a :href="'/d/' + beatmap['map_info']['set_id']">
                                <button class="button"><i class="fas fa-download"></i>Download</button>
                            </a>
                        </div>
                    </div>
                </div>
                <div class="second-block">
                    <div class="alert" v-if="postresponse" :style="'background-color: var(--alert-' + postresponsestatus + ');'">
                        <div class="alert-content">
                            <p><% postresponse.message %></p>
                        </div>
                    </div>
                    <div class="content">
                        <div class="beatmap-block">
                            <div class="beatmap-section">
                                <button class="button" @click="submitMapChanges">Submit</button>
                                <h1 class="title">Requested Map/Diff:</h1>
                                <div class="beatmap-content">
                                    <div class="selector" style="position: relative; top: 1;">
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> Rating: <% beatmap['map_info']['diff'] %></span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> CS: <% beatmap['map_info']['cs'] %></span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> AR: <% beatmap['map_info']['ar'] %></span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> OD: <% beatmap['map_info']['od'] %></span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> HP: <% beatmap['map_info']['hp'] %></span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> BPM: <% beatmap['map_info']['bpm'] %></span>
                                        </a></br>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> Length: <% (beatmap['map_info']['total_length'] / 60).toFixed(3) %> minutes</span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> Plays: <% beatmap['map_info']['plays'] %></span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> Passes: <% beatmap['map_info']['passes'] %></span>
                                        </a>
                                    </div>
                                    <div class="beatmap-info">
                                        <h3 class="subtitle"><% beatmap['map_info']['version'] %></h3>
                                    </div>
                                    <div class="beatmap-subsection">
                                        <button class="button rank" :class="{ active: selectedAction[beatmap.map_info.id] === 'rank' }" @click="selectAction('rank', beatmap.map_info.id)">Rank</button>
                                        <button class="button approve" :class="{ active: selectedAction[beatmap.map_info.id] === 'approve' }" @click="selectAction('approve', beatmap.map_info.id)">Approve</button>
                                        <button class="button qualify" :class="{ active: selectedAction[beatmap.map_info.id] === 'qualify' }" @click="selectAction('qualify', beatmap.map_info.id)">Qualify</button>
                                        <button class="button love" :class="{ active: selectedAction[beatmap.map_info.id] === 'love' }" @click="selectAction('love', beatmap.map_info.id)">Love</button>
                                        <button class="button unrank" :class="{ active: selectedAction[beatmap.map_info.id] === 'unrank' }" @click="selectAction('unrank', beatmap.map_info.id)">Unrank</button>
                                        <button class="button deny" :class="{ active: selectedAction[beatmap.map_info.id] === 'deny' }" @click="selectAction('deny', beatmap.map_info.id)">Deny</button>
                                    </div>
                                </div>
                            </div>
                            <div class="divider"></div>
                            <div class="beatmap-section">
                                <h1 class="title">All Difficulties:</h1>
                                <div class="beatmap-content" v-for="(diff, index) in beatmap.map_diffs" :key="diff.id">
                                    <div class="selector" style="position: relative; top: 1;">
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> Rating: <% diff['diff'] %></span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> CS: <% diff['cs'] %></span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> AR: <% diff['ar'] %></span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> OD: <% diff['od'] %></span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> HP: <% diff['hp'] %></span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> BPM: <% diff['bpm'] %></span>
                                        </a></br>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> Length: <% (diff['total_length'] / 60).toFixed(3) %> minutes</span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> Plays: <% diff['plays'] %></span>
                                        </a>
                                        <a class="top-tab">
                                            <i class=""></i><span class="modetext"> Passes: <% diff['passes'] %></span>
                                        </a>
                                    </div>
                                    <div class="beatmap-info">
                                        <h3 class="subtitle"><% diff['version'] %></h3>
                                    </div>
                                    <div class="beatmap-subsection">
                                        <button class="button rank" :class="{ active: selectedAction[diff.id] === 'rank' }" @click="selectAction('rank', diff.id)">Rank</button>
                                        <button class="button approve" :class="{ active: selectedAction[diff.id] === 'approve' }" @click="selectAction('approve', diff.id)">Approve</button>
                                        <button class="button qualify" :class="{ active: selectedAction[diff.id] === 'qualify' }" @click="selectAction('qualify', diff.id)">Qualify</button>
                                        <button class="button love" :class="{ active: selectedAction[diff.id] === 'love' }" @click="selectAction('love', diff.id)">Love</button>
                                        <button class="button unrank" :class="{ active: selectedAction[diff.id] === 'unrank' }" @click="selectAction('unrank', diff.id)">Unrank</button>
                                        <button class="button deny" :class="{ active: selectedAction[diff.id] === 'deny' }" @click="selectAction('deny', diff.id)">Deny</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `
});