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
        this.$log = ColorfulLogger.child('Admin | Beatmaps Page');
        this.$log.info('LIFECYCLE', 'Beatmaps.js Beatmaps Page Created');
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
        }
    },
    created: function() {
        this.$log = ColorfulLogger.child('Admin | Edit Beatmap Panel');
        editMapBus.$on('showEditBeatmapPanel', (map) => {
            this.$log.debug('EVENT', 'Edit Beatmap Window Triggered')
            this.$log.debug('DATA', 'Map data:', map);
            this.beatmap = map;
            this.$log.debug('DATA', 'Beatmap set:', this.beatmap);
            this.show = true;
        });
    },
    methods: {
        close: function() {
            this.show = false;
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
    },
    computed: {
        statusInfo() {
            const statuses = ['Pending', 'Update Available', 'Ranked', 'Approved', 'Qualified', 'Loved'];
            const statusClasses = ['pending', 'update', 'ranked', 'approved', 'qualified', 'loved'];
            const status = this.beatmap.map_info.status;
            return {
                text: statuses[status],
                class: statusClasses[status]
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
                                <button class="button" @click="postAction('/admin/action/completerequest', { map: beatmap['map_info']['id'] })">Mark Request as Complete</button>
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
                                        <button class="button rank" @click="postAction('/admin/action/rank', { map: beatmap['map_info']['id'] })">Rank</button>
                                        <button class="button approve" @click="postAction('/admin/action/approve', { map: beatmap['map_info']['id'] })">Approve</button>
                                        <button class="button qualify" @click="postAction('/admin/action/qualify', { map: beatmap['map_info']['id'] })">Qualify</button>
                                        <button class="button love" @click="postAction('/admin/action/love', { map: beatmap['map_info']['id'] })">Love</button>
                                        <button class="button unrank" @click="postAction('/admin/action/unrank', { map: beatmap['map_info']['id'] })">Unrank</button>
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
                                        <button class="button rank" @click="postAction('/admin/action/rank', { map: diff['id'] })">Rank</button>
                                        <button class="button approve" @click="postAction('/admin/action/approve', { map: diff['id'] })">Approve</button>
                                        <button class="button qualify" @click="postAction('/admin/action/qualify', { map: diff['id'] })">Qualify</button>
                                        <button class="button love" @click="postAction('/admin/action/love', { map: diff['id'] })">Love</button>
                                        <button class="button unrank" @click="postAction('/admin/action/unrank', { map: diff['id'] })">Unrank</button>
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