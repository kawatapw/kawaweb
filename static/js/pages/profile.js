new Vue({
    el: "#app",
    delimiters: ["<%", "%>"],
    data() {
        return {
            data: {
                stats: {
                    out: [{}],
                    load: true
                },
                grades: {},
                scores: {
                    recent: {
                        out: [],
                        load: true,
                        more: {
                            limit: 5,
                            full: true
                        }
                    },
                    best: {
                        out: [],
                        load: true,
                        more: {
                            limit: 5,
                            full: true
                        }
                    }
                },
                maps: {
                    most: {
                        out: [],
                        load: true,
                        more: {
                            limit: 6,
                            full: true
                        }
                    }
                },
                badges: [],
                userpage: {
                    load: true,
                    content: ''
                },
                status: {}
            },
            mode: mode,
            mods: mods,
            modegulag: 0,
            load: 0,
            userid: userid,
            // Season state
            schedules: [],
            selectedSchedule: null,
            seasons: [],
            selectedSeason: 0,     // 0 = all-time
            selectedYear: null,
            activeSeason: null,
            // Friend state
            isLoggedIn: typeof isLoggedIn !== 'undefined' ? isLoggedIn : false,
            isOwnProfile: typeof isOwnProfile !== 'undefined' ? isOwnProfile : false,
            isStaff: typeof isStaff !== 'undefined' ? isStaff : false,
            isFriend: false,
            isMutual: false,
            friendHover: false,
            friendLoading: false
        };
    },
    async created() {
        // starting a page
        this.modegulag = this.StrtoGulagInt();
        // Load seasons first, then data (fetchSeasons may set selectedSeason)
        var self = this;
        this.fetchSeasons().then(function() {
            self.LoadProfileData();
            self.LoadAllofdata();
        });
        this.LoadUserStatus();
        if (this.isLoggedIn && !this.isOwnProfile) {
            this.checkFriendStatus();
        }
        this.$log.debug('Data', "Profile Data Loaded:", this.data);

        // Pause status polling when tab is hidden
        this.visibilityHandler = () => {
            if (document.hidden) {
                clearTimeout(loop);
            } else {
                this.LoadUserStatus();
            }
        };
        document.addEventListener('visibilitychange', this.visibilityHandler);
    },
    beforeDestroy() {
        clearTimeout(loop);
        if (this.visibilityHandler) {
            document.removeEventListener('visibilitychange', this.visibilityHandler);
        }
    },
    methods: {
        checkFriendStatus() {
            var self = this;
            // Check if we added this user: fetch their followers — if we appear, we added them
            this.$axios.get(`${window.location.protocol}//api.${domain}/v1/get_friends_detailed`, {
                params: { id: this.userid, scope: 'followers' }
            }).then(function(res) {
                if (res.data.status === 'success' && res.data.followers) {
                    self.isFriend = res.data.followers.some(function(u) { return u.id === selfId; });
                }
            }).catch(function() {});
            // Check mutuals from our side
            this.$axios.get(`${window.location.protocol}//api.${domain}/v1/get_friends_detailed`, {
                params: { id: selfId, scope: 'mutuals' }
            }).then(function(res) {
                if (res.data.status === 'success' && res.data.mutuals) {
                    var mutual = res.data.mutuals.some(function(u) { return u.id === self.userid; });
                    if (mutual) {
                        self.isFriend = true;
                        self.isMutual = true;
                    }
                }
            }).catch(function() {});
        },
        toggleFriend() {
            var self = this;
            this.friendLoading = true;
            var action = this.isFriend ? 'remove' : 'add';
            var fd = new FormData();
            fd.append('target_id', String(this.userid));
            fetch('/friends/' + action, { method: 'POST', body: fd })
                .then(function(res) { return res.json(); })
                .then(function(data) {
                    if (data.status === 'success') {
                        self.isFriend = !self.isFriend;
                        if (!self.isFriend) self.isMutual = false;
                    }
                })
                .catch(function(err) {
                    console.error('[Profile] toggleFriend error:', err);
                })
                .then(function() { self.friendLoading = false; });
        },
        LoadAllofdata() {
            this.LoadMostBeatmaps();
            this.LoadScores('best');
            this.LoadScores('recent');
        },
        LoadProfileData() {
            this.$set(this.data.stats, 'load', true);
            var params = { id: this.userid, scope: 'all' };
            if (this.selectedSeason) params.season_id = this.selectedSeason;
            this.$axios.get(`${window.location.protocol}//api.${domain}/v1/get_player_info`, {
                    params: params
                })
                .then(res => {
                    this.$set(this.data.stats, 'out', res.data.player.stats);
                    this.data.userpage.content = res.data.player.info.userpage_content;
                    if (this.load == 0) {
                        this.$set(this.data, 'badges', res.data.player.info.badges);
                        this.load = 1;
                    }
                    this.data.stats.load = false;
                });
        },
        LoadScores(sort) {
            this.$set(this.data.scores[`${sort}`], 'load', true);
            var params = {
                id: this.userid,
                mode: this.StrtoGulagInt(),
                scope: sort,
                limit: this.data.scores[`${sort}`].more.limit
            };
            if (this.selectedSeason) params.season_id = this.selectedSeason;
            this.$axios.get(`${window.location.protocol}//api.${domain}/v1/get_player_scores`, {
                    params: params
                })
                .then(res => {
                    this.data.scores[`${sort}`].out = res.data.scores;
                    this.data.scores[`${sort}`].load = false
                    this.data.scores[`${sort}`].more.full = this.data.scores[`${sort}`].out.length != this.data.scores[`${sort}`].more.limit;
                });
        },
        LoadMostBeatmaps() {
            this.$set(this.data.maps.most, 'load', true);
            var params = {
                id: this.userid,
                mode: this.StrtoGulagInt(),
                limit: this.data.maps.most.more.limit
            };
            if (this.selectedSeason) params.season_id = this.selectedSeason;
            this.$axios.get(`${window.location.protocol}//api.${domain}/v1/get_player_most_played`, {
                    params: params
                })
                .then(res => {
                    this.data.maps.most.out = res.data.maps;
                    this.data.maps.most.load = false;
                    this.data.maps.most.more.full = this.data.maps.most.out.length != this.data.maps.most.more.limit;
                });
        },
        LoadUserStatus() {
            this.$axios.get(`${window.location.protocol}//api.${domain}/v1/get_player_status`, {
                    params: {
                        id: this.userid
                    }
                })
                .then(res => {
                    this.$set(this.data, 'status', res.data.player_status)
                })
                .catch((error) => {
                    clearTimeout(loop);
                    console.error('[Profile] LoadUserStatus error:', error);
                });
            loop = setTimeout(this.LoadUserStatus, 5000);
        },
        ChangeModeMods(mode, mods) {
            if (window.event)
                window.event.preventDefault();

            this.mode = mode;
            this.mods = mods;

            this.modegulag = this.StrtoGulagInt();
            this.data.scores.recent.more.limit = 5
            this.data.scores.best.more.limit = 5
            this.data.maps.most.more.limit = 6
            this.LoadAllofdata();
        },
        fetchSeasons() {
            var self = this;
            var proto = window.location.protocol;
            // Fetch schedules and seasons in parallel
            return Promise.all([
                self.$axios.get(`${proto}//api.${domain}/v2/schedules`),
                self.$axios.get(`${proto}//api.${domain}/v2/seasons`, { params: { page: 1, page_size: 100 } })
            ]).then(function(results) {
                var schedRes = results[0], seasRes = results[1];
                if (schedRes.data.status === 'success' && schedRes.data.data) {
                    self.schedules = schedRes.data.data;
                    if (self.schedules.length > 0) {
                        self.selectedSchedule = self.schedules[0].id;
                    }
                }
                if (seasRes.data.status === 'success' && seasRes.data.data) {
                    self.seasons = seasRes.data.data;
                    self.activeSeason = self.seasons.find(function(s) { return s.is_active; }) || null;
                    // Auto-select schedule of active season if available
                    if (self.activeSeason && self.schedules.some(function(sc) { return sc.id === self.activeSeason.schedule_id; })) {
                        self.selectedSchedule = self.activeSeason.schedule_id;
                    }
                    // Default to current season (was 0 = All Time before).
                    if (self.activeSeason && (self.selectedSeason == null || self.selectedSeason === 0)) {
                        self.selectedSeason = self.activeSeason.id;
                    }
                    if (self.yearOptions.length > 0) {
                        self.selectedYear = self.yearOptions[0];
                    }
                }
            }).catch(function() {
                // Seasons not available — switcher stays hidden
            });
        },
        _resetAndReload() {
            this.data.scores.recent.more.limit = 5;
            this.data.scores.best.more.limit = 5;
            this.data.maps.most.more.limit = 6;
            this.LoadProfileData();
            this.LoadAllofdata();
        },
        selectSeason(seasonId) {
            this.selectedSeason = seasonId;
            this._resetAndReload();
        },
        onScheduleChange() {
            if (this.yearOptions.length > 0) {
                this.selectedYear = this.yearOptions[0];
            }
            var seasons = this.filteredSeasons;
            if (seasons.length > 0) {
                this.selectedSeason = seasons[seasons.length - 1].id;
                this._resetAndReload();
            }
        },
        onYearChange() {
            var seasons = this.filteredSeasons;
            if (seasons.length > 0) {
                this.selectedSeason = seasons[seasons.length - 1].id;
                this._resetAndReload();
            }
        },
        onSeasonChange() {
            this._resetAndReload();
        },
        AddLimit(which) {
            if (window.event)
                window.event.preventDefault();

            if (which == 'bestscore') {
                this.data.scores.best.more.limit += 5;
                this.LoadScores('best');
            } else if (which == 'recentscore') {
                this.data.scores.recent.more.limit += 5;
                this.LoadScores('recent');
            } else if (which == 'mostplay') {
                this.data.maps.most.more.limit += 4;
                this.LoadMostBeatmaps();
            }
        },
        actionIntToStr(d) {
            switch (d.action) {
                case 0:
                    return 'Idle: 🔍 Song Select';
                case 1:
                    return '🌙 AFK';
                case 2:
                    return `Playing: 🎶 ${d.info_text}`;
                case 3:
                    return `Editing: 🔨 ${d.info_text}`;
                case 4:
                    return `Modding: 🔨 ${d.info_text}`;
                case 5:
                    return 'In Multiplayer: Song Select';
                case 6:
                    return `Watching: 👓 ${d.info_text}`;
                    // 7 not used
                case 8:
                    return `Testing: 🎾 ${d.info_text}`;
                case 9:
                    return `Submitting: 🧼 ${d.info_text}`;
                    // 10 paused, never used
                case 11:
                    return 'Idle: 🏢 In multiplayer lobby';
                case 12:
                    return `In Multiplayer: Playing 🌍 ${d.info_text} 🎶`;
                case 13:
                    return 'Idle: 🔍 Searching for beatmaps in osu!direct';
                default:
                    return 'Unknown: 🚔 not yet implemented!';
            }
        },
        addCommas(nStr) {
            nStr += '';
            var x = nStr.split('.');
            var x1 = x[0];
            var x2 = x.length > 1 ? '.' + x[1] : '';
            var rgx = /(\d+)(\d{3})/;
            while (rgx.test(x1)) {
                x1 = x1.replace(rgx, '$1' + ',' + '$2');
            }
            return x1 + x2;
        },
        secondsToDhm(seconds) {
            seconds = Number(seconds);
            var dDisplay = `${Math.floor(seconds / (3600 * 24))}d `;
            var hDisplay = `${Math.floor(seconds % (3600 * 24) / 3600)}h `;
            var mDisplay = `${Math.floor(seconds % 3600 / 60)}m `;
            return dDisplay + hDisplay + mDisplay;
        },
        StrtoGulagInt() {
            switch (this.mode + "|" + this.mods) {
                case 'std|vn':
                    return 0;
                case 'taiko|vn':
                    return 1;
                case 'catch|vn':
                    return 2;
                case 'mania|vn':
                    return 3;
                case 'std|rx':
                    return 4;
                case 'taiko|rx':
                    return 5;
                case 'catch|rx':
                    return 6;
                case 'std|ap':
                    return 8;
                default:
                    return -1;
            }
        },
        StrtoModeInt() {
            switch (this.mode) {
                case 'std':
                    return 0;
                case 'taiko':
                    return 1;
                case 'catch':
                    return 2;
                case 'mania':
                    return 3;
            }
        },
        MAAIntToStr(int) {
            switch (int) {
                case 0:
                    return 'V1';
                case 1:
                    return 'V2';
                case 2:
                    return 'V3';
                case 3:
                    return 'V-L1';
            }
        },
        generateMapleSettingsHTML(obj) {
            const iconMap = {
                // Aiming & FOV
                FOV_Base: '🎯',
                FOV_Min: '📍',
                FOV_Max: '🎪',
                MaxOffset: '📏',

                // Strength Settings
                BaseStrength: '💪',
                Power: '⚡',
                AimStrength: '🎯',
                ResyncStrength: '🔄',
                SliderPower: '⚡',

                // Movement & Prediction
                PredictiveAiming: '🔮',
                PredictionMs: '⏱️',
                MovementSmoothing: '🌊',
                MovementThreshold: '📊',

                // Proximity & Timing
                MinProximityStrength: '📉',
                MaxProximityStrength: '📈',
                MinTimingStrength: '⏰',
                MaxTimingStrength: '⚡',

                // Slider Handling
                EnhancedSliderHandling: '🎚️',
                SliderProgressionScale: '📐',
                MinSliderStrength: '🔽',
                MaxSliderStrength: '🔼',
                AssistOnSliders: '🛷',

                // Angle Settings
                AngleInfluence: '📐',
                MaxAngleInfluence: '📏',
                MinAngleStrength: '↘️',
                MaxAngleStrength: '↗️',

                // Acceleration
                UseAcceleration: '🚀',
                AccelerationExponent: '📈',
                AccelFactor: '🏃'
            };
        
            let settingsHTML = '<div class="settings-grid">';
            
            // Generate settings based on algorithm version
            switch(obj.Algorithm) {
                case 0: // V1
                    settingsHTML += this.generateSettingItem('FOV_Base', obj.FOV_Base, iconMap);
                    settingsHTML += this.generateSettingItem('FOV_Min', obj.FOV_Min, iconMap);
                    settingsHTML += this.generateSettingItem('FOV_Max', obj.FOV_Max, iconMap);
                    settingsHTML += this.generateSettingItem('AimStrength', obj.AimStrength, iconMap);
                    settingsHTML += this.generateSettingItem('AccelFactor', obj.AccelFactor, iconMap);
                    break;
                
                case 1: // V2
                    settingsHTML += this.generateSettingItem('Power', obj.Power, iconMap);
                    settingsHTML += this.generateSettingItem('AssistOnSliders', obj.AssistOnSliders, iconMap);
                    break;
                
                case 2: // V3
                    settingsHTML += this.generateSettingItem('Power', obj.Power, iconMap);
                    settingsHTML += this.generateSettingItem('SliderPower', obj.SliderPower, iconMap);
                    break;
                case 3: // VL1
                const vl1Settings = [
                    'FOV_Base', 'FOV_Min', 'FOV_Max', 'MaxOffset', 'FovDynamicScale', 'FovScaleMin', 'FovScaleMax', 'PreemptScale', 'MovementSmoothing', 'MovementThreshold',
                    'BaseStrength', 'ResyncStrength', 'MinProximityStrength', 'MaxProximityStrength', 'MinTimingStrength', 'MaxTimingStrength'
                    ];

                    // Add base settings
                    vl1Settings.forEach(setting => {
                        if (obj[setting] !== undefined) {
                            settingsHTML += this.generateSettingItem(setting, obj[setting], iconMap);
                        }
                    });
                
                    // Handle Grouped Settings
                    if (obj.PredictiveAiming !== undefined) {
                        settingsHTML += this.generateSettingItem('PredictiveAiming', obj.PredictiveAiming, iconMap);
                        if (obj.PredictiveAiming === true && obj.PredictionMs !== undefined) {
                            settingsHTML += this.generateSettingItem('PredictionMs', obj.PredictionMs, iconMap);
                        }
                    }
                    if (obj.EnhancedSliderHandling !== undefined) {
                        settingsHTML += this.generateSettingItem('EnhancedSliderHandling', obj.EnhancedSliderHandling, iconMap);
                        if (obj.EnhancedSliderHandling === true) {
                            if (obj.SliderProgressionScale !== undefined) settingsHTML += this.generateSettingItem('SliderProgressionScale', obj.SliderProgressionScale, iconMap);
                            if (obj.MinSliderStrength !== undefined) settingsHTML += this.generateSettingItem('MinSliderStrength', obj.MinSliderStrength, iconMap);
                            if (obj.MaxSliderStrength !== undefined) settingsHTML += this.generateSettingItem('MaxSliderStrength', obj.MaxSliderStrength, iconMap);
                        }
                    }
                    if (obj.AngleInfluence !== undefined) {
                        settingsHTML += this.generateSettingItem('AngleInfluence', obj.AngleInfluence, iconMap);
                        if (obj.AngleInfluence === true) {
                            if (obj.MaxAngleInfluence !== undefined) settingsHTML += this.generateSettingItem('MaxAngleInfluence', obj.MaxAngleInfluence, iconMap);
                            if (obj.MinAngleStrength !== undefined) settingsHTML += this.generateSettingItem('MinAngleStrength', obj.MinAngleStrength, iconMap);
                            if (obj.MaxAngleStrength !== undefined) settingsHTML += this.generateSettingItem('MaxAngleStrength', obj.MaxAngleStrength, iconMap);
                        }
                    }
                    if (obj.UseAcceleration !== undefined) {
                        settingsHTML += this.generateSettingItem('UseAcceleration', obj.UseAcceleration, iconMap);
                        if (obj.UseAcceleration === true) {
                            if (obj.AccelerationExponent !== undefined) settingsHTML += this.generateSettingItem('AccelerationExponent', obj.AccelerationExponent, iconMap);
                        }
                    }
                    break;
            }
            
            settingsHTML += '</div>';
            return settingsHTML;
        },
        
        generateSettingItem(name, value, iconMap) {
            const icon = iconMap[name] || '⚙️';
            return `
                <div class="setting-item">
                    <span class="setting-name">${this.formatSettingName(name)}</span>
                    <span class="setting-icon">${icon}</span>
                    <span class="setting-value">${this.formatSettingValue(value)}</span>
                </div>
            `;
        },
        
        formatSettingName(name) {
            return name.split('_').join(' ').replace(/([A-Z])/g, ' $1').trim();
        },
        
        formatSettingValue(value) {
            if (typeof value === 'boolean') return value ? 'On' : 'Off';
            if (typeof value === 'number') return value.toFixed(2);
            return value;
        },
        DisplayCheats(obj) {
            let htmlString = '';
            if (obj.RelaxHack === true) htmlString += `<div>Relax</div>`;
            if (obj.ARChanger === true && obj.ARChangerAR) htmlString += `<div>AR: ${obj.ARChangerAR.toFixed(2)}</div>`;
            if (obj.Timewarp === true) {
                if (obj.TimewarpRate || obj.TimewarpType == 'Rate') htmlString += `<div>TW: ${obj.TimewarpRate}%</div>`
                else if (obj.TimewarpMultiplier || obj.TimewarpType == 'Multiplier') htmlString += `<div>TW: ${obj.TimewarpMultiplier}x</div>`
            }
            if (obj.AimType) {
                if (obj.AimType == 'Correction' || obj.AimCorrectionValue)
                    if (obj.AimCorrectionRelative === true) htmlString += `<div>AC: CS + ${obj.AimCorrectionValue}</div>`
                    else htmlString += `<div>AC: ${obj.AimCorrectionValue}</div>`
                    if (obj.TapOnCorrect === true) htmlString += `<div>AC: TOC</div>`
                if (obj.AimType == 'OBAA') {
                    htmlString += `<div>AA: OsuBuddy</div>`
                }
                if (obj.AimType == 'MapleAA') {
                    htmlString += `<div class="maple-settings" onmouseover="showMaplePopup(event, this)" onmouseout="hideMaplePopup()">
                        Maple AA: ${this.MAAIntToStr(obj.Algorithm)}
                        <div class="maple-popup">
                            ${this.generateMapleSettingsHTML(obj)}
                        </div>
                    </div>`;
                }
            }
            if (obj.HiddenRemover === true) htmlString += `<div>No HD</div>`;
            if (obj.FlashlightRemover === true) htmlString += `<div>No FL</div>`;

            return htmlString;
        },
    },
    computed: {
        currentStats() {
            var s = this.data.stats.out[this.modegulag];
            if (s && typeof s.rank !== 'undefined') return s;
            return { rank: 0, country_rank: 0, pp: 0, rscore: 0, tscore: 0, max_combo: 0, plays: 0, playtime: 0, acc: 0, xh_count: 0, x_count: 0, sh_count: 0, s_count: 0, a_count: 0 };
        },
        scheduledSeasons() {
            var self = this;
            if (!this.selectedSchedule) return this.seasons;
            return this.seasons.filter(function(s) {
                return s.schedule_id === self.selectedSchedule;
            });
        },
        yearOptions() {
            var years = [];
            var ss = this.scheduledSeasons;
            for (var i = 0; i < ss.length; i++) {
                var y = new Date(ss[i].start_date).getFullYear();
                if (years.indexOf(y) === -1) years.push(y);
            }
            return years.sort(function(a, b) { return b - a; });
        },
        filteredSeasons() {
            var self = this;
            return this.scheduledSeasons
                .filter(function(s) {
                    return new Date(s.start_date).getFullYear() === self.selectedYear;
                })
                .map(function(s) {
                    var parts = s.name.split('-');
                    return Object.assign({}, s, { label: parts[parts.length - 1] });
                })
                .sort(function(a, b) {
                    return new Date(a.start_date) - new Date(b.start_date);
                });
        }
    },
});
window.showMaplePopup = (event, element) => {
    const popup = element.querySelector('.maple-popup');
    const grid = popup.querySelector('.settings-grid');
    popup.style.opacity = '1';
    popup.style.visibility = 'visible';
    popup.style.transform = 'translateX(-50%) translateY(0)';
    
    // Calculate if items wrap into multiple rows
    const firstItemTop = grid.firstElementChild.offsetTop;
    const lastItemTop = grid.lastElementChild.offsetTop;
    const hasMultipleRows = firstItemTop !== lastItemTop;
    
    // Position popup with dynamic top value
    const topOffset = hasMultipleRows ? '-175%' : '-100%';
    popup.style.left = '50%';
    popup.style.top = `calc(${topOffset} - 12px)`;
};


window.hideMaplePopup = () => {
    document.querySelectorAll('.maple-popup').forEach(popup => {
        popup.style.opacity = '0';
        popup.style.visibility = 'hidden';
        popup.style.transform = 'translateX(-50%) translateY(10px)';
    });
};
