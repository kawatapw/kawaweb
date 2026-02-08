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
            userid: userid
        };
    },
    async created() {
        // starting a page
        this.modegulag = this.StrtoGulagInt();
        this.LoadProfileData();
        this.LoadAllofdata();
        this.LoadUserStatus();
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
        LoadAllofdata() {
            this.LoadMostBeatmaps();
            this.LoadScores('best');
            this.LoadScores('recent');
        },
        LoadProfileData() {
            this.$set(this.data.stats, 'load', true);
            this.$axios.get(`${window.location.protocol}//api.${domain}/v1/get_player_info`, {
                    params: {
                        id: this.userid,
                        scope: 'all'
                    }
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
            this.$axios.get(`${window.location.protocol}//api.${domain}/v1/get_player_scores`, {
                    params: {
                        id: this.userid,
                        mode: this.StrtoGulagInt(),
                        scope: sort,
                        limit: this.data.scores[`${sort}`].more.limit
                    }
                })
                .then(res => {
                    this.data.scores[`${sort}`].out = res.data.scores;
                    this.data.scores[`${sort}`].load = false
                    this.data.scores[`${sort}`].more.full = this.data.scores[`${sort}`].out.length != this.data.scores[`${sort}`].more.limit;
                });
        },
        LoadMostBeatmaps() {
            this.$set(this.data.maps.most, 'load', true);
            this.$axios.get(`${window.location.protocol}//api.${domain}/v1/get_player_most_played`, {
                    params: {
                        id: this.userid,
                        mode: this.StrtoGulagInt(),
                        limit: this.data.maps.most.more.limit
                    }
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
                .catch(function (error) {
                    clearTimeout(loop);
                    this.$log.error(error);
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
            if (obj.ARChanger === true & obj.ARChangerAR) htmlString += `<div>AR: ${obj.ARChangerAR.toFixed(2)}</div>`;
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
    computed: {},
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
