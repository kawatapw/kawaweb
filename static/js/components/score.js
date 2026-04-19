// Note: Needs to be refactored into a master score component with sub components for displaying scores in different display styles to be used around the website.
Vue.component('score-card', {
  delimiters: ["<%", "%>"],
  props: {
    score: {
      type: Object,
      required: true
    },
    type: {
      type: String,
      default: 'best'
    }
  },
  created () {
    this.$log = ColorfulLogger.child('Comp | Score Card');
  },
  methods: {
    formatNumber(num) {
      if (!num) return '0';
      num += '';
      var x = num.split('.');
      var x1 = x[0];
      var x2 = x.length > 1 ? '.' + x[1] : '';
      var rgx = /(\d+)(\d{3})/;
      while (rgx.test(x1)) {
        x1 = x1.replace(rgx, '$1' + ',' + '$2');
      }
      return x1 + x2;
    },
    DisplayCheats(obj) {
      if (!obj) return '';
      
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
      this.$log.debug("Score", `Displaying score card for score: ${this.score.id}`, this.score);
      return htmlString;
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
  },
  beforeDestroy() {
    // Clean up any resources
    if (this.$log) {
      this.$log.debug('LIFECYCLE', 'Score card component destroyed');
    }
  },
  template: `#score-card-template`
});
