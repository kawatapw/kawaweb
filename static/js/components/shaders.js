Vue.component('bg-effect-psy', {
    props: {
        width: {
            type: Number,
            default: function() {
              return this.$el ? this.$el.clientWidth : window.innerWidth;
            }
        },
        height: {
            type: Number,
            default: function() {
              return this.$el ? this.$el.clientHeight : window.innerHeight;
            }
        },
        settings: {
            type: Object,
            default: function() {
              return {
                speed: 0.2,
                hue: 0.5,
                hueVariation: 0.1,
                gradient: 0.15,
                density: 0.5,
                displacement: 0.25,
                zindex: -1,
              };
            }
        },
        showGui: {
            type: Boolean,
            default: false
        },
        debugLevel: {
            type: Number,
            default: 0 // 0: minimal, 1: normal, 2: verbose
        }
    },
    data: function() {
        const defaultSettings = {
            speed: 0.2,
            hue: 0.5,
            hueVariation: 0.1,
            gradient: 0.15,
            density: 0.5,
            displacement: 0.25,
            zindex: 0
        };
        
        // Merge provided settings with defaults
        const mergedSettings = { ...defaultSettings, ...this.settings };
        return {
            world: null,
            mousePos: { x: 0, y: 0, px: 0.5, py: 0.5 },
            parameters: mergedSettings,
            gui: null,
            vertexShader: `
                // attributes of our mesh
                attribute vec3 position;
                attribute vec2 uv;

                // built-in uniforms from ThreeJS camera and Object3D
                uniform mat4 projectionMatrix;
                uniform mat4 modelViewMatrix;
                uniform mat3 normalMatrix;

                // custom uniforms to build up our tubes
                uniform float uTime;
                uniform vec2 uMousePosition;

                // pass a few things along to the vertex shader
                varying vec2 vUv;

                void main() {
                    vUv = uv;
                    vec4 pos = vec4(position, 1.0);
                    gl_Position = pos;
                }
            `,
            fragmentShader: `
                precision highp float;

	            uniform float uTime;
	            uniform vec2 uMousePosition;
	            uniform float uHue;
	            uniform float uHueVariation;
	            uniform float uDensity;
	            uniform float uDisplacement;
	            uniform float uGradient;
                uniform vec2 uResolution;

	            varying vec2 vUv;

	            float mod289(float x){return x - floor(x * (1.0 / 289.0)) * 289.0;}
	            vec4 mod289(vec4 x){return x - floor(x * (1.0 / 289.0)) * 289.0;}
	            vec4 perm(vec4 x){return mod289(((x * 34.0) + 1.0) * x);}

	            float rand(vec2 co){
	            	return fract(sin(dot(co.xy ,vec2(12.9898,78.233))) * 43758.5453);
	            }

	            float hue2rgb(float f1, float f2, float hue) {
	            	if (hue < 0.0)
	            			hue += 1.0;
	            	else if (hue > 1.0)
	            			hue -= 1.0;
	            	float res;
	            	if ((6.0 * hue) < 1.0)
	            			res = f1 + (f2 - f1) * 6.0 * hue;
	            	else if ((2.0 * hue) < 1.0)
	            			res = f2;
	            	else if ((3.0 * hue) < 2.0)
	            			res = f1 + (f2 - f1) * ((2.0 / 3.0) - hue) * 6.0;
	            	else
	            			res = f1;
	            	return res;
	            }

	            vec3 hsl2rgb(vec3 hsl) {
	            	vec3 rgb;
            
	            	if (hsl.y == 0.0) {
	            		rgb = vec3(hsl.z); // Luminance
	            	} else {
	            		float f2;
        
	            		if (hsl.z < 0.5)
	            				f2 = hsl.z * (1.0 + hsl.y);
	            		else
	            				f2 = hsl.z + hsl.y - hsl.y * hsl.z;
        
	            		float f1 = 2.0 * hsl.z - f2;
        
	            		rgb.r = hue2rgb(f1, f2, hsl.x + (1.0/3.0));
	            		rgb.g = hue2rgb(f1, f2, hsl.x);
	            		rgb.b = hue2rgb(f1, f2, hsl.x - (1.0/3.0));
	            	}
	            	return rgb;
	            }

	            vec3 hsl2rgb(float h, float s, float l) {
	            	return hsl2rgb(vec3(h, s, l));
	            }

	            float noise(vec3 p){
	            	vec3 a = floor(p);
	            	vec3 d = p - a;
	            	d = d * d * (3.0 - 2.0 * d);

	            	vec4 b = a.xxyy + vec4(0.0, 1.0, 0.0, 1.0);
	            	vec4 k1 = perm(b.xyxy);
	            	vec4 k2 = perm(k1.xyxy + b.zzww);

	            	vec4 c = k2 + a.zzzz;
	            	vec4 k3 = perm(c);
	            	vec4 k4 = perm(c + 1.0);

	            	vec4 o1 = fract(k3 * (1.0 / 41.0));
	            	vec4 o2 = fract(k4 * (1.0 / 41.0));

	            	vec4 o3 = o2 * d.z + o1 * (1.0 - d.z);
	            	vec2 o4 = o3.yw * d.x + o3.xz * (1.0 - d.x);

	            	return o4.y * d.y + o4.x * (1.0 - d.y);
	            }

	            vec2 fade(vec2 t) {return t*t*t*(t*(t*6.0-15.0)+10.0);}

	            float cnoise(vec2 P){
	            	vec4 Pi = floor(P.xyxy) + vec4(0.0, 0.0, 1.0, 1.0);
	            	vec4 Pf = fract(P.xyxy) - vec4(0.0, 0.0, 1.0, 1.0);
	            	Pi = mod(Pi, 289.0); // To avoid truncation effects in permutation
	            	vec4 ix = Pi.xzxz;
	            	vec4 iy = Pi.yyww;
	            	vec4 fx = Pf.xzxz;
	            	vec4 fy = Pf.yyww;
	            	vec4 i = perm(perm(ix) + iy);
	            	vec4 gx = 2.0 * fract(i * 0.0243902439) - 1.0; // 1/41 = 0.024...
	            	vec4 gy = abs(gx) - 0.5;
	            	vec4 tx = floor(gx + 0.5);
	            	gx = gx - tx;
	            	vec2 g00 = vec2(gx.x,gy.x);
	            	vec2 g10 = vec2(gx.y,gy.y);
	            	vec2 g01 = vec2(gx.z,gy.z);
	            	vec2 g11 = vec2(gx.w,gy.w);
	            	vec4 norm = 1.79284291400159 - 0.85373472095314 *
	            	vec4(dot(g00, g00), dot(g01, g01), dot(g10, g10), dot(g11, g11));
	            	g00 *= norm.x;
	            	g01 *= norm.y;
	            	g10 *= norm.z;
	            	g11 *= norm.w;
	            	float n00 = dot(g00, vec2(fx.x, fy.x));
	            	float n10 = dot(g10, vec2(fx.y, fy.y));
	            	float n01 = dot(g01, vec2(fx.z, fy.z));
	            	float n11 = dot(g11, vec2(fx.w, fy.w));
	            	vec2 fade_xy = fade(Pf.xy);
	            	vec2 n_x = mix(vec2(n00, n01), vec2(n10, n11), fade_xy.x);
	            	float n_xy = mix(n_x.x, n_x.y, fade_xy.y);
	            	return 2.3 * n_xy;
	            }

	            void main () {
                    vec2 uv = gl_FragCoord.xy / uResolution;
	            	float mouseDistance = length(vUv - uMousePosition);
	            	float t = uTime * .005;
	            	float elevation =  vUv.y * uDensity * 30.0;

	            	float shadow = smoothstep(0.0, .3 + sin(t * 5.0 * 3.14) * .1 , mouseDistance);
	            	elevation += shadow * 5.0;

	            	float displacement = cnoise( vec2( t + vUv.y * 2.0, t + vUv.x * 3.0 )) * uDisplacement * 3.0 ;

	            	elevation += displacement * 4.0;
	            	elevation *= 2.0 + cnoise( vec2( t + vUv.y * 1.0, t + .5)) * 2.0 ;

	            	//elevation += cnoise ( vec2 (elevation * .1, t * 3.0) );

	            	float light = .9 + fract(elevation) ;
	            	light *= .9 + (1.0 - (displacement * displacement)) * .1;
	            	elevation = floor(elevation);
	            	//elevation += uGradient * .25;

	            	float hue =  uHue + shadow * .1 + cnoise( vec2( elevation * .10, .1 + t)) * uHueVariation;
	            	float saturation = .6;;
	            	float brightness =  - (1.0 - shadow) * .1 + .5  - smoothstep( 0.0, .9,  cnoise( vec2( elevation * .5, .4 + t * 5.0)) ) * .1;


	            	vec3 hslCol = vec3( hue, saturation, brightness);
	            	vec3 col = hsl2rgb(hslCol) * vec3(light, 1.0, 1.0);


	            	/* circle:
	            	float d = length(vUv- vec2(.5,.5));
	            	float radius = .1;// + (t * .1);
	            	float stroke = 0.001;
	            	float smoothing = .0005;
	            	d = smoothstep(radius, radius+smoothing, d) - smoothstep(radius+stroke, radius+stroke+smoothing, d);

	            	col += d;// * 10.0;
	            	*/

	            	gl_FragColor = vec4(col, 1.);
	            }
            `
        };
    },
    created: function() {
        this.log('debug', 1, "BG Effect Psy component created with parameters:", this.parameters);
        this.log('debug', 2, "Debug level set to:", this.debugLevel);
    },
    mounted: function() {
        this.log('debug', 1, "BG Effect Psy component mounted");
        this.log('debug', 1, "settings:", this.settings);
        // Check if THREE is available
        if (!window.THREE) {
            this.log('error', 0, "THREE.js is not loaded. Make sure it's included before this component.");
            return;
        }
        
        // Initialize the component
        this.$nextTick(() => {
            this.log('debug', 2, "Starting initialization in nextTick");
            this.initWorld();
            window.addEventListener('resize', this.handleWindowResize);
            window.addEventListener('mousemove', this.handleMouseMove);

            if (this.showGui && window.dat) {
                this.log('debug', 1, "Initializing GUI");
                this.initGui();
            } else if (this.showGui && !window.dat) {
                this.log('warn', 0, "dat.GUI not available but showGui is true");
            }
            
            // Start the animation loop
            this.loop();
            this.log('info', 1, "Animation loop started");
        });
    },
    beforeDestroy: function() {
        this.log('debug', 1, "BG Effect Psy component being destroyed");
        
        window.removeEventListener('resize', this.handleWindowResize);
        window.removeEventListener('mousemove', this.handleMouseMove);
        
        // Clean up Three.js resources
        if (this.world && this.world.renderer) {
            this.log('debug', 2, "Disposing Three.js resources");
            this.world.renderer.dispose();
            if (this.world.scene) this.world.scene.dispose();
            if (this.world.planeGeometry) this.world.planeGeometry.dispose();
            if (this.world.material) this.world.material.dispose();
        } else {
            this.log('warn', 1, "No world or renderer to dispose");
        }

        // Clean up dat.GUI
        if (this.gui) {
            this.log('debug', 2, "Destroying GUI");
            this.gui.destroy();
        }
    },
    methods: {
        log: function(level, minDebugLevel, ...args) {
            if (this.debugLevel < minDebugLevel) return;
            
            if (this.$log && typeof this.$log[level] === 'function') {
                this.$log[level](...args);
            } else {
                console[level === 'debug' ? 'log' : level](...args);
            }
        },
        
        initWorld: function() {
            this.log('debug', 1, "Initializing world");
            
            const container = this.$el;
            
            if (!container) {
                this.log('error', 0, "Container element not found");
                return;
            }

            try {
                // Create the renderer
                this.world = {
                    renderer: new THREE.WebGLRenderer({
                        alpha: true,
                        antialias: true
                    }),
                    scene: new THREE.Scene(),
                    timer: 0,
                    mousePos: { x: 0.5, y: 0.5 },
                    targetMousePos: { x: 0.5, y: 0.5 }
                };
                // Log the initial timer value
                this.log('debug', 2, "Initial timer value:", this.world.timer);
                // Log the speed parameter
                this.log('debug', 2, "Speed parameter value:", this.parameters.speed);
                this.log('debug', 2, "Renderer created");
                
                const containerWidth = this.$el.clientWidth;
                const containerHeight = this.$el.clientHeight;

                const baseWidth = this.width;
                const baseHeight = this.height;
                
                // Calculate scaling factors based on size difference from base dimensions
                const widthRatio = containerWidth / baseWidth;
                const heightRatio = containerHeight / baseHeight;
                const sizeRatio = Math.min(widthRatio, heightRatio);

                // Dynamic scaling: smaller elements get closer to 3x scaling
                const maxScale = 3;
                const minScale = 1;
                const threshold = 0.2; // Adjust this to control when max scaling kicks in

                const scaleFactor = sizeRatio < threshold ? 
                    maxScale : 
                    minScale + (maxScale - minScale) * (1 - Math.min(1, sizeRatio / threshold));

                
                const size = new THREE.Vector2(
                    containerWidth * scaleFactor,
                    containerHeight * scaleFactor
                );

                // Set up renderer
                this.world.renderer.setPixelRatio(window.devicePixelRatio);
                this.world.renderer.setSize(
                    size.x,
                    size.y
                );
                container.appendChild(this.world.renderer.domElement);
                this.log('debug', 2, `Renderer size set to ${this.$el.clientWidth}x${this.$el.clientHeight}, pixel ratio: ${window.devicePixelRatio}`);

                // Set up camera
                const nearPlane = 0.1;
                const farPlane = 20000;
                this.world.camera = new THREE.PerspectiveCamera(
                    50, // field of view
                    this.$el.clientWidth / this.$el.clientHeight, // aspect ratio
                    nearPlane,
                    farPlane
                );
                this.world.camera.position.z = 2;
                this.log('debug', 2, "Camera created with aspect ratio:", this.$el.clientWidth / this.$el.clientHeight);

                // Create the plane with shader material
                this.createPlane();
                
                this.log('info', 1, "World initialized successfully");
            } catch (error) {
                this.log('error', 0, "Error initializing world:", error);
            }
        },

        createPlane: function() {
            this.log('debug', 2, "Creating plane with shader material");
            try {
                this.world.material = new THREE.RawShaderMaterial({
                    vertexShader: this.vertexShader,
                    fragmentShader: this.fragmentShader,
                    uniforms: {
                        uTime: { type: 'f', value: 0 },
                        uHue: { type: 'f', value: this.parameters.hue },
                        uHueVariation: { type: 'f', value: this.parameters.hueVariation },
                        uGradient: { type: 'f', value: this.parameters.gradient },
                        uDensity: { type: 'f', value: this.parameters.density },
                        uDisplacement: { type: 'f', value: this.parameters.displacement },
                        uMousePosition: { type: 'v2', value: new THREE.Vector2(0.5, 0.5) }
                    }
                });

                this.log('debug', 2, "Shader material created with uniforms:", 
                    JSON.stringify({
                        hue: this.parameters.hue,
                        hueVariation: this.parameters.hueVariation,
                        gradient: this.parameters.gradient,
                        density: this.parameters.density,
                        displacement: this.parameters.displacement
                    })
                );

                this.world.planeGeometry = new THREE.PlaneGeometry(2, 2, 1, 1);
                this.world.plane = new THREE.Mesh(this.world.planeGeometry, this.world.material);
                this.world.scene.add(this.world.plane);
                this.log('debug', 1, "Plane created and added to scene");
            } catch (error) {
                this.log('error', 0, "Error creating plane:", error);
                if (error.toString().includes("shader")) {
                    this.log('error', 0, "Shader compilation error. Check shader code.");
                }
            }
        },

        render: function() {
            try {
                // Check if speed is a valid number
                if (typeof this.parameters.speed !== 'number' || isNaN(this.parameters.speed)) {
                    this.log('error', 0, "Invalid speed parameter:", this.parameters.speed);
                    // Set a default value
                    this.parameters.speed = 0.2;
                }

                // Check if timer is a valid number
                if (typeof this.world.timer !== 'number' || isNaN(this.world.timer)) {
                    this.log('error', 0, "Invalid timer value:", this.world.timer);
                    // Reset timer
                    this.world.timer = 0;
                }
                this.world.timer += this.parameters.speed;
                this.world.plane.material.uniforms.uTime.value = this.world.timer;

                this.world.mousePos.x += (this.world.targetMousePos.x - this.world.mousePos.x) * 0.1;
                this.world.mousePos.y += (this.world.targetMousePos.y - this.world.mousePos.y) * 0.1;

                if (this.world.plane) {
                    this.world.plane.material.uniforms.uMousePosition.value = new THREE.Vector2(
                        this.world.mousePos.x,
                        this.world.mousePos.y
                    );
                    
                    this.log('debug', 2, `Render frame: time=${this.world.timer.toFixed(2)}, mouse=(${this.world.mousePos.x.toFixed(2)}, ${this.world.mousePos.y.toFixed(2)})`);
                } else {
                    this.log('warn', 1, "Render called but plane is not available");
                }

                this.world.renderer.render(this.world.scene, this.world.camera);
            } catch (error) {
                this.log('error', 0, "Error in render loop:", error);
            }
        },

        loop: function() {
            try {
                this.render();
                requestAnimationFrame(this.loop.bind(this));
            } catch (error) {
                this.log('error', 0, "Animation loop error:", error);
            }
        },

        updateSize: function(w, h) {
            this.log('debug', 1, `Updating size to ${w}x${h}`);
            try {
                this.world.renderer.setSize(w, h);
                this.world.camera.aspect = w / h;
                this.world.camera.updateProjectionMatrix();
                this.log('debug', 2, "Size updated, camera projection matrix recalculated");
            } catch (error) {
                this.log('error', 0, "Error updating size:", error);
            }
        },

        mouseMove: function(mousePos) {
            this.world.targetMousePos.x = mousePos.px;
            this.world.targetMousePos.y = mousePos.py;
            this.log('debug', 2, `Mouse target position updated: (${mousePos.px.toFixed(2)}, ${mousePos.py.toFixed(2)})`);
        },

        handleWindowResize: function() {
            const width = this.$el.clientWidth;
            const height = this.$el.clientHeight;
            this.log('debug', 1, `Window resize detected: ${width}x${height}`);
            this.updateSize(width, height);
        },

        handleMouseMove: function(e) {
            this.mousePos.x = e.clientX;
            this.mousePos.y = e.clientY;
            this.mousePos.px = this.mousePos.x / window.innerWidth;
            this.mousePos.py = 1.0 - this.mousePos.y / window.innerHeight;
            this.mouseMove(this.mousePos);
        },

        initGui: function() {
            try {
                this.gui = new dat.GUI();
                this.gui.width = 250;
                
                const guiSpeed = this.gui.add(this.parameters, 'speed').min(0.1).max(1).step(0.01).name('speed');
                const guiHue = this.gui.add(this.parameters, 'hue').min(0).max(1).step(0.01).name('hue');
                const guiVariation = this.gui.add(this.parameters, 'hueVariation').min(0).max(1).step(0.01).name('hue variation');
                const guiDensity = this.gui.add(this.parameters, 'density').min(0).max(1).step(0.01).name('density');
                const guiDisp = this.gui.add(this.parameters, 'displacement').min(0).max(1).step(0.01).name('displacement');
                
                guiHue.onChange(this.updateParameters);
                guiVariation.onChange(this.updateParameters);
                guiDensity.onChange(this.updateParameters);
                guiDisp.onChange(this.updateParameters);
                
                this.updateParameters();
                this.log('debug', 1, "GUI initialized with controls");
            } catch (error) {
                this.log('error', 0, "Error initializing GUI:", error);
            }
        },

        updateParameters: function() {
            this.log('debug', 1, "Updating shader parameters");
            if (this.world && this.world.plane) {
                try {
                    this.world.plane.material.uniforms.uHue.value = this.parameters.hue;
                    this.world.plane.material.uniforms.uHueVariation.value = this.parameters.hueVariation;
                    this.world.plane.material.uniforms.uDensity.value = this.parameters.density;
                    this.world.plane.material.uniforms.uDisplacement.value = this.parameters.displacement;
                    this.world.plane.material.uniforms.uGradient.value = this.parameters.gradient;
                    this.world.plane.material.uniforms.uResolution = new THREE.Vector2(this.$el.clientWidth, this.$el.clientHeight);
                    
                    this.log('debug', 2, "Parameters updated:", 
                        JSON.stringify({
                            hue: this.parameters.hue,
                            hueVariation: this.parameters.hueVariation,
                            density: this.parameters.density,
                            displacement: this.parameters.displacement
                        })
                    );
                } catch (error) {
                    this.log('error', 0, "Error updating parameters:", error);
                }
            } else {
                this.log('warn', 1, "Cannot update parameters: world or plane not initialized");
            }
        }
    },
    watch: {
        settings: {
            handler: function(newSettings) {
                this.log('debug', 1, "Settings changed:", newSettings);
                
                // Default settings to ensure all required values exist
                const defaultSettings = {
                    speed: 0.2,
                    hue: 0.5,
                    hueVariation: 0.1,
                    gradient: 0.3,
                    density: 0.5,
                    displacement: 0.66
                };
                
                // Merge new settings with defaults
                this.parameters = { ...defaultSettings, ...newSettings };
                
                this.log('debug', 2, "Merged parameters:", this.parameters);
                this.updateParameters();
            },
            deep: true
        },
        debugLevel: {
            handler: function(newLevel) {
                this.log('info', 0, "Debug level changed to:", newLevel);
            }
        }
    },
    template: `
    <div class="bg-effect-psy" style="width: 100%; height: 100%; position: absolute; top: 0; left: 0; overflow: hidden; border-radius: inherit;" :style="{'z-index': settings.zindex}"></div>
    `
  });