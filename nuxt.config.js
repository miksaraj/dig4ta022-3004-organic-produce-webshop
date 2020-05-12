/* eslint-disable nuxt/no-cjs-in-config */
module.exports = {
	mode: 'universal',
	/*
	 ** Headers of the page
	 */
	head: {
		title: process.env.npm_package_name || '',
		meta: [
			{ charset: 'utf-8' },
			{
				name: 'viewport',
				content: 'width=device-width, initial-scale=1'
			},
			{
				hid: 'description',
				name: 'description',
				content: process.env.npm_package_description || ''
			}
		],
		link: [{ rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }]
	},
	/*
	 ** Customize the progress-bar color
	 */
	loading: { color: '#fff' },
	/*
	 ** Global CSS
	 */
	css: ['@/assets/main.css'],
	/*
	 ** Plugins to load before mounting the App
	 */
	plugins: [],
	/*
	 ** Nuxt.js dev-modules
	 */
	buildModules: [
		// Doc: https://github.com/nuxt-community/eslint-module
		'@nuxtjs/eslint-module',
		// Doc: https://github.com/nuxt-community/stylelint-module
		'@nuxtjs/stylelint-module'
	],
	/*
	 ** Nuxt.js modules
	 */
	modules: [
		// Doc: https://bootstrap-vue.js.org
		'bootstrap-vue/nuxt',
		// Doc: https://axios.nuxtjs.org/usage
		'@nuxtjs/axios',
		'@nuxtjs/pwa',
		// Doc: https://github.com/nuxt-community/dotenv-module
		'@nuxtjs/dotenv'
	],
	bootstrapVue: {
		icons: true
	},
	/*
	 ** Axios module configuration
	 ** See https://axios.nuxtjs.org/options
	 */
	axios: {},
	/*
	 ** Build configuration
	 */
	build: {
		/*
		 ** You can extend webpack config here
		 */
		extend(config, ctx) {
			// Run ESLint on save
			if (ctx.isDev && ctx.isClient) {
				config.module.rules.push({
					enforce: 'pre',
					test: /\.(js|vue)$/,
					loader: 'eslint-loader',
					exclude: /(node_modules)/
				})
			}
			/**
			 * Tansform Asset Urls to enable using
			 * images in ./static with Bootstrap-Vue
			 * elements.
			 * UNCOMMENT IF NEEDED!
			 * -- From Bootstrap-Vue Docs:
			 * "If using the BootstrapVue Nuxt module with Nuxt.js,
			 * the plugin module will automatically add in the BootstrapVue
			 * specific transformAssetUrls configuration for you."
			 */
			/*
			const vueLoader = config.module.rules.find(
				rule => rule.loader === 'vue-loader'
			)
			vueLoader.options.transformAssetUrls = {
				video: ['src', 'poster'],
				source: 'src',
				img: 'src',
				image: 'xlink:href',
				'b-avatar': 'src',
				'b-img': 'src',
				'b-img-lazy': ['src', 'blank-src'],
				'b-card': 'img-src',
				'b-card-img': 'src',
				'b-card-img-lazy': ['src', 'blank-src'],
				'b-carousel-slide': 'img-src',
				'b-embed': 'src'
			}
			*/
		}
	},
	server: {
		host: '0.0.0.0'
	},
	router: {
		middleware: 'auth'
	}
}
