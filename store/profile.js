export const state = () => ({
	details: {
		email: '',
		name: '',
		username: ''
	}
})

export const mutations = {
	update(state, payload) {
		for (const [key, value] of Object.entries(payload)) {
			if (key in state.details) {
				state.details[key] = value
			}
		}
		// set base64 encoded password to cookies
		if (payload.pwd) {
			window.$nuxt.$cookies.set('pw', payload.pwd)
		}
	},
	clear(state) {
		state.details = {}
		window.$nuxt.$cookies.remove('pw')
	}
}

export const actions = {
	update({ commit }, payload) {
		commit('update', payload)
	},
	clear({ commit }) {
		commit('clear')
	}
}
