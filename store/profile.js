export const state = () => ({
	details: {
		// id,
		email: '',
		name: '',
		username: ''
	}
})

export const mutations = {
	update(state, payload) {
		for (const [key, value] of Object.entries(payload)) {
			state.details[key] = value
		}
	},
	clear(state) {
		state.details = {}
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
