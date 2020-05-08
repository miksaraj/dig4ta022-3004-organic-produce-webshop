export const state = () => ({
	user: null
})

export const mutations = {
	login(state, payload) {
		state.user = payload
	},
	logout(state) {
		state.user = null
	}
}

export const actions = {
	login({ commit }, payload) {
		commit('login', payload)
	},
	logout({ commit }, vm) {
		commit('logout')
		vm.$router.go('/login')
	}
}
