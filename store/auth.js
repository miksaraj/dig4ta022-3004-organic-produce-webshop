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
		vm.$store.dispatch('profile/clear')
		vm.$router.go('/login')
	}
}
