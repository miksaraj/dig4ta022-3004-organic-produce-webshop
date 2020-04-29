export const state = () => ({
	coursesView: 'cards',
	modulesView: 'cards'
})

export const actions = {
	toggleView({ commit }, payload) {
		const type = payload.type + 'View'
		commit('toggle', type)
	}
}

export const mutations = {
	toggle(state, payload) {
		if (state[payload] === 'cards') {
			state[payload] = 'list'
		} else {
			state[payload] = 'cards'
		}
	}
}
