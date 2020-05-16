export const state = () => ({
	completed: [],
	assignments: []
})

export const getters = {
	/*
	progressBySection: state => id => {
		return state.completed.filter(item => item.section === id)
	},
	progressByChapter: state => id => {
		return state.completed.filter(item => item.chapter === id)
	},
	*/
	isRead: state => id => {
		return state.completed.includes(id)
	},
	isDone: state => id => {
		return state.assignments.includes(id)
	}
}

export const mutations = {
	toggleRead(state, id) {
		if (state.completed.includes(id)) {
			state.completed = state.completed.filter(x => x !== id)
		} else {
			state.completed.push(id)
		}
	},
	markAsDone(state, id) {
		if (!state.assignments.includes(id)) {
			state.assignments.push(id)
		}
	}
}

export const actions = {
	toggleRead({ commit }, id) {
		commit('toggleRead', id)
	},
	markAsDone({ commit }, id) {
		commit('markAsDone', id)
	}
}
