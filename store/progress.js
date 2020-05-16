export const state = () => ({
	completed: [],
	assignments: []
})

export const getters = {
	getProgressCount: state => array => {
		let count = 0
		const completed = state.completed
		const assignments = state.assignments
		array.forEach(id => {
			if (
				completed.some(x => x === id) ||
				assignments.some(x => x === id)
			) {
				count++
			}
		})
		return count
	},
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
