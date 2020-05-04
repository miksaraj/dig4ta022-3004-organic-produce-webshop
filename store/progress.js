export const state = () => ({
	completed: [
		{
			module: 1,
			course: 1,
			task: 1
		},
		{
			module: 1,
			course: 1,
			task: 2
		},
		{
			module: 1,
			course: 1,
			task: 3
		},
		{
			module: 1,
			course: 1,
			task: 4
		},
		{
			module: 2,
			course: 1,
			task: 1
		},
		{
			module: 2,
			course: 1,
			task: 2
		},
		{
			module: 7,
			course: 2,
			task: 1
		}
	]
})

export const getters = {
	progressByModule: state => id => {
		return state.completed.filter(item => item.module === id)
	},
	progressByCourse: state => id => {
		return state.completed.filter(item => item.course === id)
	}
}
