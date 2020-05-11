export const state = () => ({
	completed: [
		{
			section: 1,
			chapter: 1,
			assignments: 1
		},
		{
			section: 2,
			chapter: 1,
			assignments: 1
		},
		{
			section: 1,
			chapter: 1,
			assignments: 3
		},
		{
			section: 1,
			chapter: 1,
			assignments: 4
		},
		{
			section: 2,
			chapter: 1,
			assignments: 1
		},
		{
			section: 2,
			chapter: 1,
			assignments: 2
		},
		{
			section: 7,
			chapter: 2,
			assignments: 1
		}
	]
})

export const getters = {
	progressBySection: state => id => {
		return state.completed.filter(item => item.section === id)
	},
	progressByChapter: state => id => {
		return state.completed.filter(item => item.chapter === id)
	}
}
