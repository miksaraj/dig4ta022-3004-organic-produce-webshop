/**	Just a basic dummy state for storing
 * an ordered list of our first dummy
 * chapter's different sections so that
 * we can demonstrate a suitable structure
 * for Chapter-component
 * */

export const state = () => ({
	list: [
		{
			order: 1,
			type: 'TheoryElement'
		},
		{
			order: 2,
			type: 'BasicText'
		},
		{
			order: 3,
			type: 'Assignment'
		},
		{
			order: 4,
			type: 'BasicText'
		},
		{
			order: 5,
			type: 'SpecialText'
		},
		{
			order: 6,
			type: 'BasicText'
		},
		{
			order: 7,
			type: 'MultipleChoice'
		},
		{
			order: 8,
			type: 'BasicText'
		},
		{
			order: 9,
			type: 'Assignment'
		},
		{
			order: 10,
			type: 'BasicText'
		}
	]
})

// We need to sort the list here though
export const getters = {
	orderedList: state => {
		return [...state.list].sort(function() {
			const key = 'order'
			return function innerSort(a, b) {
				const varA = a[key]
				const varB = b[key]
				let comparison = 0
				if (varA > varB) {
					comparison = 1
				} else if (varA < varB) {
					comparison = -1
				}
				return comparison
			}
		})
	}
}
