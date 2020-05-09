export const state = () => ({
	list: [
		{
			contentId: 1,
			sectionId: 1,
			order: 1,
			type: 'TheoryElement'
		},
		{
			contentId: 2,
			sectionId: 1,
			order: 2,
			type: 'Assignment'
		},
		{
			contentId: 3,
			sectionId: 2,
			order: 1,
			type: 'TheoryElement'
		},
		{
			contentId: 4,
			sectionId: 2,
			order: 2,
			type: 'SpecialText'
		},
		{
			contentId: 5,
			sectionId: 3,
			order: 1,
			type: 'TheoryElement'
		},
		{
			contentId: 6,
			sectionId: 3,
			order: 2,
			type: 'MultipleChoice'
		},
		{
			contentId: 7,
			sectionId: 4,
			order: 1,
			type: 'TheoryElement'
		},
		{
			contentId: 8,
			sectionId: 4,
			order: 2,
			type: 'ReturnAssignment'
		},
		{
			contentId: 9,
			sectionId: 5,
			order: 1,
			type: 'TheoryElement'
		}
	]
})

export const getters = {
	sectionStructure: state => id => {
		return [...state.list.filter(item => item.sectionId === id)].sort(
			function() {
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
			}
		)
	}
}
