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
			sectionId: 1,
			order: 3,
			type: 'TheoryElement'
		},
		{
			contentId: 4,
			sectionId: 1,
			order: 4,
			type: 'SpecialText'
		},
		{
			contentId: 5,
			sectionId: 1,
			order: 5,
			type: 'TheoryElement'
		},
		{
			contentId: 6,
			sectionId: 1,
			order: 6,
			type: 'MultipleChoice'
		},
		{
			contentId: 7,
			sectionId: 1,
			order: 7,
			type: 'TheoryElement'
		},
		{
			contentId: 8,
			sectionId: 1,
			order: 8,
			type: 'ReturnAssignment'
		},
		{
			contentId: 9,
			sectionId: 1,
			order: 9,
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
