export const state = () => ({
	list: [
		{
			id: 1,
			header: 'JavaScriptin alkeet',
			description: 'Tällä kurssilla opit kaiken olennaisen.'
		},
		{
			id: 2,
			header: 'Vue.js aloittelijoille',
			description: 'Vue on nopea, mutta monikäyttöinen!'
		},
		{
			id: 3,
			header: 'React.js',
			description: 'Opiskele kuukaudessa React-mestariksi!'
		},
		{
			id: 4,
			header: 'Java-ohjelmointi',
			description: 'Tällä kurssilla otat haltuun Java-ohjelmoinnin.'
		},
		{
			id: 5,
			header: 'PHP',
			description:
				'Klassisen, mutta aina ajankohtaisen ohjelmointikielen otat haltuusi tällä kurssilla.'
		},
		{
			id: 6,
			header: 'Node.js:llä nopeasti valmista',
			description:
				'Nodella teet muutamassa viikossa jo pelkkää timanttia!'
		}
	]
})

export const getters = {
	chapterById: state => id => {
		return state.list.find(x => x.id === id)
	}
}
