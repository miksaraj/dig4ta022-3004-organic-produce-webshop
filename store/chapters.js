// list of chapters with details required for dynamic rendering
export const state = () => ({
	// TÄÄLTÄ PUUTTUU KUVAT!
	list: [
		{
			id: 1,
			header: 'Aloitus',
			description: 'Tietoa opiskelusta sekä johdanto psykologiaan.',
			src: '/img/'
		},
		{
			id: 2,
			header: 'Biologinen näkökulma',
			description: 'Aivot ja hermosto psyykkisen toiminnan perustana',
			src: '/img/'
		},
		{
			id: 3,
			header: 'Käyttäytymisen näkökulma',
			description:
				'Ärsykkeillä voidaan ehdollistaa eläimiä ja ihmisiä oppimaan',
			src: '/img/'
		},
		{
			id: 4,
			header: 'Kognitiivinen näkökulma',
			description: 'Ihminen aktiivisena tiedonrakentajana',
			src: '/img/'
		},
		{
			id: 5,
			header: 'Tunteiden ja motivaation näkökulma',
			description:
				'Innostus syntyy itsetunnon, vapauden ja muiden ihmisten avulla',
			src: '/img/'
		},
		{
			id: 6,
			header: 'Sosiokulttuurinen näkökulma',
			description: 'Ryhmän ja yhteisöjen vaikutus yksilöön',
			src: '/img/'
		},
		{
			id: 7,
			header: 'Psykologinen tutkimus',
			description: 'Miten tehdään psykologista tutkimusta?',
			src: '/img/'
		}
	]
})

export const getters = {
	chapterById: state => id => {
		return state.list.find(x => x.id === id)
	}
}
