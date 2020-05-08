export const state = () => ({
	list: [
		{
			id: 1,
			header: 'Aloitus',
			description: 'Tietoa opiskelusta sekä johdanto psykologiaan.'
		},
		{
			id: 2,
			header: 'Biologinen näkökulma',
			description: 'Aivot ja hermosto psyykkisen toiminnan perustana'
		},
		{
			id: 3,
			header: 'Käyttäytymisen näkökullma',
			description:
				'Ärsykkeillä voidaan ehdollistaa eläimiä ja ihmisiä oppimaan'
		},
		{
			id: 4,
			header: 'Kognitiivinen näkökulma',
			description: 'Ihminen aktiivisena tiedonrakentajana'
		},
		{
			id: 5,
			header: 'Tunteiden ja motivaation näkökulma',
			description:
				'Innostus syntyy itsetunnon, vapauden ja muiden ihmisten avulla'
		},
		{
			id: 6,
			header: 'Sosiokulttuurinen näkökulma',
			description: 'Ryhmän ja yhteisöjen vaikutus yksilöön'
		},
		{
			id: 7,
			header: 'Psykologinen tutkimus',
			description: 'Miten tehdään psykologista tutkimusta?'
		}
	]
})

export const getters = {
	chapterById: state => id => {
		return state.list.find(x => x.id === id)
	}
}
