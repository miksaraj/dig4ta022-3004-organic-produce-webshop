// list of chapters with details required for dynamic rendering
export const state = () => ({
	// TÄÄLTÄ PUUTTUU KUVAT!
	list: [
		{
			id: 1,
			header: 'Aloitus',
			description: 'Tietoa opiskelusta sekä johdanto psykologiaan.',
			src: '/img/chapterImg/aloitus.png'
		},
		{
			id: 2,
			header: 'Biologinen näkökulma',
			description: 'Aivot ja hermosto psyykkisen toiminnan perustana',
			src: '/img/chapterImg/biologinen.png'
		},
		{
			id: 3,
			header: 'Käyttäytymisen näkökulma',
			description:
				'Ärsykkeillä voidaan ehdollistaa eläimiä ja ihmisiä oppimaan',
			src: '/img/chapterImg/kayttaytyminen.png'
		},
		{
			id: 4,
			header: 'Kognitiivinen näkökulma',
			description: 'Ihminen aktiivisena tiedonrakentajana',
			src: '/img/chapterImg/kognitiivinen.png'
		},
		{
			id: 5,
			header: 'Tunteiden ja motivaation näkökulma',
			description:
				'Innostus syntyy itsetunnon, vapauden ja muiden ihmisten avulla',
			src: '/img/chapterImg/tunteetjamotivaatio.png'
		},
		{
			id: 6,
			header: 'Sosiokulttuurinen näkökulma',
			description: 'Ryhmän ja yhteisöjen vaikutus yksilöön',
			src: '/img/chapterImg/sosiokulttuurinen.png'
		},
		{
			id: 7,
			header: 'Psykologinen tutkimus',
			description: 'Miten tehdään psykologista tutkimusta?',
			// FIXME
			src: '/img/chapterImg/research.html'
		}
	]
})

export const getters = {
	chapterById: state => id => {
		return state.list.find(x => x.id === id)
	}
}
