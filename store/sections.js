export const state = () => ({
	list: [
		{
			id: 1,
			chapterId: 1,
			header: 'Mikä JavaScript?',
			description:
				'Tässä moduulissa opit mikä on JS ja mihin sitä käytetään.',
			assignments: 4
		},
		{
			id: 2,
			chapterId: 1,
			header: 'Mitä tapahtuu konepellin alla?',
			description:
				'Tässä moduulissa paneudutaan tarkemmin JavaScriptin olemukseen ja toimintaan.',
			assignments: 5
		},
		{
			id: 3,
			chapterId: 1,
			header: 'DOM-manipulaatio',
			description: '',
			assignments: 3
		},
		{
			id: 4,
			chapterId: 1,
			header: 'Objektit ja funktiot',
			description:
				'Tässä moduulissa menemme syvemmälle JavaScriptin maailmaa opettelemalla hyödyntämään objekteja ja tutustumme funktioihin.',
			assignments: 6
		},
		{
			id: 5,
			chapterId: 1,
			header: 'ES6 / ES2015',
			description: '',
			assignments: 3
		},
		{
			id: 6,
			chapterId: 1,
			header: 'Async/Await ja AJAX',
			description:
				'Asynkroniset funktiot Javascriptissä. Mitä ne ovat ja miten niitä käytetään?',
			assignments: 6
		},
		{
			id: 7,
			chapterId: 2,
			header: 'Intro',
			description: 'Mikä on Vue.js, ja miksi käyttäisit sitä?',
			assignments: 3
		},
		{
			id: 8,
			chapterId: 2,
			header: 'Reaktiivinen Vue',
			description:
				'Tässä moduulissa opimme, miten Vue on vuorovaikuksessa DOMin kanssa ja kuinka sen ominaisuuksista otetaan paras hyöty irti.',
			assignments: 8
		},
		{
			id: 9,
			chapterId: 2,
			header: 'Konditionaalit ja listojen palauttaminen Vuessa',
			description: '',
			assignments: 5
		},
		{
			id: 10,
			chapterId: 3,
			header: 'Reactin perusteet',
			description: '',
			assignments: 4
		},
		{
			id: 11,
			chapterId: 3,
			header: 'Miksi React?',
			description: 'Mikä tekee Reactista niin suositun sovelluskehyksen?',
			assignments: 3
		},
		{
			id: 12,
			chapterId: 3,
			header: 'Komponentit ja JSX',
			description: '',
			assignments: 5
		},
		{
			id: 13,
			chapterId: 4,
			header: 'Java 1',
			description: 'Intro, syntaksi, kommentit ja datatyypit',
			assignments: 4
		},
		{
			id: 14,
			chapterId: 4,
			header: 'Java 2',
			description: 'Ehtolauseet ja luupit',
			assignments: 6
		},
		{
			id: 15,
			chapterId: 4,
			header: 'Java 3',
			description: 'Java-metodit',
			assignments: 5
		},
		{
			id: 16,
			chapterId: 4,
			header: 'Java 4',
			description: 'Luokat 1',
			assignments: 5
		},
		{
			id: 17,
			chapterId: 4,
			header: 'Java 5',
			description: 'Luokat 2',
			assignments: 5
		}
	]
})

export const getters = {
	sectionsByChapter: state => id => {
		return state.list.filter(item => item.chapterId === id)
	},
	sectionById: state => id => {
		return state.list.find(item => item.id === id)
	}
}
