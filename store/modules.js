export const state = () => ({
	list: [
		{
			id: 1,
			courseId: 1,
			header: 'Mikä JavaScript?',
			description:
				'Tässä moduulissa opit mikä on JS ja mihin sitä käytetään.',
			tasks: 4
		},
		{
			id: 2,
			courseId: 1,
			header: 'Mitä tapahtuu konepellin alla?',
			description:
				'Tässä moduulissa paneudutaan tarkemmin JavaScriptin olemukseen ja toimintaan.',
			tasks: 5
		},
		{
			id: 3,
			courseId: 1,
			header: 'DOM-manipulaatio',
			description: '',
			tasks: 3
		},
		{
			id: 4,
			courseId: 1,
			header: 'Objektit ja funktiot',
			description:
				'Tässä moduulissa menemme syvemmälle JavaScriptin maailmaa opettelemalla hyödyntämään objekteja ja tutustumme funktioihin.',
			tasks: 6
		},
		{
			id: 5,
			courseId: 1,
			header: 'ES6 / ES2015',
			description: '',
			tasks: 3
		},
		{
			id: 6,
			courseId: 1,
			header: 'Async/Await ja AJAX',
			description:
				'Asynkroniset funktiot Javascriptissä. Mitä ne ovat ja miten niitä käytetään?',
			tasks: 6
		},
		{
			id: 7,
			courseId: 2,
			header: 'Intro',
			description: 'Mikä on Vue.js, ja miksi käyttäisit sitä?',
			tasks: 3
		},
		{
			id: 8,
			courseId: 2,
			header: 'Reaktiivinen Vue',
			description:
				'Tässä moduulissa opimme, miten Vue on vuorovaikuksessa DOMin kanssa ja kuinka sen ominaisuuksista otetaan paras hyöty irti.',
			tasks: 8
		},
		{
			id: 9,
			courseId: 2,
			header: 'Konditionaalit ja listojen palauttaminen Vuessa',
			description: '',
			tasks: 5
		},
		{
			id: 10,
			courseId: 3,
			header: 'Reactin perusteet',
			description: '',
			tasks: 4
		},
		{
			id: 11,
			courseId: 3,
			header: 'Miksi React?',
			description: 'Mikä tekee Reactista niin suositun sovelluskehyksen?',
			tasks: 3
		},
		{
			id: 12,
			courseId: 3,
			header: 'Komponentit ja JSX',
			description: '',
			tasks: 5
		},
		{
			id: 13,
			courseId: 4,
			header: 'Java 1',
			description: 'Intro, syntaksi, kommentit ja datatyypit',
			tasks: 4
		},
		{
			id: 14,
			courseId: 4,
			header: 'Java 2',
			description: 'Ehtolauseet ja luupit',
			tasks: 6
		},
		{
			id: 15,
			courseId: 4,
			header: 'Java 3',
			description: 'Java-metodit',
			tasks: 5
		},
		{
			id: 16,
			courseId: 4,
			header: 'Java 4',
			description: 'Luokat 1',
			tasks: 5
		},
		{
			id: 17,
			courseId: 4,
			header: 'Java 5',
			description: 'Luokat 2',
			tasks: 5
		}
	]
})

export const getters = {
	modulesByCourse: state => id => {
		return state.list.filter(item => item.courseId === id)
	}
}
