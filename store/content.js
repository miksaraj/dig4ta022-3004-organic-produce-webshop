export const state = () => ({
	list: [
		{
			id: 1,
			header: 'Otsikko',
			text: [
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo.'
				},
				{
					type: 'ul',
					content: [
						'Lorem ipsum dolor sit amet, consectetuer adipiscing elit.',
						'Aliquam tincidunt mauris eu risus.',
						'Vestibulum auctor dapibus neque.'
					]
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas.'
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo. Quisque sit amet est et sapien ullamcorper pharetra. Vestibulum erat wisi, condimentum sed, commodo vitae, ornare sit amet, wisi. Aenean fermentum, elit eget tincidunt condimentum, eros ipsum rutrum orci, sagittis tempus lacus enim ac dui. Donec non enim in turpis pulvinar facilisis. Ut felis. Praesent dapibus, neque id cursus faucibus, tortor neque egestas augue, eu vulputate magna eros eu erat. Aliquam erat volutpat. Nam dui mi, tincidunt quis, accumsan porttitor, facilisis luctus, metus'
				}
			]
		},
		{
			id: 2,
			header: 'Tehtävä:',
			description: 'Lorem ipsum liirum laarum?',
			placeholder: 'Kirjoita tähän...'
		},
		{
			id: 3,
			header: 'Otsikko',
			text: [
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo.'
				},
				{
					type: 'ul',
					content: [
						'Lorem ipsum dolor sit amet, consectetuer adipiscing elit.',
						'Aliquam tincidunt mauris eu risus.',
						'Vestibulum auctor dapibus neque.'
					]
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas.'
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo. Quisque sit amet est et sapien ullamcorper pharetra. Vestibulum erat wisi, condimentum sed, commodo vitae, ornare sit amet, wisi. Aenean fermentum, elit eget tincidunt condimentum, eros ipsum rutrum orci, sagittis tempus lacus enim ac dui. Donec non enim in turpis pulvinar facilisis. Ut felis. Praesent dapibus, neque id cursus faucibus, tortor neque egestas augue, eu vulputate magna eros eu erat. Aliquam erat volutpat. Nam dui mi, tincidunt quis, accumsan porttitor, facilisis luctus, metus'
				}
			]
		},
		{
			id: 4,
			header: 'Otsikko',
			text:
				'Lorem ipsum orem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum. Why do we use it? It is a long established fact that a reader will be distracted by the the readable content of a page when looking at its layout. The point of'
		},
		{
			id: 5,
			header: 'Otsikko',
			text: [
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo.'
				},
				{
					type: 'ul',
					content: [
						'Lorem ipsum dolor sit amet, consectetuer adipiscing elit.',
						'Aliquam tincidunt mauris eu risus.',
						'Vestibulum auctor dapibus neque.'
					]
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas.'
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo. Quisque sit amet est et sapien ullamcorper pharetra. Vestibulum erat wisi, condimentum sed, commodo vitae, ornare sit amet, wisi. Aenean fermentum, elit eget tincidunt condimentum, eros ipsum rutrum orci, sagittis tempus lacus enim ac dui. Donec non enim in turpis pulvinar facilisis. Ut felis. Praesent dapibus, neque id cursus faucibus, tortor neque egestas augue, eu vulputate magna eros eu erat. Aliquam erat volutpat. Nam dui mi, tincidunt quis, accumsan porttitor, facilisis luctus, metus'
				}
			]
		},
		{
			id: 6,
			header: 'Tehtäväkokonaisuus',
			btnText: 'Lähetä',
			parts: [
				{
					label: 'Stacked CB',
					order: 1,
					type: 'CBGroup',
					stacked: true,
					items: [
						{
							text: 'Omena',
							value: 'apple'
						},
						{
							text: 'Appelsiini',
							value: 'orange'
						},
						{
							text: 'Mango',
							value: 'mango'
						},
						{
							text: 'Banaani',
							value: 'banana'
						}
					]
					// correctAnswer: lisätään vasta kun tiedetään miten handlataan
					// tosin voit lisätä kommentoituna
				},
				{
					label: 'Inline Radio',
					order: 2,
					type: 'RadioGroup',
					stacked: false,
					items: [
						{
							text: 'Omena',
							value: 'apple'
						},
						{
							text: 'Appelsiini',
							value: 'orange'
						},
						{
							text: 'Mango',
							value: 'mango'
						},
						{
							text: 'Banaani',
							value: 'banana'
						}
					]
				},
				{
					label: 'Select Element',
					order: 3,
					type: 'SelectElement',
					items: [
						{
							text: 'Omena',
							value: 'apple'
						},
						{
							text: 'Appelsiini',
							value: 'orange'
						},
						{
							text: 'Mango',
							value: 'mango'
						},
						{
							text: 'Banaani',
							value: 'banana'
						}
					]
				},
				{
					label: 'Inline CB',
					order: 4,
					type: 'CBGroup',
					stacked: false,
					items: [
						{
							text: 'Omena',
							value: 'apple'
						},
						{
							text: 'Appelsiini',
							value: 'orange'
						},
						{
							text: 'Mango',
							value: 'mango'
						},
						{
							text: 'Banaani',
							value: 'banana'
						}
					]
				},
				{
					label: 'Stacked Radio',
					order: 5,
					type: 'RadioGroup',
					stacked: true,
					items: [
						{
							text: 'Omena',
							value: 'apple'
						},
						{
							text: 'Appelsiini',
							value: 'orange'
						},
						{
							text: 'Mango',
							value: 'mango'
						},
						{
							text: 'Banaani',
							value: 'banana'
						}
					]
				}
				// Jos on tarvetta muunlaisille komponenttityypeille
				// lisää tänne kommenoituina
			]
		},
		{
			id: 7,
			header: 'Otsikko',
			text: [
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo.'
				},
				{
					type: 'ul',
					content: [
						'Lorem ipsum dolor sit amet, consectetuer adipiscing elit.',
						'Aliquam tincidunt mauris eu risus.',
						'Vestibulum auctor dapibus neque.'
					]
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas.'
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo. Quisque sit amet est et sapien ullamcorper pharetra. Vestibulum erat wisi, condimentum sed, commodo vitae, ornare sit amet, wisi. Aenean fermentum, elit eget tincidunt condimentum, eros ipsum rutrum orci, sagittis tempus lacus enim ac dui. Donec non enim in turpis pulvinar facilisis. Ut felis. Praesent dapibus, neque id cursus faucibus, tortor neque egestas augue, eu vulputate magna eros eu erat. Aliquam erat volutpat. Nam dui mi, tincidunt quis, accumsan porttitor, facilisis luctus, metus'
				}
			]
		},
		{
			id: 8,
			header: 'Otsikko',
			description: 'Kootut selitykset'
			// tähän voi lisätä accept: '.jpg, .png., .gif' tai jotain
		},
		{
			id: 9,
			header: 'Otsikko',
			text: [
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo.'
				},
				{
					type: 'ul',
					content: [
						'Lorem ipsum dolor sit amet, consectetuer adipiscing elit.',
						'Aliquam tincidunt mauris eu risus.',
						'Vestibulum auctor dapibus neque.'
					]
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas.'
				},
				{
					type: 'p',
					content:
						'Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum tortor quam, feugiat vitae, ultricies eget, tempor sit amet, ante. Donec eu libero sit amet quam egestas semper. Aenean ultricies mi vitae est. Mauris placerat eleifend leo. Quisque sit amet est et sapien ullamcorper pharetra. Vestibulum erat wisi, condimentum sed, commodo vitae, ornare sit amet, wisi. Aenean fermentum, elit eget tincidunt condimentum, eros ipsum rutrum orci, sagittis tempus lacus enim ac dui. Donec non enim in turpis pulvinar facilisis. Ut felis. Praesent dapibus, neque id cursus faucibus, tortor neque egestas augue, eu vulputate magna eros eu erat. Aliquam erat volutpat. Nam dui mi, tincidunt quis, accumsan porttitor, facilisis luctus, metus'
				}
			]
		}
	]
})

export const getters = {
	contentById: state => id => {
		return state.list.find(item => item.id === id)
	}
}
