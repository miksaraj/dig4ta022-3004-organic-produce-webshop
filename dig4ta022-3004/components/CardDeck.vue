<template>
	<b-card-group deck>
		<div v-for="item in items" :key="item.id">
			<card :item="item" />
		</div>
	</b-card-group>
</template>

<script>
import Card from '~/components/Card.vue'
export default {
	name: 'card-deck',
	components: {
		Card
	},
	data() {
		return {
			items: [
				{
					id: 1,
					header: 'Header',
					description: 'This is a description'
				},
				{
					id: 2,
					header: 'Header',
					description: 'This is a description'
				},
				{
					id: 3,
					header: 'Header',
					description: 'This is a description'
				},
				{
					id: 4,
					header: 'Header',
					description: 'This is a description'
				}
			]
		}
	}
}
</script>
