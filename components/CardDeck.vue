<template>
	<b-card-group deck>
		<div v-for="item in items" :key="item.id">
			<card :item="item" :type="type" />
		</div>
	</b-card-group>
</template>

<script>
import Card from '~/components/Card.vue'
export default {
	name: 'cardDeck',
	components: {
		Card
	},
	computed: {
		items() {
			return this.$attrs.items
		},
		type() {
			return this.$attrs.type
		}
	}
}
</script>
