<template>
	<b-card-group deck>
		<div v-for="item in items" :key="item.id">
			<card :item="item" />
		</div>
	</b-card-group>
	<!--chapter just nope. Nope nope nope. /-->
</template>

<script>
import Card from '~/components/Card.vue'
// import Chapter from '~/components/Chapter.vue'
export default {
	name: 'card-deck',
	components: {
		Card
	},
	computed: {
		items() {
			return this.$attrs.items
		}
	}
}
</script>
