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
	computed: {
		items() {
			return this.$store.state.courses.list
		}
	}
}
</script>
