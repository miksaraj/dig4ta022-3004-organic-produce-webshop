<template>
	<card-deck :items="items" />
</template>

<script>
import CardDeck from '~/components/CardDeck.vue'
export default {
	components: {
		CardDeck
	},
	computed: {
		items() {
			return this.$store.state.courses.list
		}
	}
}
</script>
