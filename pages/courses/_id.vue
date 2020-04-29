<template>
	<div>
		<h3>Luku</h3>
		<card-deck :items="items" />
	</div>
</template>

<script>
import CardDeck from '~/components/CardDeck.vue'
export default {
	components: {
		CardDeck
	},
	computed: {
		items() {
			return this.$store.state.modules.list
		}
	}
}
</script>
