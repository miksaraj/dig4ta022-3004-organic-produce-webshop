<template>
	<stats :items="items" />
</template>

<script>
import Stats from '~/components/Stats.vue'
export default {
	components: {
		Stats
	},
	computed: {
		items() {
			return this.$store.state.statistics.list
		}
	}
}
</script>
