<template>
	<b-row>
		<b-button pill class="btn-primary" @click="toggleView">
			<b-icon v-if="view === 'cards'" icon="grid3x3-gap" />
			<b-icon v-if="view === 'list'" icon="list" />
		</b-button>
	</b-row>
</template>

<style scoped>
.row {
	margin-bottom: 2rem;
}
</style>

<script>
export default {
	name: 'OptionsRow',
	computed: {
		type() {
			return this.$attrs.type
		},
		view() {
			return this.$store.state.settings[this.type + 'View']
		}
	},
	methods: {
		toggleView() {
			this.$store.dispatch('settings/toggleView', { type: this.type })
		}
	}
}
</script>
